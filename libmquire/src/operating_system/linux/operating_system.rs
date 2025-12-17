//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        architecture::{Architecture, Endianness},
        entities::{
            file::File, system_information::SystemInformation, system_version::SystemVersion,
            task::Task,
        },
        error::{Error, ErrorKind, Result},
        operating_system::OperatingSystem,
        virtual_memory_reader::VirtualMemoryReader,
    },
    generate_address_ranges,
    memory::{
        error::{Error as MemoryError, ErrorKind as MemoryErrorKind, Result as MemoryResult},
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    operating_system::linux::{
        btf::BtfparseReadableAdapter,
        entities::{
            cgroup::Cgroup,
            dmesg::{DmesgDataSource, DmesgEntry},
            memory_mapping::{MemoryMapping, MemoryProtection},
            syslog_file::{SyslogFile, SyslogFileDataSource, SyslogFileRegion},
        },
        kallsyms::Kallsyms,
        maple_tree::{MapleTree, MapleTreeValue},
        virtual_struct::VirtualStruct,
        xarray::XArray,
    },
    try_chain,
    utils::reader::Reader,
};

use {
    btfparse::{
        Error as BtfparseError, Integer32Value, Offset as BtfparseOffset, TypeInformation,
        TypeVariant,
    },
    log::debug,
    rayon::prelude::*,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Range, Sub},
    path::PathBuf,
    sync::Arc,
};

/// Standard page size
const PAGE_SIZE: u64 = 4096;

/// Buffer size used for initial data discovery
const SCAN_BUFFER_SIZE: usize = 4 * 1024 * 1024;

// VM flag constants
const VM_READ: u64 = 0x00000001;
const VM_WRITE: u64 = 0x00000002;
const VM_EXEC: u64 = 0x00000004;
const VM_SHARED: u64 = 0x00000008;

/// Syslog path
const SYSLOG_PATH: &str = "/var/log/syslog";

/// Swapper process comm string
const SWAPPER_PROCESS_COMM: &str = "swapper/0";

/// BTF signature for little endian machines
const BTF_LITTLE_ENDIAN_SIGNATURE: [u8; 3] = [
    0x9F, 0xEB, // Magic number
    0x01, // Version
];

//
// Constants for the printk ringbuffer
//

// Mask for extracting descriptor state
const PRB_DESC_FLAGS_SHIFT: u64 = 64 - 2;
const PRB_DESC_STATE_MASK: u64 = 0x3;
const PRB_DESC_ID_MASK: u64 = !(PRB_DESC_STATE_MASK << PRB_DESC_FLAGS_SHIFT);

// State values
const PRB_DESC_FINALIZED: u64 = 0x2;
const PRB_DESC_COMMITTED: u64 = 0x1;

// Special lpos values indicating no data
const PRB_FAILED_LPOS: u64 = 0x1;
const PRB_EMPTY_LINE_LPOS: u64 = 0x3;

/// File backing information
#[derive(Debug, Clone, Copy)]
pub struct VmAreaStructBackingFile {
    /// File virtual address
    pub file: VirtualAddress,

    /// Page offset within the file (in PAGE_SIZE units)
    pub offset: u64,
}

/// A representation of a vm_area_struct object
#[derive(Debug, Clone)]
pub struct VmAreaStruct {
    /// Virtual address of the vm_area_struct
    pub virtual_address: VirtualAddress,

    /// Memory region
    pub region: Range<u64>,

    /// VMA flags
    pub flags: u64,

    /// Backing file information
    pub backing_file: Option<VmAreaStructBackingFile>,
}

impl MapleTreeValue for VmAreaStruct {
    fn from_vaddr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<Self> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let vm_area_struct = VirtualStruct::from_name(
            &vmem_reader,
            type_information,
            "vm_area_struct",
            &virtual_address,
        )?;

        let start = vm_area_struct.traverse("vm_start")?.read_u64()?;
        let end = vm_area_struct.traverse("vm_end")?.read_u64()?;
        let flags = vm_area_struct.traverse("vm_flags")?.read_u64()?;
        let offset = vm_area_struct.traverse("vm_pgoff")?.read_u64()?;

        let file = vm_area_struct.traverse("vm_file")?.read_vaddr()?;
        let backing_file = if file.is_null() {
            None
        } else {
            Some(VmAreaStructBackingFile { file, offset })
        };

        Ok(VmAreaStruct {
            virtual_address,
            region: Range { start, end },
            flags,
            backing_file,
        })
    }
}

/// Implements the OperatingSystem trait for Linux
pub struct LinuxOperatingSystem {
    /// The memory dump
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel debug symbols
    kernel_type_info: TypeInformation,

    /// The virtual address of the init task
    init_task_vaddr: VirtualAddress,

    /// The kernel symbol table
    kallsyms: Option<Kallsyms>,
}

impl LinuxOperatingSystem {
    /// Creates a new `LinuxOperatingSystem` instance
    pub fn new(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
    ) -> Result<Arc<Self>> {
        let kernel_type_info = Self::get_kernel_type_info(memory_dump.as_ref())
            .inspect_err(|err| debug!("{err:?}"))?;

        let init_task_vaddr = Self::get_init_task_vaddr(
            memory_dump.as_ref(),
            architecture.as_ref(),
            &kernel_type_info,
        )?;

        let system_version = Self::get_system_version(
            memory_dump.as_ref(),
            architecture.as_ref(),
            &kernel_type_info,
            &init_task_vaddr,
        )?;

        let kallsyms = Kallsyms::new(
            memory_dump.as_ref(),
            architecture.as_ref(),
            init_task_vaddr.root_page_table(),
            &system_version.kernel_version,
        )
        .inspect_err(|err| debug!("{err:?}"))
        .ok();

        Ok(Arc::new(Self {
            memory_dump,
            architecture,
            kernel_type_info,
            init_task_vaddr,
            kallsyms,
        }))
    }

    /// Returns the cgroup list
    pub fn get_cgroup_list(&self) -> Result<Vec<Cgroup>> {
        // Acquire the necessary types; if anything fails, we can't proceed
        let cpuset_cgrp_id = self
            .kernel_type_info
            .id_of("cgroup_subsys_id")
            .and_then(|type_id| self.kernel_type_info.from_id(type_id))
            .and_then(|type_variant| {
                if let TypeVariant::Enum(enum_type) = type_variant {
                    enum_type.named_value_list().iter().find_map(|named_value| {
                        if named_value.name == "cpuset_cgrp_id" {
                            Some(named_value.value)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
            .map(|integer_value| match integer_value {
                Integer32Value::Signed(value) => value as u32,
                Integer32Value::Unsigned(value) => value,
            })
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "Failed to acquire the cgroup_subsys_id::cpuset_cgrp_id enum value",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let css_type = self
            .kernel_type_info
            .id_of("css_set")
            .and_then(|type_id| self.kernel_type_info.from_id(type_id))
            .and_then(|type_variant| {
                if let TypeVariant::Struct(struct_type) = type_variant {
                    Some(struct_type)
                } else {
                    None
                }
            })
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "No `struct css_set` found",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let subsys_field = css_type
            .member_list()
            .iter()
            .find(|member| member.name().map(|name| name == "subsys").unwrap_or(false))
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "No field `subsys` found inside the `struct css_set` structure",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let subsys_array_type = self
            .kernel_type_info
            .from_id(subsys_field.tid())
            .and_then(|type_variant| {
                if let TypeVariant::Array(array_type) = type_variant {
                    Some(array_type)
                } else {
                    None
                }
            })
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "The `subsys` field inside the `struct css_set` structure is not an array",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        if cpuset_cgrp_id >= *subsys_array_type.element_count() {
            let err = Error::new(
                ErrorKind::TypeInformationError,
                "The `cpuset_cgrp_id` index is outside of the subsys array size",
            );

            debug!("{err:?}");
            return Err(err);
        }

        // From now on, if any error happens we can just skip the current entry
        let mut cgroup_list = Vec::new();
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        for task_vaddr in Self::enumerate_related_task_struct_vaddrs(
            &self.kernel_type_info,
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            self.init_task_vaddr,
        )? {
            let task_struct = match VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
                "task_struct",
                &task_vaddr,
            ) {
                Ok(task_struct) => task_struct,
                Err(err) => {
                    debug!("{err:?}");
                    continue;
                }
            };

            let mut kn = match try_chain!(task_struct
                .traverse("cgroups")?
                .dereference()?
                .traverse(&format!("subsys[{cpuset_cgrp_id}]"))?
                .dereference()?
                .traverse("cgroup")?
                .dereference()?
                .traverse("kn")?
                .dereference())
            {
                Ok(kn) => kn,
                Err(err) => {
                    debug!("{err:?}");
                    continue;
                }
            };

            let mut visited_address_list = BTreeSet::new();
            let mut name_list = Vec::new();

            while !kn.virtual_address().is_null() {
                if !visited_address_list.insert(kn.virtual_address().value()) {
                    break;
                }

                let parent_kn = match try_chain!(kn.traverse("parent")?.dereference()) {
                    Ok(parent_kn) => parent_kn,
                    Err(err) => {
                        debug!("{err:?}");
                        continue;
                    }
                };

                match kn
                    .traverse("name")
                    .and_then(|obj| obj.dereference())
                    .and_then(|obj| obj.read_string_lossy(None))
                    .and_then(|buffer| {
                        if buffer.is_empty() {
                            Err(Error::new(
                                ErrorKind::InvalidData,
                                "Found an empty kn node name",
                            ))
                        } else {
                            Ok(buffer)
                        }
                    }) {
                    Ok(name) => {
                        name_list.push(name);
                    }

                    Err(err) => {
                        debug!("{err:?}");
                        break;
                    }
                };

                kn = parent_kn;
            }

            if !name_list.is_empty() {
                cgroup_list.push(Cgroup {
                    task: task_vaddr,
                    name: name_list.into_iter().rev().collect::<Vec<_>>().join("/"),
                });
            }
        }

        Ok(cgroup_list)
    }

    /// Returns the list of memory mappings in the given task
    pub fn get_task_memory_mappings(&self) -> Result<Vec<MemoryMapping>> {
        let mut memory_mapping_list = Vec::new();

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        for task in self.get_task_list()? {
            let task_struct = VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
                "task_struct",
                &task.virtual_address,
            )
            .inspect_err(|err| debug!("{err:?}"))?;

            match try_chain!(task_struct.traverse("mm")?.read_vaddr()) {
                Ok(mm_virtual_address) => {
                    if mm_virtual_address.is_null() {
                        continue;
                    }
                }

                Err(err) => {
                    debug!("{err:?}");
                    continue;
                }
            };

            let mm_mt =
                match try_chain!(task_struct.traverse("mm")?.dereference()?.traverse("mm_mt")) {
                    Ok(obj) => obj,
                    Err(err) => {
                        debug!("{err:?}");
                        continue;
                    }
                };

            let maple_tree = MapleTree::<VmAreaStruct>::new(
                self.memory_dump.as_ref(),
                self.architecture.as_ref(),
                &self.kernel_type_info,
                mm_mt.virtual_address(),
            )?;

            for entry in maple_tree.entries() {
                let vma_info = &entry.value;
                let shared = vma_info.flags & VM_SHARED != 0;

                let protection = MemoryProtection::new(
                    vma_info.flags & VM_READ != 0,
                    vma_info.flags & VM_WRITE != 0,
                    vma_info.flags & VM_EXEC != 0,
                );

                let file_path = if let Some(backing_file) = vma_info.backing_file {
                    VirtualStruct::from_name(
                        &vmem_reader,
                        &self.kernel_type_info,
                        "file",
                        &backing_file.file,
                    )
                    .inspect_err(|err| debug!("{err:?}"))
                    .ok()
                    .and_then(|file| {
                        let f_path_vaddr = match file.traverse("f_path") {
                            Ok(f_path) => f_path.virtual_address(),
                            Err(err) => {
                                debug!("{err:?}");
                                return None;
                            }
                        };

                        Self::read_path(
                            self.memory_dump.as_ref(),
                            self.architecture.as_ref(),
                            &self.kernel_type_info,
                            f_path_vaddr,
                        )
                        .map(PathBuf::from)
                        .inspect_err(|err| debug!("{err:?}"))
                        .ok()
                    })
                } else {
                    None
                };

                let vm_start = VirtualAddress::new(
                    task.page_table,
                    RawVirtualAddress::new(vma_info.region.start),
                );

                let vm_end = VirtualAddress::new(
                    task.page_table,
                    RawVirtualAddress::new(vma_info.region.end),
                );

                memory_mapping_list.push(MemoryMapping {
                    task: task.virtual_address,
                    region: vm_start..vm_end,
                    protection,
                    shared,
                    file_path,
                });
            }
        }

        Ok(memory_mapping_list)
    }

    /// Returns the syslog file data from memory
    pub fn get_syslog_file_regions(&self) -> Result<Vec<SyslogFile>> {
        // This function attempts to read /var/log/syslog from memory using two approaches:
        // 1. Page cache from open file handles
        // 2. Memory mappings of the file
        let mut syslog_entity_list: Vec<SyslogFile> = Vec::new();

        // First, read from open files via page cache. It is possible for multiple file
        // entities to exist with the same path, for example if the `/var/log/syslog` file
        // is deleted and recreated while still being held open by a process.
        let file_list: Vec<File> = self
            .get_task_open_file_list()?
            .into_iter()
            .filter(|file_entity| file_entity.path == SYSLOG_PATH)
            .map(|file_entity| (file_entity.virtual_address.value(), file_entity))
            .collect::<BTreeMap<_, _>>() // Use the file object vaddr to deduplicate
            .into_values()
            .collect();

        let page_cache_syslog: Vec<SyslogFile> = file_list
            .iter()
            .filter_map(|file| {
                let reader = match self.get_file_reader(file.virtual_address) {
                    Ok(reader) => reader,

                    Err(err) => {
                        debug!(
                            "Failed to create file reader for {SYSLOG_PATH} at {:?}: {err:?}",
                            file.virtual_address
                        );

                        return None;
                    }
                };

                let file_region_list = match reader.regions() {
                    Ok(region_list) => region_list,

                    Err(err) => {
                        debug!(
                            "Failed to enumerate regions for {SYSLOG_PATH} at {:?}: {err:?}",
                            file.virtual_address
                        );
                        return None;
                    }
                };

                let syslog_region_list: Vec<SyslogFileRegion> = file_region_list
                    .iter()
                    .filter_map(|region| {
                        let region_size = region.end - region.start;
                        let mut buffer = vec![0; region_size as usize];

                        let buffer =
                            match reader.read(&mut buffer, region.start).map(|bytes_read| {
                                buffer.truncate(bytes_read);
                                buffer
                            }) {
                                Ok(buffer) => buffer,

                                Err(err) => {
                                    debug!(
                                "Failed to read region {:?} for {SYSLOG_PATH} at {:?}: {err:?}",
                                region, file.virtual_address
                            );
                                    return None;
                                }
                            };

                        let lines = extract_valid_lines(&buffer, 10);
                        if lines.is_empty() {
                            debug!(
                                "Skipping syslog region {:?} at {:?}: no valid text lines found",
                                region, file.virtual_address
                            );

                            return None;
                        }

                        Some(SyslogFileRegion {
                            offset_range: region.clone(),
                            lines,
                        })
                    })
                    .collect();

                Some(SyslogFile {
                    virtual_address: file.virtual_address,
                    task: file.task,
                    pid: file.pid,
                    data_source: SyslogFileDataSource::PageCache,
                    region_list: syslog_region_list,
                })
            })
            .collect();

        syslog_entity_list.extend(page_cache_syslog);

        let syslog_mappings: Vec<_> = self
            .get_task_memory_mappings()?
            .into_iter()
            .filter(|mapping| {
                mapping
                    .file_path
                    .as_ref()
                    .map(|path| path.to_str().unwrap_or("") == SYSLOG_PATH)
                    .unwrap_or(false)
            })
            .collect();

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        for mapping in syslog_mappings {
            let region_size = (mapping.region.end.value() - mapping.region.start.value()) as usize;
            let mut buffer = vec![0u8; region_size];

            match vmem_reader.read(&mut buffer, mapping.region.start) {
                Ok(bytes_read) => {
                    buffer.truncate(bytes_read);

                    let lines = extract_valid_lines(&buffer, 10);
                    if lines.is_empty() {
                        debug!(
                            "Skipping syslog memory mapping at {:?}: no valid text lines found",
                            mapping.region.start
                        );
                        continue;
                    }

                    let syslog_region = SyslogFileRegion {
                        offset_range: PhysicalAddress::new(0)
                            ..PhysicalAddress::new(bytes_read as u64),
                        lines,
                    };

                    let task_struct = VirtualStruct::from_name(
                        &vmem_reader,
                        &self.kernel_type_info,
                        "task_struct",
                        &mapping.task,
                    )
                    .inspect_err(|err| debug!("{err:?}"))?;

                    let pid = match try_chain!(task_struct.traverse("tgid")?.read_u32()) {
                        Ok(tgid) => tgid,
                        Err(err) => {
                            debug!(
                                "Failed to read the tgid field from task {:?}{err:?}",
                                mapping.task
                            );
                            0
                        }
                    };

                    syslog_entity_list.push(SyslogFile {
                        virtual_address: mapping.region.start,
                        task: mapping.task,
                        pid,
                        data_source: SyslogFileDataSource::MemoryMapping,
                        region_list: vec![syslog_region],
                    });
                }

                Err(err) => {
                    debug!(
                        "Failed to read memory mapping for {SYSLOG_PATH} at {:?}: {err:?}",
                        mapping.region.start
                    );
                }
            }
        }

        Ok(syslog_entity_list)
    }

    /// Returns kernel log messages (dmesg) from the printk_ringbuffer
    pub fn get_dmesg_entries(&self) -> Result<Vec<DmesgEntry>> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })?;

        let prb_ptr_vaddr = match kallsyms.get("prb") {
            Some(vaddr) => {
                VirtualAddress::new(self.init_task_vaddr.root_page_table(), vaddr.value())
            }

            None => {
                return Err(Error::new(
                    ErrorKind::EntityNotFound,
                    "Failed to find 'prb' symbol in kallsyms - printk ringbuffer not available",
                ));
            }
        };

        debug!("Found 'prb' symbol at {:?}", prb_ptr_vaddr);

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());
        let prb_vaddr = vmem_reader.read_vaddr(prb_ptr_vaddr)?;

        debug!("Dereferenced 'prb' pointer to {:?}", prb_vaddr);

        let prb = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "printk_ringbuffer",
            &prb_vaddr,
        )?;

        let desc_ring = prb.traverse("desc_ring")?;

        let count_bits = desc_ring.traverse("count_bits")?.read_u32()? as u64;
        let descriptor_count = 1u64 << count_bits;

        debug!(
            "Descriptor ring has {} entries (count_bits={})",
            descriptor_count, count_bits
        );

        let descs_ptr = desc_ring.traverse("descs")?.read_vaddr()?;
        let infos_ptr = desc_ring.traverse("infos")?.read_vaddr()?;

        let tail_id = desc_ring.traverse("tail_id")?.read_u64()?;
        let head_id = desc_ring.traverse("head_id")?.read_u64()?;

        debug!("Descriptor ring: tail_id={}, head_id={}", tail_id, head_id);

        let text_data_ring = prb.traverse("text_data_ring")?;
        let text_size_bits = text_data_ring.traverse("size_bits")?.read_u32()? as u64;
        let text_data_ptr = text_data_ring.traverse("data")?.read_vaddr()?;
        let text_data_size = 1u64 << text_size_bits;

        debug!(
            "Text data ring: size={} bytes (size_bits={})",
            text_data_size, text_size_bits
        );

        let mut entries = Vec::new();

        let mut current_id = tail_id;
        let mut iteration_count = 0;

        let prb_desc_tid = self.kernel_type_info.id_of("prb_desc").ok_or_else(|| {
            Error::new(
                ErrorKind::TypeInformationError,
                "Failed to find prb_desc type",
            )
        })?;

        let printk_info_tid = self.kernel_type_info.id_of("printk_info").ok_or_else(|| {
            Error::new(
                ErrorKind::TypeInformationError,
                "Failed to find printk_info type",
            )
        })?;

        let desc_size = self.kernel_type_info.size_of(prb_desc_tid)? as u64;
        let info_size = self.kernel_type_info.size_of(printk_info_tid)? as u64;

        while current_id != head_id && iteration_count < descriptor_count {
            let index = current_id % descriptor_count;
            iteration_count += 1;

            let desc_vaddr = descs_ptr + (index * desc_size);
            let desc = match VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
                "prb_desc",
                &desc_vaddr,
            ) {
                Ok(desc) => desc,
                Err(err) => {
                    debug!("Failed to read descriptor at index {index}: {err:?}");
                    current_id = current_id.wrapping_add(1);
                    continue;
                }
            };

            let state_var = match desc.traverse("state_var").and_then(|f| f.read_u64()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read state_var at index {index}: {err:?}");
                    current_id = current_id.wrapping_add(1);
                    continue;
                }
            };

            let state = (state_var >> PRB_DESC_FLAGS_SHIFT) & PRB_DESC_STATE_MASK;
            let desc_id = state_var & PRB_DESC_ID_MASK;

            let expected_id = current_id;
            current_id = current_id.wrapping_add(1);

            // Each descriptor stores its own ID, so if the buffer wrapped around
            // and overwrote old entries, desc_id won't match expected_id
            if desc_id != expected_id {
                continue;
            }

            // Only process finalized or committed descriptors
            if state != PRB_DESC_FINALIZED && state != PRB_DESC_COMMITTED {
                continue;
            }

            let info_vaddr = infos_ptr + (index * info_size);
            let info = match VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
                "printk_info",
                &info_vaddr,
            ) {
                Ok(info) => info,
                Err(err) => {
                    debug!("Failed to read printk_info at index {index}: {err:?}");
                    continue;
                }
            };

            let sequence = match info.traverse("seq").and_then(|f| f.read_u64()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read seq at index {index}: {err:?}");
                    continue;
                }
            };

            let timestamp_ns = match info.traverse("ts_nsec").and_then(|f| f.read_u64()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read ts_nsec at index {index}: {err:?}");
                    continue;
                }
            };

            let text_len = match info.traverse("text_len").and_then(|f| f.read_u16()) {
                Ok(v) => v as usize,
                Err(err) => {
                    debug!("Failed to read text_len at index {index}: {err:?}");
                    continue;
                }
            };

            let facility = match info.traverse("facility").and_then(|f| f.read_u8()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read facility at index {index}: {err:?}");
                    continue;
                }
            };

            //
            // btfparse can parse bitfields and returns an Offset::BitOffsetAndSize(bit_offset, bit_size),
            // but VirtualStruct::traverse() only accepts Offset::ByteOffset and explicitly rejects anything
            // else. As a workaround, we traverse to the last regular field (facility), get its address,
            // then manually offset by 1 byte to read the bitfield byte.
            //
            // Here's the layout from kernel 6.8.0:
            //
            // struct printk_info {
            //     u64 seq;
            //     u64 ts_nsec;
            //     u16 text_len;
            //     u8 facility;
            //     u8 flags: 5;
            //     u8 level: 3;
            //     u32 caller_id;
            //     struct dev_printk_info dev_info;
            // };
            //

            let facility_field = match info.traverse("facility") {
                Ok(f) => f,
                Err(err) => {
                    debug!("Failed to traverse to facility at index {index}: {err:?}");
                    continue;
                }
            };

            let flags_level_vaddr = facility_field.virtual_address() + 1u64;

            let mut flags_level_byte = [0u8; 1];
            if let Err(err) = vmem_reader.read(&mut flags_level_byte, flags_level_vaddr) {
                debug!("Failed to read flags_level_byte at index {index}: {err:?}");
                continue;
            }

            let level = (flags_level_byte[0] >> 5) & 0x7;

            let caller_id = match info.traverse("caller_id").and_then(|f| f.read_u32()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read caller_id at index {index}: {err:?}");
                    continue;
                }
            };

            let text_blk_lpos = match desc.traverse("text_blk_lpos") {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to traverse to text_blk_lpos at index {index}: {err:?}");
                    continue;
                }
            };

            let text_begin = match text_blk_lpos.traverse("begin").and_then(|f| f.read_u64()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read text_begin at index {index}: {err:?}");
                    continue;
                }
            };

            if text_begin == PRB_FAILED_LPOS || text_begin == PRB_EMPTY_LINE_LPOS {
                continue;
            }

            // Read the text data, skipping the ID prefix
            let text_pos = text_begin % text_data_size;
            let text_vaddr = text_data_ptr + text_pos + 8u64;
            let mut text_buffer = vec![0u8; text_len];

            let message = match vmem_reader.read(&mut text_buffer, text_vaddr) {
                Ok(bytes_read) => {
                    if bytes_read == text_len {
                        let msg = String::from_utf8_lossy(&text_buffer).to_string();

                        if !is_valid_text(&msg, 1) {
                            debug!("Invalid/corrupted message text at index {index}: not enough printable characters");
                            continue;
                        }

                        msg
                    } else {
                        debug!(
                            "Partial read of message text at index {index}: expected {text_len} bytes, got {bytes_read}"
                        );
                        continue;
                    }
                }

                Err(err) => {
                    debug!("Failed to read message text at index {index}: {err:?}");
                    continue;
                }
            };

            entries.push(DmesgEntry {
                data_source: DmesgDataSource::PrintkRingbuffer,
                timestamp_ns,
                level,
                facility,
                sequence,
                message,
                caller_id: if caller_id != 0 {
                    Some(caller_id)
                } else {
                    None
                },
            });
        }

        Ok(entries)
    }

    // Returns the length of an array located in a structure
    fn get_struct_array_member_len(
        kernel_type_info: &TypeInformation,
        struct_name: &str,
        member_name: &str,
    ) -> Result<usize> {
        let tid = kernel_type_info
            .id_of(struct_name)
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "Failed to acquire the type definition of `struct {struct_name}`",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let struct_type_var = kernel_type_info.from_id(tid).ok_or(
            Error::new(
                ErrorKind::TypeInformationError,
                &format!("Failed to acquire the type information for `struct {struct_name}` from tid {tid}"),
            )
        ).inspect_err(|err| debug!("{err:?}"))?;

        let struct_type = match struct_type_var {
            TypeVariant::Struct(struct_type) => struct_type,
            _ => {
                let err = Error::new(
                    ErrorKind::TypeInformationError,
                    &format!("Failed to acquire the type information for `struct {struct_name}` from tid {tid}"),
                );

                debug!("{err:?}");
                return Err(err);
            }
        };

        let member_tid = struct_type
            .member_list()
            .iter()
            .find(|member| {
                member
                    .name()
                    .map(|name| name == member_name)
                    .unwrap_or(false)
            })
            .map(|member| member.tid())
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                &format!("No field `{member_name}` found inside the `{struct_name}` structure",),
            ))?;

        let member_type_var = kernel_type_info.from_id(member_tid).ok_or(Error::new(
            ErrorKind::TypeInformationError,
            &format!(
                "Type ID {member_tid} for member `{struct_name}::{member_name}` was not found",
            ),
        ))?;

        match member_type_var {
            TypeVariant::Array(array_type) => Ok(*array_type.element_count() as usize),

            _ => Err(Error::new(
                ErrorKind::TypeInformationError,
                &format!("Not an array: `{struct_name}::{member_name}`",),
            )),
        }
    }

    /// Enumerates the virtual addresses of task structs related to the given one
    fn enumerate_related_task_struct_vaddrs(
        kernel_type_info: &TypeInformation,
        memory_dump: &dyn Readable,
        architecture: &dyn Architecture,
        task_struct: VirtualAddress,
    ) -> Result<Vec<VirtualAddress>> {
        let mut task_struct_vaddr_set = BTreeSet::new();

        let mut visited_physical_addresses = BTreeSet::new();
        let mut next_vaddr_queue = vec![task_struct];

        let vmem_reader = VirtualMemoryReader::new(memory_dump, architecture);

        while !next_vaddr_queue.is_empty() {
            let virtual_address_queue = next_vaddr_queue.clone();
            next_vaddr_queue.clear();

            for virtual_address in virtual_address_queue {
                let physical_address =
                    match architecture.translate_virtual_address(memory_dump, virtual_address) {
                        Ok(physical_address_range) => physical_address_range.address(),
                        Err(err) => {
                            debug!("{err:?}");
                            continue;
                        }
                    };

                if !visited_physical_addresses.insert(physical_address.value()) {
                    continue;
                }

                task_struct_vaddr_set.insert(virtual_address.value());

                // This can only fail if the type is not present, so it's ok to
                // propagate the error
                let task_struct = VirtualStruct::from_name(
                    &vmem_reader,
                    kernel_type_info,
                    "task_struct",
                    &virtual_address,
                )?;

                for field_path in ["parent", "real_parent"] {
                    match try_chain!(task_struct.traverse(field_path)?.read_vaddr()) {
                        Ok(vaddr) => next_vaddr_queue.push(vaddr),
                        Err(err) => debug!("{err:?}"),
                    }
                }

                // Same as before, if there's a type issue we'll just propagate the error
                let sibling_offset = Self::get_struct_member_byte_offset(
                    kernel_type_info,
                    task_struct.tid(),
                    "sibling",
                )?;

                for field_path in [
                    "children.prev",
                    "children.next",
                    "sibling.prev",
                    "sibling.next",
                ] {
                    match try_chain!(task_struct.traverse(field_path)?.read_vaddr()) {
                        Ok(vaddr) => next_vaddr_queue.push(vaddr - sibling_offset),
                        Err(err) => debug!("{err:?}"),
                    }
                }
            }
        }

        Ok(task_struct_vaddr_set
            .into_iter()
            .map(|raw_vaddr| VirtualAddress::new(task_struct.root_page_table(), raw_vaddr))
            .collect())
    }

    /// Scans the given `Readable` object for the kernel BTF debug symbols
    fn get_kernel_type_info(readable: &dyn Readable) -> Result<TypeInformation> {
        let regions = readable.regions()?;

        regions
            .par_iter()
            .find_map_any(|region| {
                let mut read_buffer = vec![0u8; SCAN_BUFFER_SIZE];

                for range in generate_address_ranges!(
                    region.start,
                    region.end,
                    read_buffer.len(),
                    BTF_LITTLE_ENDIAN_SIGNATURE.len()
                ) {
                    let bytes_read =
                        if let Ok(bytes_read) = readable.read(&mut read_buffer, range.start) {
                            bytes_read
                        } else {
                            debug!("Failed to read buffer during BTF scan at {:?}", range.start);
                            continue;
                        };

                    for offset in read_buffer[..bytes_read]
                        .windows(BTF_LITTLE_ENDIAN_SIGNATURE.len())
                        .enumerate()
                        .filter_map(|(offset, window)| {
                            if window == BTF_LITTLE_ENDIAN_SIGNATURE {
                                Some(offset)
                            } else {
                                None
                            }
                        })
                    {
                        let btf_offset = range.start + (offset as u64);
                        let readable_adapter =
                            BtfparseReadableAdapter::new(readable, btf_offset.value());

                        let type_information =
                            if let Ok(type_information) = TypeInformation::new(&readable_adapter) {
                                type_information
                            } else {
                                debug!("Failed to parse BTF data at offset {}", btf_offset);
                                continue;
                            };

                        if type_information.id_of("task_struct").is_some() {
                            debug!("BTF data found at offset {btf_offset}");
                            return Some(type_information);
                        }
                    }
                }

                None
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "Failed to locate the BTF debug symbols",
                )
            })
    }

    /// Returns a byte member offset
    fn get_struct_member_byte_offset(
        type_information: &TypeInformation,
        tid: u32,
        member_name: &str,
    ) -> Result<u64> {
        if let (_, BtfparseOffset::ByteOffset(byte_offset)) =
            type_information.offset_of(tid, member_name)?
        {
            Ok(byte_offset as u64)
        } else {
            Err(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Unexpected bitfield offset found when retrieving the task_struct::comm offset",
            ))
        }
    }

    /// Returns the location of the swapper task_struct
    fn get_swapper_struct_location(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
    ) -> Result<(PhysicalAddress, RawVirtualAddress)> {
        // Propagate type errors to the caller, since there's nothing we can do about them
        let task_struct_tid = kernel_type_info.id_of("task_struct").ok_or(Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            "Failed to locate the task_struct type",
        ))?;

        let comm_offset =
            Self::get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "comm")?;

        let parent_offset =
            Self::get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "parent")?;

        let real_parent_offset =
            Self::get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "real_parent")?;

        let task_struct_size = kernel_type_info.size_of(task_struct_tid)?;
        let regions = readable.regions()?;

        regions
            .par_iter()
            .find_map_any(|region| {
                let reader = Reader::new(readable, architecture.endianness() == Endianness::Little);
                let mut read_buffer = vec![0u8; SCAN_BUFFER_SIZE];

                for range in generate_address_ranges!(
                    region.start,
                    region.end,
                    read_buffer.len(),
                    task_struct_size
                ) {
                    let read_size = if let Ok(read_size) = readable.read(&mut read_buffer, range.start) {
                        read_size
                    } else {
                        debug!("Failed to read buffer during swapper scan at {:?}", range.start);
                        continue;
                    };

                    if read_size < SWAPPER_PROCESS_COMM.len() {
                        debug!("Read size {} too small for swapper comm", read_size);
                        continue;
                    }

                    for offset in read_buffer[..read_size]
                        .windows(SWAPPER_PROCESS_COMM.len())
                        .enumerate()
                        .filter_map(|(offset, window)| {
                            if window == SWAPPER_PROCESS_COMM.as_bytes() {
                                Some(offset)
                            } else {
                                None
                            }
                        })
                    {
                        let swapper_comm_physical_address = range.start + (offset as u64);
                        let swapper_task_physical_address = swapper_comm_physical_address - comm_offset;

                        let swapper_struct_parent_field =
                            match reader.read_u64(swapper_task_physical_address + parent_offset) {
                                Ok(value) => value,
                                Err(e) => {
                                    debug!("Failed to read parent field: {:?}", e);
                                    continue;
                                }
                            };

                        let swapper_struct_real_parent_field =
                            match reader.read_u64(swapper_task_physical_address + real_parent_offset) {
                                Ok(value) => value,
                                Err(e) => {
                                    debug!("Failed to read real_parent field: {:?}", e);
                                    continue;
                                }
                            };

                        let swapper_struct_raw_vaddr =
                            if swapper_struct_parent_field == swapper_struct_real_parent_field {
                                RawVirtualAddress::new(swapper_struct_parent_field)
                            } else {
                                debug!(
                                    "Parent fields mismatch: {} != {}",
                                    swapper_struct_parent_field, swapper_struct_real_parent_field
                                );
                                continue;
                            };

                        debug!("Swapper struct located: {swapper_task_physical_address} => {swapper_struct_raw_vaddr}");
                        return Some((swapper_task_physical_address, swapper_struct_raw_vaddr));
                    }
                }

                None
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "Failed to locate the swapper task_struct",
                )
            })
    }

    /// Returns the virtual address of the swapper task_struct
    fn get_init_task_vaddr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
    ) -> Result<VirtualAddress> {
        let (swapper_struct_physical_addr, swapper_struct_raw_vaddr) =
            Self::get_swapper_struct_location(readable, architecture, kernel_type_info)?;

        let discovered_page_table = architecture.locate_page_table_for_virtual_address(
            readable,
            swapper_struct_physical_addr,
            swapper_struct_raw_vaddr,
        )?;

        let task_vaddr_list = Self::enumerate_related_task_struct_vaddrs(
            kernel_type_info,
            readable,
            architecture,
            VirtualAddress::new(discovered_page_table, swapper_struct_raw_vaddr),
        )?;

        let init_task =
            task_vaddr_list.into_iter().find_map(
                |virtual_address| match Self::get_task_from_vaddr(
                    readable,
                    architecture,
                    kernel_type_info,
                    virtual_address,
                ) {
                    Ok(task_struct) => {
                        if task_struct.pid == 1 {
                            Some(task_struct)
                        } else {
                            None
                        }
                    }

                    Err(_) => None,
                },
            );

        init_task
            .map(|task_struct| {
                let raw_virtual_address = task_struct.virtual_address.value();
                VirtualAddress::new(task_struct.page_table, raw_virtual_address)
            })
            .ok_or(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate the init task struct",
            ))
    }

    /// Reconstructs the path from a dentry structure
    fn read_path(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<String> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let path_struct =
            VirtualStruct::from_name(&vmem_reader, kernel_type_info, "path", &virtual_address)?;

        let mut dentry = path_struct.traverse("dentry")?.dereference()?;
        let mut path_component_list = Vec::new();

        loop {
            let dname_length = dentry.traverse("d_name.len")?.read_u32()?;
            let name = if dname_length != 0 {
                dentry
                    .traverse("d_name.name")?
                    .dereference()?
                    .read_string_lossy(Some(dname_length as usize))?
            } else {
                dentry.traverse("d_iname")?.read_string_lossy(Some(16))?
            };

            path_component_list.push(name);

            let parent_dentry = dentry.traverse("d_parent")?.dereference()?;
            if parent_dentry.virtual_address() == dentry.virtual_address() {
                // TODO: The `struct vfsmount *mnt` should be used too in order
                //       jump to the next parent
                break;
            }

            dentry = parent_dentry;
        }

        let mut path = PathBuf::new();
        for path_component in path_component_list.iter().rev() {
            path.push(path_component);
        }

        Ok(path.to_string_lossy().to_string())
    }

    /// Returns a snapshot for the task entity at the given VirtualAddress
    fn get_task_from_vaddr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<Task> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let task_struct = VirtualStruct::from_name(
            &vmem_reader,
            kernel_type_info,
            "task_struct",
            &virtual_address,
        )?;

        let comm = task_struct.traverse("comm")?.read_string_lossy(Some(16))?;
        let tgid = task_struct.traverse("tgid")?.read_u32()?;

        let cred = task_struct.traverse("cred")?.dereference()?;
        let uid = cred.traverse("uid")?.read_u32()?;
        let gid = cred.traverse("gid")?.read_u32()?;

        let mut page_table = virtual_address.root_page_table();
        let mut command_line: Option<String> = None;
        let mut environment_variable_map = BTreeMap::new();
        let mut binary_path: Option<String> = None;

        let mm_struct = task_struct.traverse("mm")?.dereference()?;
        if !mm_struct.virtual_address().is_null() {
            let pgd = mm_struct.traverse("pgd")?.read_vaddr()?;
            if let Ok(physical_addr_range) = architecture.translate_virtual_address(readable, pgd) {
                page_table = physical_addr_range.address();

                let arg_start_vaddr = VirtualAddress::new(
                    page_table,
                    RawVirtualAddress::new(mm_struct.traverse("arg_start")?.read_u64()?),
                );

                let arg_end_vaddr = VirtualAddress::new(
                    page_table,
                    RawVirtualAddress::new(mm_struct.traverse("arg_end")?.read_u64()?),
                );

                let arg_size = arg_end_vaddr.sub(arg_start_vaddr)? as usize;
                let arg_start = VirtualStruct::from_id(
                    &vmem_reader,
                    kernel_type_info,
                    mm_struct.traverse("arg_start")?.tid(),
                    &arg_start_vaddr,
                )?;

                if let Ok(command_line_buffer) = arg_start.read_bytes(arg_size) {
                    let argument_buffer_list: Vec<_> = command_line_buffer
                        .split(|&byte| byte == 0)
                        .filter(|slice| !slice.is_empty())
                        .collect();

                    let mut processed_command_line = String::new();
                    for argument_buffer in argument_buffer_list {
                        let argument = String::from_utf8_lossy(argument_buffer);

                        if !processed_command_line.is_empty() {
                            processed_command_line.push(' ');
                        }

                        if argument.contains(' ') || argument.contains('\t') {
                            processed_command_line += "'";
                        }

                        processed_command_line += &argument;

                        if argument.contains(' ') || argument.contains('\t') {
                            processed_command_line += "'";
                        }
                    }

                    if !processed_command_line.is_empty() {
                        command_line = Some(processed_command_line);
                    }
                }

                let env_start_vaddr = VirtualAddress::new(
                    page_table,
                    RawVirtualAddress::new(mm_struct.traverse("env_start")?.read_u64()?),
                );

                let env_end_vaddr = VirtualAddress::new(
                    page_table,
                    RawVirtualAddress::new(mm_struct.traverse("env_end")?.read_u64()?),
                );

                let env_size = env_end_vaddr.sub(env_start_vaddr)?;
                let env_start = VirtualStruct::from_id(
                    &vmem_reader,
                    kernel_type_info,
                    mm_struct.traverse("env_start")?.tid(),
                    &env_start_vaddr,
                )?;

                if let Ok(env_variables_buffer) = env_start.read_bytes(env_size as usize) {
                    let env_variable_buffer_list: Vec<_> = env_variables_buffer
                        .split(|&byte| byte == 0)
                        .filter_map(|slice| {
                            if slice.is_empty() {
                                None
                            } else {
                                let part_list = String::from_utf8_lossy(slice)
                                    .split(['='])
                                    .map(|s| s.to_string())
                                    .collect::<Vec<_>>();

                                if part_list.len() == 2 {
                                    Some((part_list[0].to_string(), part_list[1].to_string()))
                                } else {
                                    None
                                }
                            }
                        })
                        .collect();

                    for (variable_name, variable_value) in env_variable_buffer_list {
                        environment_variable_map.insert(variable_name, variable_value);
                    }
                }

                let exe_file_vaddr = mm_struct.traverse("exe_file")?.read_vaddr()?;
                if !exe_file_vaddr.is_null() {
                    let path_struct_vaddr = mm_struct
                        .traverse("exe_file")?
                        .dereference()?
                        .traverse("f_path")?
                        .virtual_address();

                    binary_path = Self::read_path(
                        readable,
                        architecture,
                        kernel_type_info,
                        path_struct_vaddr,
                    )
                    .ok();
                }
            }
        }

        Ok(Task {
            virtual_address,
            page_table,
            binary_path,
            name: Some(comm),
            command_line,
            environment_variable_map,
            pid: tgid,
            uid,
            gid,
        })
    }

    fn get_system_version(
        memory_dump: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        init_task_vaddr: &VirtualAddress,
    ) -> Result<SystemVersion> {
        let release_array_len =
            Self::get_struct_array_member_len(kernel_type_info, "new_utsname", "release")
                .inspect_err(|err| debug!("{err:?}"))?;

        let version_array_len =
            Self::get_struct_array_member_len(kernel_type_info, "new_utsname", "version")
                .inspect_err(|err| debug!("{err:?}"))?;

        let machine_array_len =
            Self::get_struct_array_member_len(kernel_type_info, "new_utsname", "machine")
                .inspect_err(|err| debug!("{err:?}"))?;

        let vmem_reader = VirtualMemoryReader::new(memory_dump, architecture);

        let init_task_struct = VirtualStruct::from_name(
            &vmem_reader,
            kernel_type_info,
            "task_struct",
            init_task_vaddr,
        )
        .inspect_err(|err| debug!("{err:?}"))?;

        let new_utsname = try_chain!(init_task_struct
            .traverse("nsproxy")?
            .dereference()?
            .traverse("uts_ns")?
            .dereference()?
            .traverse("name"))
        .inspect_err(|err| debug!("{err:?}"))?;

        let kernel_version = try_chain!(new_utsname
            .traverse("release")?
            .read_string_lossy(Some(release_array_len)))
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        let system_version = try_chain!(new_utsname
            .traverse("version")?
            .read_string_lossy(Some(version_array_len)))
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        let arch = try_chain!(new_utsname
            .traverse("machine")?
            .read_string_lossy(Some(machine_array_len)))
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        Ok(SystemVersion {
            system_version,
            kernel_version,
            arch,
        })
    }
}

impl OperatingSystem for LinuxOperatingSystem {
    /// Returns the OS version
    fn get_os_version(&self) -> Result<SystemVersion> {
        Self::get_system_version(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            &self.kernel_type_info,
            &self.init_task_vaddr,
        )
    }

    /// Returns the system information
    fn get_system_information(&self) -> Result<SystemInformation> {
        let nodename_array_len =
            Self::get_struct_array_member_len(&self.kernel_type_info, "new_utsname", "nodename")
                .inspect_err(|err| debug!("{err:?}"))?;

        let domainname_array_len =
            Self::get_struct_array_member_len(&self.kernel_type_info, "new_utsname", "domainname")
                .inspect_err(|err| debug!("{err:?}"))?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let init_task_struct = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "task_struct",
            &self.init_task_vaddr,
        )
        .inspect_err(|err| debug!("{err:?}"))?;

        let new_utsname = try_chain!(init_task_struct
            .traverse("nsproxy")?
            .dereference()?
            .traverse("uts_ns")?
            .dereference()?
            .traverse("name"))
        .inspect_err(|err| debug!("{err:?}"))?;

        let hostname = try_chain!(new_utsname
            .traverse("nodename")?
            .read_string_lossy(Some(nodename_array_len)))
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        let domain = try_chain!(new_utsname
            .traverse("domainname")?
            .read_string_lossy(Some(domainname_array_len)))
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        Ok(SystemInformation { hostname, domain })
    }

    /// Returns the list of tasks
    fn get_task_list(&self) -> Result<Vec<Task>> {
        let mut task_list = Vec::new();

        for virtual_address in Self::enumerate_related_task_struct_vaddrs(
            &self.kernel_type_info,
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            self.init_task_vaddr,
        )? {
            match Self::get_task_from_vaddr(
                self.memory_dump.as_ref(),
                self.architecture.as_ref(),
                &self.kernel_type_info,
                virtual_address,
            ) {
                Ok(task) => {
                    task_list.push(task);
                }

                Err(err) => {
                    debug!("Failed to read the task_struct from vaddr {virtual_address}: {err:?}",);
                }
            }
        }

        Ok(task_list)
    }

    /// Returns the list of files opened by the given task
    fn get_task_open_file_list(&self) -> Result<Vec<File>> {
        let mut open_file_list = Vec::new();

        for task in self.get_task_list()? {
            let vmem_reader =
                VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

            let task_struct_vaddr = VirtualAddress::new(
                self.init_task_vaddr.root_page_table(),
                task.virtual_address.value(),
            );

            let task_struct = VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
                "task_struct",
                &task_struct_vaddr,
            )
            .inspect_err(|err| debug!("{err:?}"))?;

            let fd_array = match try_chain!(task_struct
                .traverse("files")?
                .dereference()?
                .traverse("fdt")?
                .dereference()?
                .traverse("fd")?
                .dereference())
            {
                Ok(fd_array) => fd_array,
                Err(err) => {
                    debug!("{err:?}");
                    continue;
                }
            };

            let mut fd_index: u64 = 0;
            let fd_array_vaddr = fd_array.virtual_address();

            loop {
                let fd_array_entry = fd_array_vaddr + (fd_index * 8);
                fd_index += 1;

                let file_vaddr = match vmem_reader.read_vaddr(fd_array_entry) {
                    Ok(file_vaddr) => file_vaddr,
                    Err(err) => {
                        debug!("{err:?}");
                        continue;
                    }
                };

                if file_vaddr.is_null() {
                    break;
                }

                let file = VirtualStruct::from_name(
                    &vmem_reader,
                    &self.kernel_type_info,
                    "file",
                    &file_vaddr,
                )
                .inspect_err(|err| debug!("{err:?}"))?;

                let path = match Self::read_path(
                    self.memory_dump.as_ref(),
                    self.architecture.as_ref(),
                    &self.kernel_type_info,
                    file.traverse("f_path")?.virtual_address(),
                ) {
                    Ok(path) => path,
                    Err(err) => {
                        debug!("{err:?}");
                        continue;
                    }
                };

                let file_entity = File {
                    virtual_address: file.virtual_address(),
                    task: task.virtual_address,
                    path,
                    pid: task.pid,
                };

                open_file_list.push(file_entity);
            }
        }

        Ok(open_file_list)
    }

    fn get_file_reader(&self, file: VirtualAddress) -> Result<Arc<dyn Readable>> {
        let kallsyms = match self.kallsyms {
            Some(ref kallsyms) => kallsyms,
            None => {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "Kallsyms not initialized",
                ));
            }
        };

        ReadableLinuxFileObject::from_file_vaddr(
            self.memory_dump.clone(),
            self.architecture.clone(),
            &self.kernel_type_info,
            kallsyms,
            file,
        )
    }
}

/// Implements reading from a Linux file object in memory
struct ReadableLinuxFileObject {
    /// Underlying memory dump
    memory_dump: Arc<dyn Readable>,

    /// Base virtual address of the vmemmap
    vmemmap_base: VirtualAddress,

    /// Size of struct page
    page_struct_size: u64,

    /// Size of the file
    file_size: u64,

    /// Page map
    cached_page_map: BTreeMap<u64, VirtualAddress>,
}

impl ReadableLinuxFileObject {
    /// Creates a new reader for the `struct file` object at the given vaddr
    fn from_file_vaddr(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        type_information: &TypeInformation,
        kallsyms: &Kallsyms,
        file_vaddr: VirtualAddress,
    ) -> Result<Arc<dyn Readable>> {
        let vmemmap_base_ptr = kallsyms.get("vmemmap_base").ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to find vmemmap_base symbol in kallsyms",
            )
        })?;

        let vmem_reader = VirtualMemoryReader::new(memory_dump.as_ref(), architecture.as_ref());
        let vmemmap_base = match vmem_reader.read_vaddr(vmemmap_base_ptr) {
            Ok(value) => value,
            Err(err) => {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    &format!("Failed to read vmemmap_base: {:?}", err),
                ));
            }
        };

        let page_tid = type_information.id_of("page").ok_or(Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            "Failed to find 'page' struct in BTF",
        ))?;

        let page_struct_size = type_information.size_of(page_tid)? as u64;
        let file = VirtualStruct::from_name(&vmem_reader, type_information, "file", &file_vaddr)?;

        // Parse the XArray to get all cached pages
        let inode = file.traverse("f_inode")?.dereference()?;
        let file_size = inode.traverse("i_size")?.read_u64()?;
        let i_pages_vaddr = inode
            .traverse("i_mapping")?
            .dereference()?
            .traverse("i_pages")?
            .virtual_address();

        let xarray = XArray::new(
            memory_dump.as_ref(),
            architecture.as_ref(),
            type_information,
            i_pages_vaddr,
        )?;

        let page_vaddrs = xarray.entries();
        let mut cached_page_map = BTreeMap::new();

        for &page_vaddr in page_vaddrs {
            if let Ok(folio) =
                VirtualStruct::from_name(&vmem_reader, type_information, "folio", &page_vaddr)
            {
                let page_index = folio.traverse("index")?.read_u64()?;
                let nr_pages = folio
                    .traverse("_folio_nr_pages")
                    .and_then(|field| field.read_u32())
                    .unwrap_or(1) as u64;

                for i in 0..nr_pages {
                    cached_page_map.insert(page_index + i, page_vaddr);
                }
            } else if let Ok(page) =
                VirtualStruct::from_name(&vmem_reader, type_information, "page", &page_vaddr)
            {
                let page_index = page.traverse("index")?.read_u64()?;
                cached_page_map.insert(page_index, page_vaddr);
            } else {
                debug!("Failed to parse page/folio at vaddr {:?}", page_vaddr);
                continue;
            }
        }

        Ok(Arc::new(Self {
            memory_dump,
            vmemmap_base,
            page_struct_size,
            file_size,
            cached_page_map,
        }))
    }

    /// Converts a `struct page` virtual address to a physical address.
    fn page_to_phys(&self, page_vaddr: RawVirtualAddress) -> PhysicalAddress {
        let raw_vmemmap_base_vaddr = self.vmemmap_base.value();
        let offset_from_vmemmap = page_vaddr.value() - raw_vmemmap_base_vaddr.value();
        let pfn = offset_from_vmemmap / self.page_struct_size;

        PhysicalAddress::new(pfn * PAGE_SIZE)
    }
}

impl Readable for ReadableLinuxFileObject {
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> MemoryResult<usize> {
        let mut total_bytes_read = 0;
        let mut current_offset = physical_address;
        let mut buffer_offset = 0;

        while buffer_offset < buffer.len() {
            let page_index = current_offset.value() / PAGE_SIZE;
            let offset_in_page = (current_offset.value() % PAGE_SIZE) as usize;

            let page_vaddr = self.cached_page_map.get(&page_index).ok_or_else(|| {
                MemoryError::new(
                    MemoryErrorKind::IOError,
                    &format!("Page {} not in cache", page_index),
                )
            })?;

            let phys_addr = self.page_to_phys(page_vaddr.value());
            let read_phys_addr = PhysicalAddress::new(phys_addr.value() + offset_in_page as u64);

            let remaining_in_buffer = buffer.len() - buffer_offset;
            let remaining_in_page = PAGE_SIZE as usize - offset_in_page;
            let bytes_to_read = remaining_in_buffer.min(remaining_in_page);

            let bytes_read = self.memory_dump.read(
                &mut buffer[buffer_offset..buffer_offset + bytes_to_read],
                read_phys_addr,
            )?;

            if bytes_read == 0 {
                break;
            }

            total_bytes_read += bytes_read;
            buffer_offset += bytes_read;
            current_offset = PhysicalAddress::new(current_offset.value() + bytes_read as u64);

            if bytes_read < bytes_to_read {
                break;
            }
        }

        Ok(total_bytes_read)
    }

    fn len(&self) -> crate::memory::error::Result<u64> {
        Ok(self.file_size)
    }

    fn regions(&self) -> MemoryResult<Vec<Range<PhysicalAddress>>> {
        let page_index_list = {
            let mut key_list = self.cached_page_map.keys().cloned().collect::<Vec<u64>>();
            key_list.sort();

            key_list
        };

        let range_list: Vec<Range<PhysicalAddress>> = page_index_list
            .iter()
            .map(|page_index| {
                let page_offset = PhysicalAddress::new(page_index.wrapping_mul(PAGE_SIZE));

                Range {
                    start: page_offset,
                    end: page_offset + PAGE_SIZE,
                }
            })
            .collect();

        let mut region_list: Vec<Range<PhysicalAddress>> = Vec::new();

        for range in range_list {
            if let Some(last) = region_list.last_mut() {
                if last.end >= range.start {
                    last.end = last.end.max(range.end);
                } else {
                    region_list.push(range);
                }
            } else {
                region_list.push(range);
            }
        }

        Ok(region_list)
    }
}

/// Validates if a text string contains mostly printable characters
fn is_valid_text(text: &str, min_length: usize) -> bool {
    if text.len() < min_length {
        return false;
    }

    let printable_count = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();

    // Require at least 80% printable characters
    printable_count as f32 / text.len() as f32 >= 0.8
}

/// Extracts valid text lines from a buffer that may contain binary data
fn extract_valid_lines(buffer: &[u8], min_line_length: usize) -> Vec<String> {
    let mut valid_lines = Vec::new();
    let mut current_line_start = 0;

    for i in 0..buffer.len() {
        if buffer[i] == b'\n' || i == buffer.len() - 1 {
            let line_end = if buffer[i] == b'\n' { i } else { i + 1 };
            let line_bytes = &buffer[current_line_start..line_end];

            if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                let line_clean = line_str.trim_end_matches('\r').trim();

                if is_valid_text(line_clean, min_line_length) {
                    valid_lines.push(line_clean.to_string());
                }
            }

            current_line_start = line_end + 1;
        }
    }

    valid_lines
}

impl From<BtfparseError> for Error {
    /// Converts a btfparse error into a System error
    fn from(error: BtfparseError) -> Self {
        Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            &format!("btfparse has returned the following error: {error:?}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_valid_lines_preserves_valid_input() {
        let input = b"This is a valid line\nAnother valid line\nThird valid line\n";
        let expected = vec![
            "This is a valid line",
            "Another valid line",
            "Third valid line",
        ];

        let result = extract_valid_lines(input, 1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_valid_lines_handles_different_line_endings() {
        let input = b"Line with CRLF\r\nAnother line\r\nThird line\r\n";
        let expected = vec!["Line with CRLF", "Another line", "Third line"];

        let result = extract_valid_lines(input, 1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_valid_lines_filters_short_lines() {
        let input = b"This is long enough\nShort\nAnother long line\n";
        let expected = vec!["This is long enough", "Another long line"];

        let result = extract_valid_lines(input, 10);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_valid_lines_handles_no_final_newline() {
        let input = b"First line\nSecond line\nLast line without newline";
        let expected = vec!["First line", "Second line", "Last line without newline"];

        let result = extract_valid_lines(input, 1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_valid_lines_trims_whitespace() {
        let input = b"  Line with leading spaces\nLine with trailing spaces  \n  Both sides  \n";
        let expected = vec![
            "Line with leading spaces",
            "Line with trailing spaces",
            "Both sides",
        ];

        let result = extract_valid_lines(input, 1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_is_valid_text_accepts_fully_printable() {
        assert!(is_valid_text("This is 100% valid ASCII text!", 1));
        assert!(is_valid_text("Line with spaces and punctuation.", 1));
        assert!(is_valid_text("Numbers 12345 are fine", 1));
    }

    #[test]
    fn test_is_valid_text_rejects_mostly_binary() {
        let binary_heavy = "abc\x00\x01\x02\x03\x04\x05";
        assert!(!is_valid_text(binary_heavy, 1));
    }

    #[test]
    fn test_is_valid_text_respects_min_length() {
        assert!(!is_valid_text("ab", 5));
        assert!(is_valid_text("abcde", 5));
        assert!(is_valid_text("abcdef", 5));
    }
}
