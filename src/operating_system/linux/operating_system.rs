//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

mod boot_time;
mod cgroup;
mod dmesg;
mod file;
mod kallsyms_symbol;
mod kernel_module;
mod memory_mapping;
mod network_connection;
mod network_interface;
mod readable_file_linux_object;
mod syslog_file;
mod system_information;
mod task;
mod utils;

use crate::{
    core::{
        architecture::{Architecture, Endianness},
        entities::{
            file::File, network_connection::NetworkConnection, network_interface::NetworkInterface,
            system_information::SystemInformation, system_version::SystemVersion, task::Task,
        },
        error::{Error, ErrorKind, Result},
        operating_system::OperatingSystem,
    },
    generate_address_ranges,
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    operating_system::linux::{
        btf::BtfparseReadableAdapter,
        entities::{
            boot_time::BootTime, cgroup::Cgroup, dmesg::DmesgEntry,
            kallsyms_symbol::KallsymsSymbol, memory_mapping::MemoryMapping,
            syslog_file::SyslogFile,
        },
        kallsyms::Kallsyms,
        kernel_version::KernelVersion,
        operating_system::{
            readable_file_linux_object::ReadableLinuxFileObject,
            utils::get_struct_member_byte_offset,
        },
    },
    utils::reader::Reader,
};

use {
    btfparse::{Error as BtfparseError, TypeInformation},
    log::debug,
    rayon::prelude::*,
};

use std::sync::Arc;

/// Buffer size used for initial data discovery
const SCAN_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Swapper process comm string
const SWAPPER_PROCESS_COMM: &str = "swapper/0";

/// BTF signature for little endian machines
const BTF_LITTLE_ENDIAN_SIGNATURE: [u8; 3] = [
    0x9F, 0xEB, // Magic number
    0x01, // Version
];

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

    /// The kernel version
    kernel_version: Option<KernelVersion>,
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

        let kernel_version: Option<KernelVersion> = system_version
            .kernel_version
            .and_then(|version_string| version_string.parse().ok());

        let kallsyms = Kallsyms::new(
            memory_dump.as_ref(),
            architecture.as_ref(),
            init_task_vaddr.root_page_table(),
            &kernel_version,
        )
        .inspect_err(|err| debug!("{err:?}"))
        .ok();

        Ok(Arc::new(Self {
            memory_dump,
            architecture,
            kernel_type_info,
            init_task_vaddr,
            kallsyms,
            kernel_version,
        }))
    }

    /// Returns the cgroup list
    pub fn get_cgroup_list(&self) -> Result<Vec<Cgroup>> {
        self.get_cgroup_list_impl()
    }

    /// Returns the list of memory mappings in the given task
    pub fn get_task_memory_mappings(&self) -> Result<Vec<MemoryMapping>> {
        self.get_task_memory_mappings_impl()
    }

    /// Returns the syslog file data from memory
    pub fn get_syslog_file_regions(&self) -> Result<Vec<SyslogFile>> {
        self.get_syslog_file_regions_impl()
    }

    /// Returns kernel log messages (dmesg) from the printk_ringbuffer
    pub fn get_dmesg_entries(&self) -> Result<Vec<DmesgEntry>> {
        self.get_dmesg_entries_impl()
    }

    /// Returns the list of kernel symbols from kallsyms
    pub fn get_kallsyms_symbols(&self) -> Result<Vec<KallsymsSymbol>> {
        self.get_kallsyms_symbols_impl()
    }

    /// Returns the system boot time
    pub fn get_boot_time(&self) -> Result<Vec<BootTime>> {
        self.get_boot_time_impl()
    }

    /// Returns the list of network connections
    pub fn get_network_connection_list(&self) -> Result<Vec<NetworkConnection>> {
        self.get_network_connection_list_impl()
    }

    /// Returns the list of loaded kernel modules
    pub fn get_kernel_module_list(
        &self,
    ) -> Result<Vec<crate::operating_system::linux::entities::kernel_module::KernelModule>> {
        self.get_kernel_module_list_impl()
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

        let comm_offset = get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "comm")?;

        let parent_offset =
            get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "parent")?;

        let real_parent_offset =
            get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "real_parent")?;

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
}

impl OperatingSystem for LinuxOperatingSystem {
    fn get_os_version(&self) -> Result<SystemVersion> {
        Self::get_system_version(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            &self.kernel_type_info,
            &self.init_task_vaddr,
        )
    }

    fn get_system_information(&self) -> Result<SystemInformation> {
        self.get_system_information_impl()
    }

    fn get_task_list(&self) -> Result<Vec<Task>> {
        self.get_task_list_impl()
    }

    fn get_task_open_file_list(&self) -> Result<Vec<File>> {
        self.get_task_open_file_list_impl()
    }

    fn get_network_interface_list(&self) -> Result<Vec<NetworkInterface>> {
        self.get_network_interface_list_impl()
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

impl From<BtfparseError> for Error {
    /// Converts a btfparse error into a System error
    fn from(error: BtfparseError) -> Self {
        Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            &format!("btfparse has returned the following error: {error:?}"),
        )
    }
}
