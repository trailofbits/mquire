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
        error::{Error as CoreError, ErrorKind as CoreErrorKind, Result as CoreResult},
        operating_system::OperatingSystem,
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    operating_system::linux::{btf::BtfparseReadableAdapter, virtual_struct::VirtualStruct},
    utils::reader::Reader,
};

use btfparse::{Error as BtfparseError, Offset as BtfparseOffset, TypeInformation};

use std::{collections::BTreeMap, ops::Sub, path::PathBuf, rc::Rc};

/// Chunk size used to search the memory dump for kernel data
const CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Swapper process comm string
const SWAPPER_PROCESS_COMM: &str = "swapper/0\x00\x00\x00\x00\x00\x00\x00";

/// BTF signature for little endian machines
const BTF_LITTLE_ENDIAN_SIGNATURE: [u8; 12] = [
    0x9F, 0xEB, // Magic number
    0x01, // Version
    0x00, // Flags
    0x18, 0x00, 0x00, 0x00, // Header size
    0x00, 0x00, 0x00, 0x00, // Type offset section
];

/// Minimum size of the BTF type section, used to skip BTF data for kernel modules
const MIN_BTF_TYPE_SECTION_SIZE: u32 = 2 * 1024 * 1024;

/// A task entity, along with the linked task list
struct TaskSnapshot {
    /// The task entity
    pub task: Task,

    /// The linked task list (children, siblings, parents)
    pub linked_task_list: Vec<VirtualAddress>,
}

/// Implements the OperatingSystem trait for Linux
pub struct LinuxOperatingSystem {
    /// The memory dump
    memory_dump: Rc<dyn Readable>,

    /// The target architecture
    architecture: Rc<dyn Architecture>,

    /// Kernel debug symbols
    pub kernel_type_info: TypeInformation,

    /// The virtual address of the swapper task_struct
    pub swapper_task_struct_vaddr: VirtualAddress,
}

impl LinuxOperatingSystem {
    /// Creates a new `LinuxOperatingSystem` instance
    pub fn new(
        memory_dump: Rc<dyn Readable>,
        architecture: Rc<dyn Architecture>,
    ) -> CoreResult<Rc<Self>> {
        let kernel_type_info = Self::get_kernel_type_info(memory_dump.as_ref())?;
        let swapper_task_struct_vaddr = Self::get_swapper_struct_virtual_addr(
            memory_dump.as_ref(),
            architecture.as_ref(),
            &kernel_type_info,
        )?;

        Ok(Rc::new(Self {
            memory_dump,
            architecture,
            kernel_type_info,
            swapper_task_struct_vaddr,
        }))
    }

    /// Scans the given `Readable` object for the kernel BTF debug symbols
    fn get_kernel_type_info(readable: &dyn Readable) -> CoreResult<TypeInformation> {
        let chunk_count = readable.len()? / CHUNK_SIZE;
        let mut chunk_buffer = [0; CHUNK_SIZE as usize];

        for chunk_index in 0..chunk_count {
            let physical_chunk_address = PhysicalAddress::new(chunk_index * CHUNK_SIZE);
            readable.read(&mut chunk_buffer, physical_chunk_address)?;

            for offset in chunk_buffer
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
                let type_section_size_offset = offset + BTF_LITTLE_ENDIAN_SIGNATURE.len();
                let type_section_size = u32::from_le_bytes([
                    chunk_buffer[type_section_size_offset],
                    chunk_buffer[type_section_size_offset + 1],
                    chunk_buffer[type_section_size_offset + 2],
                    chunk_buffer[type_section_size_offset + 3],
                ]);

                if type_section_size >= MIN_BTF_TYPE_SECTION_SIZE {
                    let btf_offset = physical_chunk_address + (offset as u64);
                    let readable_adapter =
                        BtfparseReadableAdapter::new(readable, btf_offset.value());

                    let type_information = match TypeInformation::new(&readable_adapter) {
                        Ok(ti) => ti,
                        Err(_) => continue,
                    };

                    if type_information.id_of("task_struct").is_some() {
                        return Ok(type_information);
                    }
                }
            }
        }

        Err(CoreError::new(
            CoreErrorKind::OperatingSystemInitializationFailed,
            "Failed to locate the BTF debug symbols",
        ))
    }

    /// Returns a byte member offset
    fn get_struct_member_byte_offset(
        type_information: &TypeInformation,
        tid: u32,
        member_name: &str,
    ) -> CoreResult<u64> {
        if let (_, BtfparseOffset::ByteOffset(byte_offset)) =
            type_information.offset_of(tid, member_name)?
        {
            Ok(byte_offset as u64)
        } else {
            Err(CoreError::new(
                CoreErrorKind::OperatingSystemInitializationFailed,
                "Unexpected bitfield offset found when retrieving the task_struct::comm offset",
            ))
        }
    }

    /// Returns the location of the swapper task_struct
    fn get_swapper_struct_location(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
    ) -> CoreResult<(PhysicalAddress, RawVirtualAddress)> {
        let task_struct_tid = kernel_type_info.id_of("task_struct").ok_or(CoreError::new(
            CoreErrorKind::OperatingSystemInitializationFailed,
            "Failed to locate the task_struct type",
        ))?;

        let chunk_count = readable.len()? / CHUNK_SIZE;
        let mut chunk_buffer = [0; CHUNK_SIZE as usize];

        let reader = Reader::new(readable, architecture.endianness() == Endianness::Little);

        for chunk_index in 0..chunk_count {
            let page_physical_address = PhysicalAddress::new(chunk_index * CHUNK_SIZE);
            reader.read(page_physical_address, &mut chunk_buffer)?;

            if let Some(offset) = chunk_buffer
                .windows(SWAPPER_PROCESS_COMM.len())
                .position(|window| window == SWAPPER_PROCESS_COMM.as_bytes())
            {
                let swapper_comm_physical_address = page_physical_address + (offset as u64);
                let swapper_task_physical_address = swapper_comm_physical_address
                    - Self::get_struct_member_byte_offset(
                        kernel_type_info,
                        task_struct_tid,
                        "comm",
                    )?;

                let swapper_struct_parent_field = reader.read_u64(
                    swapper_task_physical_address
                        + Self::get_struct_member_byte_offset(
                            kernel_type_info,
                            task_struct_tid,
                            "parent",
                        )?,
                )?;

                let swapper_struct_real_parent_field = reader.read_u64(
                    swapper_task_physical_address
                        + Self::get_struct_member_byte_offset(
                            kernel_type_info,
                            task_struct_tid,
                            "real_parent",
                        )?,
                )?;

                let swapper_struct_raw_vaddr =
                    if swapper_struct_parent_field == swapper_struct_real_parent_field {
                        RawVirtualAddress::new(swapper_struct_parent_field)
                    } else {
                        continue;
                    };

                return Ok((swapper_task_physical_address, swapper_struct_raw_vaddr));
            }
        }

        Err(CoreError::new(
            CoreErrorKind::OperatingSystemInitializationFailed,
            "Failed to locate the swapper task_struct",
        ))
    }

    /// Returns the virtual address of the swapper task_struct
    fn get_swapper_struct_virtual_addr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
    ) -> CoreResult<VirtualAddress> {
        let (swapper_struct_physical_addr, swapper_struct_raw_vaddr) =
            Self::get_swapper_struct_location(readable, architecture, kernel_type_info)?;

        let page_table = architecture.locate_page_table_for_virtual_address(
            readable,
            swapper_struct_physical_addr,
            swapper_struct_raw_vaddr,
        )?;

        Ok(VirtualAddress::new(page_table, swapper_struct_raw_vaddr))
    }

    fn get_os_version(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        swapper_task_struct_vaddr: VirtualAddress,
    ) -> CoreResult<SystemVersion> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let swapper_task_struct = VirtualStruct::from_name(
            &vmem_reader,
            kernel_type_info,
            "task_struct",
            &swapper_task_struct_vaddr,
        )?;

        let new_utsname = swapper_task_struct
            .traverse("nsproxy")?
            .dereference()?
            .traverse("uts_ns")?
            .dereference()?
            .traverse("name")?;

        let kernel_version = new_utsname
            .traverse("release")?
            .read_string(Some(65), true)?;

        let system_version = new_utsname
            .traverse("version")?
            .read_string(Some(65), true)?;

        let arch = new_utsname
            .traverse("machine")?
            .read_string(Some(65), true)?;

        Ok(SystemVersion {
            system_version,
            kernel_version,
            arch,
        })
    }

    fn get_system_information(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        swapper_task_struct_vaddr: VirtualAddress,
    ) -> CoreResult<SystemInformation> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let swapper_task_struct = VirtualStruct::from_name(
            &vmem_reader,
            kernel_type_info,
            "task_struct",
            &swapper_task_struct_vaddr,
        )?;

        let new_utsname = swapper_task_struct
            .traverse("nsproxy")?
            .dereference()?
            .traverse("uts_ns")?
            .dereference()?
            .traverse("name")?;

        let hostname = new_utsname
            .traverse("nodename")?
            .read_string(Some(65), true)?;

        let domain = new_utsname
            .traverse("domainname")?
            .read_string(Some(65), true)?;

        let domain = if domain.is_empty() {
            None
        } else {
            Some(domain)
        };

        Ok(SystemInformation { hostname, domain })
    }

    /// Reconstructs the path from a dentry structure
    fn read_path(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> CoreResult<String> {
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
                    .read_string(Some(dname_length as usize), true)?
            } else {
                dentry.traverse("d_iname")?.read_string(Some(16), true)?
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
    fn get_task_snapshot(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> CoreResult<TaskSnapshot> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let task_struct = VirtualStruct::from_name(
            &vmem_reader,
            kernel_type_info,
            "task_struct",
            &virtual_address,
        )?;

        let comm = task_struct.traverse("comm")?.read_string(Some(16), false)?;
        let tgid = task_struct.traverse("tgid")?.read_u32()?;
        let parent = task_struct.traverse("parent")?.read_vaddr()?;
        let real_parent = task_struct.traverse("real_parent")?.read_vaddr()?;

        let sibling_offset =
            Self::get_struct_member_byte_offset(kernel_type_info, task_struct.tid(), "sibling")?;

        let prev_child = task_struct.traverse("children.prev")?.read_vaddr()? - sibling_offset;
        let next_child = task_struct.traverse("children.next")?.read_vaddr()? - sibling_offset;
        let prev_sibling = task_struct.traverse("sibling.prev")?.read_vaddr()? - sibling_offset;
        let next_sibling = task_struct.traverse("sibling.next")?.read_vaddr()? - sibling_offset;

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

        Ok(TaskSnapshot {
            task: Task {
                virtual_address,
                page_table,
                binary_path,
                name: Some(comm),
                command_line,
                environment_variable_map,
                pid: tgid,
                uid,
                gid,
            },

            linked_task_list: vec![
                next_child,
                prev_child,
                next_sibling,
                prev_sibling,
                parent,
                real_parent,
            ],
        })
    }
}

impl OperatingSystem for LinuxOperatingSystem {
    /// Returns the OS version
    fn get_os_version(&self) -> CoreResult<SystemVersion> {
        Self::get_os_version(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            &self.kernel_type_info,
            self.swapper_task_struct_vaddr,
        )
    }

    /// Returns the system information
    fn get_system_information(&self) -> CoreResult<SystemInformation> {
        Self::get_system_information(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            &self.kernel_type_info,
            self.swapper_task_struct_vaddr,
        )
    }

    /// Returns the list of tasks
    fn get_task_list(&self) -> CoreResult<Vec<Task>> {
        let mut task_list = Vec::new();

        let mut visited_physical_address_list = Vec::new();
        let mut next_virtual_address_queue = vec![self.swapper_task_struct_vaddr];

        while !next_virtual_address_queue.is_empty() {
            let virtual_address_queue = next_virtual_address_queue.clone();
            next_virtual_address_queue.clear();

            for virtual_address in virtual_address_queue {
                let physical_address = match self
                    .architecture
                    .translate_virtual_address(self.memory_dump.as_ref(), virtual_address)
                {
                    Ok(physical_address_range) => physical_address_range.address(),
                    Err(_) => {
                        continue;
                    }
                };

                if visited_physical_address_list.contains(&physical_address.value()) {
                    continue;
                }

                visited_physical_address_list.push(physical_address.value());

                match Self::get_task_snapshot(
                    self.memory_dump.as_ref(),
                    self.architecture.as_ref(),
                    &self.kernel_type_info,
                    virtual_address,
                ) {
                    Ok(task_snapshot) => {
                        task_list.push(task_snapshot.task);

                        for linked_task in task_snapshot.linked_task_list {
                            next_virtual_address_queue.push(linked_task);
                        }
                    }

                    Err(_) => {
                        continue;
                    }
                }
            }
        }

        Ok(task_list)
    }

    /// Returns the list of files opened by the given task
    fn get_task_open_file_list(&self) -> CoreResult<Vec<File>> {
        let mut open_file_list = Vec::new();

        for task in self.get_task_list()? {
            let vmem_reader =
                VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());
            let task_struct = VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
                "task_struct",
                &task.virtual_address,
            )?;

            let fd_array = task_struct
                .traverse("files")?
                .dereference()?
                .traverse("fdt")?
                .dereference()?
                .traverse("fd")?
                .dereference()?;

            let mut fd_index: u64 = 0;

            let fd_array_vaddr = fd_array.virtual_address();

            loop {
                let fd_array_entry = fd_array_vaddr + (fd_index * 8);
                fd_index += 1;

                let file_vaddr = vmem_reader.read_vaddr(fd_array_entry)?;
                if file_vaddr.is_null() {
                    break;
                }

                let file = VirtualStruct::from_name(
                    &vmem_reader,
                    &self.kernel_type_info,
                    "file",
                    &file_vaddr,
                )?;

                let path = Self::read_path(
                    self.memory_dump.as_ref(),
                    self.architecture.as_ref(),
                    &self.kernel_type_info,
                    file.traverse("f_path")?.virtual_address(),
                )?;

                let file_entity = File {
                    virtual_address: file.virtual_address(),
                    path,
                    pid: task.pid,
                };

                open_file_list.push(file_entity);
            }
        }

        Ok(open_file_list)
    }
}

impl From<BtfparseError> for CoreError {
    /// Converts a btfparse error into a System error
    fn from(error: BtfparseError) -> Self {
        CoreError::new(
            CoreErrorKind::OperatingSystemInitializationFailed,
            &format!("btfparse has returned the following error: {:?}", error),
        )
    }
}
