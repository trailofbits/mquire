//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        architecture::Architecture, entities::task::Task, error::Result,
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{primitives::RawVirtualAddress, readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        operating_system::{utils::get_struct_member_byte_offset, LinuxOperatingSystem},
        virtual_struct::VirtualStruct,
    },
    try_chain,
};

use {btfparse::TypeInformation, log::debug};

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Sub,
    path::PathBuf,
};

impl LinuxOperatingSystem {
    /// Returns the list of tasks
    pub(super) fn get_task_list_impl(&self) -> Result<Vec<Task>> {
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

    /// Enumerates the virtual addresses of task structs related to the given one
    pub(super) fn enumerate_related_task_struct_vaddrs(
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
                let sibling_offset =
                    get_struct_member_byte_offset(kernel_type_info, task_struct.tid(), "sibling")?;

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

    /// Returns a snapshot for the task entity at the given VirtualAddress
    pub(super) fn get_task_from_vaddr(
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

    /// Reconstructs the path from a dentry structure
    pub(super) fn read_path(
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
}
