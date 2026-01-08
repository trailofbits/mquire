//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{entities::file::File, error::Result, virtual_memory_reader::VirtualMemoryReader},
    memory::virtual_address::VirtualAddress,
    operating_system::linux::{
        operating_system::LinuxOperatingSystem, virtual_struct::VirtualStruct,
    },
    try_chain,
};

use log::debug;

impl LinuxOperatingSystem {
    /// Returns the list of files opened by tasks
    pub(super) fn get_task_open_file_list_impl(&self) -> Result<Vec<File>> {
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

            let fd_array = match try_chain!(
                task_struct
                    .traverse("files")?
                    .dereference()?
                    .traverse("fdt")?
                    .dereference()?
                    .traverse("fd")?
                    .dereference()
            ) {
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

                let inode = file
                    .traverse("f_inode")
                    .ok()
                    .and_then(|f| f.read_vaddr().ok())
                    .filter(|ptr| !ptr.is_null())
                    .and_then(|f_inode_ptr| {
                        VirtualStruct::from_name(
                            &vmem_reader,
                            &self.kernel_type_info,
                            "inode",
                            &f_inode_ptr,
                        )
                        .ok()
                    })
                    .and_then(|inode_struct| inode_struct.traverse("i_ino").ok())
                    .and_then(|f| f.read_u64().ok());

                let file_entity = File {
                    virtual_address: file.virtual_address(),
                    task: task.virtual_address,
                    path,
                    pid: task.pid,
                    inode,
                };

                open_file_list.push(file_entity);
            }
        }

        Ok(open_file_list)
    }
}
