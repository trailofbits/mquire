//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        architecture::Architecture,
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        entities::file::File, operating_system::LinuxOperatingSystem, utils::get_pointer_size,
        virtual_struct::VirtualStruct,
    },
    try_chain,
};

use {
    btfparse::{TypeInformation, TypeVariant},
    log::{debug, error},
};

use std::sync::Arc;

/// Fallback/safety limit for max_fds
const MAX_FDS_LIMIT: u64 = 65536;

/// Max consecutive read errors before stopping iteration
const MAX_CONSECUTIVE_READ_ERRORS: u32 = 10;

/// Iterator over open files for a single task
pub struct TaskOpenFilesIterator<'a> {
    /// The memory dump
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel debug symbols
    kernel_type_info: &'a TypeInformation,

    /// The task virtual address
    task_vaddr: VirtualAddress,

    /// The task's thread group identifier
    task_tgid: u32,

    /// Virtual address of the fd array
    fd_array_vaddr: VirtualAddress,

    /// Maximum number of file descriptors
    max_fds: u64,

    /// Current file descriptor index
    fd_index: u64,

    /// Size of each fd array entry (pointer size)
    fd_entry_size: u64,

    /// Consecutive read error count
    consecutive_read_errors: u32,
}

impl Iterator for TaskOpenFilesIterator<'_> {
    type Item = Result<File>;

    fn next(&mut self) -> Option<Self::Item> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        loop {
            if self.fd_index >= self.max_fds {
                return None;
            }

            let fd = self.fd_index;
            self.fd_index += 1;

            let fd_array_entry = self.fd_array_vaddr + (fd * self.fd_entry_size);
            let file_vaddr = match vmem_reader.read_vaddr(fd_array_entry) {
                Ok(vaddr) => {
                    self.consecutive_read_errors = 0;
                    vaddr
                }

                Err(err) => {
                    error!("Failed to read fd array entry at index {fd}: {err:?}");

                    self.consecutive_read_errors += 1;
                    if self.consecutive_read_errors >= MAX_CONSECUTIVE_READ_ERRORS {
                        error!("Too many consecutive read errors, stopping iteration");
                        return None;
                    }

                    continue;
                }
            };

            if file_vaddr.is_null() {
                continue;
            }

            let file = match VirtualStruct::from_name(
                &vmem_reader,
                self.kernel_type_info,
                "file",
                &file_vaddr,
            ) {
                Ok(file) => file,

                Err(err) => {
                    debug!("Failed to parse file struct at fd {fd}: {err:?}");
                    continue;
                }
            };

            let path = match LinuxOperatingSystem::read_path(
                self.memory_dump.as_ref(),
                self.architecture.as_ref(),
                self.kernel_type_info,
                file.traverse("f_path").ok()?.virtual_address(),
            ) {
                Ok(path) => path,
                Err(err) => {
                    debug!("Failed to read path for fd {fd}: {err:?}");
                    continue;
                }
            };

            let optional_inode = file
                .traverse("f_inode")
                .ok()
                .and_then(|f| f.read_vaddr().ok())
                .filter(|ptr| !ptr.is_null())
                .and_then(|f_inode_ptr| {
                    VirtualStruct::from_name(
                        &vmem_reader,
                        self.kernel_type_info,
                        "inode",
                        &f_inode_ptr,
                    )
                    .ok()
                })
                .and_then(|inode_struct| inode_struct.traverse("i_ino").ok())
                .and_then(|f| f.read_u64().ok());

            return Some(Ok(File {
                virtual_address: file.virtual_address(),
                task: self.task_vaddr,
                path,
                tgid: self.task_tgid,
                fd,
                inode: optional_inode,
            }));
        }
    }
}

impl LinuxOperatingSystem {
    /// Returns an iterator over open files for a single task
    pub(super) fn iter_task_open_files_impl(
        &self,
        task_vaddr: VirtualAddress,
    ) -> Result<TaskOpenFilesIterator<'_>> {
        Self::check_fdtable_type(&self.kernel_type_info)?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let task_struct = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "task_struct",
            &task_vaddr,
        )?;

        let task_tgid = try_chain!(task_struct.traverse("tgid")?.read_u32())?;

        let fdt = try_chain!(
            task_struct
                .traverse("files")?
                .dereference()?
                .traverse("fdt")?
                .dereference()
        )?;

        let fd_array = fdt.traverse("fd")?.dereference()?;
        let max_fds = try_chain!(fdt.traverse("max_fds")?.read_u32())
            .map(|max_fds| max_fds as u64)
            .unwrap_or(MAX_FDS_LIMIT)
            .min(MAX_FDS_LIMIT);

        let fd_entry_size = get_pointer_size(&self.kernel_type_info)?;

        Ok(TaskOpenFilesIterator {
            memory_dump: self.memory_dump.clone(),
            architecture: self.architecture.clone(),
            kernel_type_info: &self.kernel_type_info,
            task_vaddr,
            task_tgid,
            fd_array_vaddr: fd_array.virtual_address(),
            max_fds,
            fd_index: 0,
            fd_entry_size,
            consecutive_read_errors: 0,
        })
    }

    /// Validates that fdtable.fd has the expected type
    fn check_fdtable_type(type_info: &TypeInformation) -> Result<()> {
        let fdtable_tid = type_info
            .id_of("fdtable")
            .ok_or_else(|| Error::new(ErrorKind::TypeInformationError, "fdtable type not found"))?;

        let fdtable_type = match type_info.from_id(fdtable_tid) {
            Some(TypeVariant::Struct(s)) => s,
            _ => {
                return Err(Error::new(
                    ErrorKind::TypeInformationError,
                    "fdtable is not a struct",
                ));
            }
        };

        let fd_member_tid = fdtable_type
            .member_list()
            .iter()
            .find(|m| m.name().as_deref() == Some("fd"))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::TypeInformationError,
                    "fdtable.fd member not found",
                )
            })?
            .tid();

        // fd should be of type `struct file **`
        //  - First dereference: struct file *
        //  - Second dereference: struct file
        let file_ptr_tid = type_info.pointee_tid(fd_member_tid).map_err(|_| {
            Error::new(
                ErrorKind::TypeInformationError,
                "fdtable.fd is not a pointer",
            )
        })?;

        let file_tid = type_info.pointee_tid(file_ptr_tid).map_err(|_| {
            Error::new(
                ErrorKind::TypeInformationError,
                "fdtable.fd is not a pointer to pointer",
            )
        })?;

        let file_name = type_info.name_of(file_tid);
        if file_name.as_deref() != Some("file") {
            return Err(Error::new(
                ErrorKind::TypeInformationError,
                &format!(
                    "fdtable.fd does not point to struct file (found: {:?})",
                    file_name
                ),
            ));
        }

        Ok(())
    }
}
