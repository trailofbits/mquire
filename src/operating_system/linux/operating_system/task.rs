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
    memory::{primitives::RawVirtualAddress, readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        entities::task::{Task, TaskKind},
        kallsyms::Kallsyms,
        operating_system::LinuxOperatingSystem,
        pid_ns_iterator::PidNsIterator,
        task_struct_iterator::TaskStructIterator,
        virtual_struct::VirtualStruct,
    },
    try_chain,
};

use {btfparse::TypeInformation, log::debug};

use std::{collections::BTreeMap, ops::Sub, path::PathBuf, sync::Arc};

/// Maximum size for command line arguments buffer (1 MB)
const MAX_ARG_SIZE: usize = 1024 * 1024;

/// Maximum size for environment variables buffer (1 MB)
const MAX_ENV_SIZE: usize = 1024 * 1024;

/// Public iterator over Linux tasks
pub struct TaskIterator<'a> {
    /// Inner iterator over task_struct virtual addresses
    task_struct_it: TaskStructIterator<'a>,

    /// The memory dump being analyzed
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel type information from BTF
    kernel_type_info: &'a TypeInformation,

    /// The virtual address of the root task used for iteration
    root_task: VirtualAddress,
}

impl<'a> TaskIterator<'a> {
    /// Creates a new TaskIterator
    pub fn new(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        kernel_type_info: &'a TypeInformation,
        start_vaddr: VirtualAddress,
    ) -> Result<Self> {
        let inner = TaskStructIterator::new(
            memory_dump.clone(),
            architecture.clone(),
            kernel_type_info,
            start_vaddr,
        )?;

        Ok(Self {
            task_struct_it: inner,
            memory_dump,
            architecture,
            kernel_type_info,
            root_task: start_vaddr,
        })
    }

    /// Returns the virtual address of the root task used for iteration
    pub fn root_task(&self) -> VirtualAddress {
        self.root_task
    }
}

impl<'a> Iterator for TaskIterator<'a> {
    type Item = Result<Task>;

    fn next(&mut self) -> Option<Self::Item> {
        let addr = self.task_struct_it.next()?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let task_struct = match VirtualStruct::from_name(
            &vmem_reader,
            self.kernel_type_info,
            "task_struct",
            &addr,
        ) {
            Ok(ts) => ts,
            Err(err) => return Some(Err(err)),
        };

        let result = LinuxOperatingSystem::parse_virtual_task_struct(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            self.kernel_type_info,
            &task_struct,
        );

        Some(result)
    }
}

/// Public iterator over Linux tasks discovered via the PID namespace IDR
pub struct PidNsTaskIterator<'a> {
    /// Inner iterator over task_struct virtual addresses from the PID namespace
    pid_ns_it: PidNsIterator<'a>,

    /// The memory dump being analyzed
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel type information from BTF
    kernel_type_info: &'a TypeInformation,
}

impl<'a> PidNsTaskIterator<'a> {
    /// Creates a new PidNsTaskIterator from a pid_namespace address
    pub fn new(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        kernel_type_info: &'a TypeInformation,
        pid_ns_vaddr: VirtualAddress,
    ) -> Result<Self> {
        let pid_ns_it = PidNsIterator::new(
            memory_dump.clone(),
            architecture.clone(),
            kernel_type_info,
            pid_ns_vaddr,
        )?;

        Ok(Self {
            pid_ns_it,
            memory_dump,
            architecture,
            kernel_type_info,
        })
    }

    /// Creates a new PidNsTaskIterator by looking up init_pid_ns from kallsyms
    pub fn from_kallsyms(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        kernel_type_info: &'a TypeInformation,
        kallsyms: &Kallsyms,
    ) -> Result<Self> {
        let init_pid_ns = kallsyms.get("init_pid_ns").ok_or_else(|| {
            Error::new(
                ErrorKind::EntityNotFound,
                "init_pid_ns symbol not found in kallsyms",
            )
        })?;

        debug!("PidNsTaskIterator: found init_pid_ns at {:?}", init_pid_ns);

        Self::new(memory_dump, architecture, kernel_type_info, init_pid_ns)
    }
}

impl<'a> Iterator for PidNsTaskIterator<'a> {
    type Item = Result<Task>;

    fn next(&mut self) -> Option<Self::Item> {
        let addr = self.pid_ns_it.next()?;
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let task_struct = match VirtualStruct::from_name(
            &vmem_reader,
            self.kernel_type_info,
            "task_struct",
            &addr,
        ) {
            Ok(task_struct) => task_struct,
            Err(error) => return Some(Err(error)),
        };

        let result = LinuxOperatingSystem::parse_virtual_task_struct(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            self.kernel_type_info,
            &task_struct,
        );

        Some(result)
    }
}

impl LinuxOperatingSystem {
    /// Returns a task at the given virtual address
    pub(super) fn task_at_impl(&self, vaddr: VirtualAddress) -> Result<Task> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let task_struct =
            VirtualStruct::from_name(&vmem_reader, &self.kernel_type_info, "task_struct", &vaddr)?;

        Self::parse_virtual_task_struct(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            &self.kernel_type_info,
            &task_struct,
        )
    }

    /// Returns an iterator over tasks starting from init_task
    pub(super) fn iter_tasks_impl(&self) -> Result<TaskIterator<'_>> {
        TaskIterator::new(
            self.memory_dump.clone(),
            self.architecture.clone(),
            &self.kernel_type_info,
            self.init_task_vaddr,
        )
    }

    /// Returns an iterator over tasks starting from the given root
    pub(super) fn iter_tasks_from_impl(&self, root: VirtualAddress) -> Result<TaskIterator<'_>> {
        TaskIterator::new(
            self.memory_dump.clone(),
            self.architecture.clone(),
            &self.kernel_type_info,
            root,
        )
    }

    /// Returns an iterator over tasks discovered via the PID namespace IDR
    pub(super) fn iter_pid_ns_tasks_impl(&self) -> Result<PidNsTaskIterator<'_>> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::EntityNotFound,
                "Kallsyms not available - cannot locate init_pid_ns",
            )
        })?;

        PidNsTaskIterator::from_kallsyms(
            self.memory_dump.clone(),
            self.architecture.clone(),
            &self.kernel_type_info,
            kallsyms,
        )
    }

    /// Returns an iterator over tasks discovered via the specified PID namespace
    pub(super) fn iter_pid_ns_tasks_at_impl(
        &self,
        pid_ns_vaddr: VirtualAddress,
    ) -> Result<PidNsTaskIterator<'_>> {
        PidNsTaskIterator::new(
            self.memory_dump.clone(),
            self.architecture.clone(),
            &self.kernel_type_info,
            pid_ns_vaddr,
        )
    }

    /// Returns a snapshot for the task entity at the given VirtualAddress
    pub(super) fn parse_virtual_task_struct(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        task_struct: &VirtualStruct,
    ) -> Result<Task> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);

        let comm = task_struct.traverse("comm")?.read_string_lossy(Some(16))?;
        let pid = task_struct.traverse("pid")?.read_u32()?;
        let tgid = task_struct.traverse("tgid")?.read_u32()?;

        let ppid = try_chain!(
            task_struct
                .traverse("parent")?
                .dereference()?
                .traverse("tgid")?
                .read_u32()
        )
        .inspect_err(|error| {
            debug!(
                "Could not determine the parent process id for process {:?}: {error:?}",
                task_struct.virtual_address()
            )
        })
        .ok();

        let real_ppid = try_chain!(
            task_struct
                .traverse("real_parent")?
                .dereference()?
                .traverse("tgid")?
                .read_u32()
        )
        .inspect_err(|error| {
            debug!(
                "Could not determine the real parent process id for process {:?}: {error:?}",
                task_struct.virtual_address()
            )
        })
        .ok();

        let cred = task_struct.traverse("cred")?.dereference()?;
        let uid = cred.traverse("uid")?.read_u32()?;
        let gid = cred.traverse("gid")?.read_u32()?;

        let mut page_table = task_struct.virtual_address().root_page_table();
        let mut command_line: Option<String> = None;
        let mut environment_variable_map = BTreeMap::new();
        let mut binary_path: Option<String> = None;

        let mm_struct = task_struct.traverse("mm")?.dereference()?;
        let is_kthread = mm_struct.virtual_address().is_null();

        let kind = if is_kthread {
            TaskKind::Kthread
        } else if tgid == pid {
            TaskKind::ThreadGroupLeader
        } else {
            TaskKind::Thread
        };

        if !is_kthread {
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
                if arg_size <= MAX_ARG_SIZE {
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
                }

                let env_start_vaddr = VirtualAddress::new(
                    page_table,
                    RawVirtualAddress::new(mm_struct.traverse("env_start")?.read_u64()?),
                );

                let env_end_vaddr = VirtualAddress::new(
                    page_table,
                    RawVirtualAddress::new(mm_struct.traverse("env_end")?.read_u64()?),
                );

                let env_size = env_end_vaddr.sub(env_start_vaddr)? as usize;
                if env_size <= MAX_ENV_SIZE {
                    let env_start = VirtualStruct::from_id(
                        &vmem_reader,
                        kernel_type_info,
                        mm_struct.traverse("env_start")?.tid(),
                        &env_start_vaddr,
                    )?;

                    if let Ok(env_variables_buffer) = env_start.read_bytes(env_size) {
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
            virtual_address: task_struct.virtual_address(),
            kind,
            page_table,
            binary_path,
            name: Some(comm),
            command_line,
            environment_variable_map,
            tgid,
            ppid,
            real_ppid,
            pid,
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
