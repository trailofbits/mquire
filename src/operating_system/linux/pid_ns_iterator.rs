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
        utils::get_struct_member_byte_offset, virtual_struct::VirtualStruct, xarray::XArray,
    },
};

use {btfparse::TypeInformation, log::error};

use std::{collections::BTreeSet, sync::Arc};

/// Maximum expected pid namespace nesting level.
/// Linux allows up to MAX_PID_NS_LEVEL (32) levels of namespace nesting.
const MAX_PID_NS_LEVEL: u32 = 32;

/// Index into struct pid.tasks[] for PIDTYPE_PID.
/// This gives us the unique task that owns this PID.
const PIDTYPE_PID: usize = 0;

/// Iterator over tasks discovered via the PID namespace xarray.
///
/// This iterator returns PIDs from the perspective of the given namespace. When initialized
/// with `init_pid_ns` (the root namespace), all processes are discovered since every process
/// is visible from root. Containerized processes appear with their outer PID (e.g., 12345)
/// rather than their container-internal PID (e.g., 1). To discover container-internal PID
/// numbers, iterate the specific nested namespace.
///
/// This implementation has only been verified with kernels 6.8.0-6.18.6.
pub struct PidNsIterator<'a> {
    /// The memory dump being analyzed
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel type information from BTF
    kernel_type_info: &'a TypeInformation,

    /// Offset of task_struct.pid_links for container_of calculation
    pid_links_offset: u64,

    /// The nesting level of the namespace we're iterating (0 = root)
    namespace_level: u32,

    /// List of struct pid addresses from the xarray
    pid_entries: Vec<VirtualAddress>,

    /// Current index into pid_entries
    current_index: usize,

    /// Set of task addresses that we have already seen to avoid duplicates
    visited_tasks: BTreeSet<RawVirtualAddress>,
}

impl<'a> PidNsIterator<'a> {
    /// Creates a new PidNsIterator from a pid_namespace address
    pub fn new(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        kernel_type_info: &'a TypeInformation,
        pid_ns_vaddr: VirtualAddress,
    ) -> Result<Self> {
        let task_struct_tid = kernel_type_info.id_of("task_struct").ok_or_else(|| {
            Error::new(
                ErrorKind::TypeInformationError,
                "Failed to find task_struct type",
            )
        })?;

        let pid_links_offset =
            get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "pid_links")?;

        let vmem_reader = VirtualMemoryReader::new(memory_dump.as_ref(), architecture.as_ref());
        let pid_ns = VirtualStruct::from_name(
            &vmem_reader,
            kernel_type_info,
            "pid_namespace",
            &pid_ns_vaddr,
        )?;

        let namespace_level = pid_ns.traverse("level")?.read_u32()?;
        let idr_rt_vaddr = pid_ns.traverse("idr.idr_rt")?.virtual_address();

        let xarray = XArray::new(
            memory_dump.as_ref(),
            architecture.as_ref(),
            kernel_type_info,
            idr_rt_vaddr,
        )?;

        let total_xarray_entries = xarray.entries().len();
        let pid_entries: Vec<_> = xarray
            .entries()
            .iter()
            .filter(|addr| addr.is_in_high_canonical_space())
            .copied()
            .collect();

        if total_xarray_entries != pid_entries.len() {
            error!(
                "PidNsIterator: xarray returned {} entries, {} passed kernel space filter, namespace at {:?}",
                total_xarray_entries,
                pid_entries.len(),
                pid_ns_vaddr
            );
        }

        Ok(Self {
            memory_dump,
            architecture,
            kernel_type_info,
            pid_links_offset,
            namespace_level,
            pid_entries,
            current_index: 0,
            visited_tasks: BTreeSet::new(),
        })
    }

    /// Converts a struct pid address to task_struct address
    fn pid_to_task_vaddr(&self, pid_vaddr: VirtualAddress) -> Option<VirtualAddress> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let pid_struct =
            VirtualStruct::from_name(&vmem_reader, self.kernel_type_info, "pid", &pid_vaddr)
                .ok()?;

        // pid.level indicates the deepest namespace level this PID is visible in.
        // A struct pid with level=N has N+1 entries in the numbers[] array, indexed by
        // namespace level. For example:
        //   - level=0: numbers[0] = root PID (1 entry)
        //   - level=1: numbers[0] = root PID, numbers[1] = container PID (2 entries)
        //   - level=2: numbers[0..2] = PIDs at each nesting level (3 entries)
        //
        // When iterating namespace at level N, all struct pid entries must have level >= N,
        // since a pid can only be registered in a namespace if it's visible at that depth.
        let level = pid_struct.traverse("level").ok()?.read_u32().ok()?;
        if level >= MAX_PID_NS_LEVEL {
            error!(
                "Invalid pid.level ({}) at {:?}, expected < {}",
                level, pid_vaddr, MAX_PID_NS_LEVEL
            );
            return None;
        }

        if level < self.namespace_level {
            error!(
                "pid.level ({}) < namespace_level ({}) at {:?}, struct pid should not be in this namespace",
                level, self.namespace_level, pid_vaddr
            );
            return None;
        }

        // Read pid.tasks[PIDTYPE_PID] to get the hlist_head linking to the owning task.
        // The tasks[] array has 4 entries for different PID types:
        //   - PIDTYPE_PID (0): unique task owning this PID
        //   - PIDTYPE_TGID (1): thread group leader
        //   - PIDTYPE_PGID (2): all tasks in the process group
        //   - PIDTYPE_SID (3): all tasks in the session
        let tasks_hlist_head = pid_struct
            .traverse(&format!("tasks[{PIDTYPE_PID}]"))
            .ok()?
            .read_vaddr()
            .ok()?;

        if tasks_hlist_head.is_null() {
            error!("Null tasks hlist_head for pid at {:?}", pid_vaddr);
            return None;
        }

        if !tasks_hlist_head.is_in_high_canonical_space() {
            error!(
                "tasks hlist_head {:?} not in kernel space for pid at {:?}",
                tasks_hlist_head, pid_vaddr
            );

            return None;
        }

        // tasks[0].first points to task_struct.pid_links[0]
        // We'd use container_of + pid_links_offset to get back to task_struct
        let task_vaddr = tasks_hlist_head - self.pid_links_offset;
        if !task_vaddr.is_in_high_canonical_space() {
            error!(
                "task_struct address {:?} not in kernel space for pid at {:?}",
                task_vaddr, pid_vaddr
            );
            return None;
        }

        Some(task_vaddr)
    }
}

impl<'a> Iterator for PidNsIterator<'a> {
    type Item = VirtualAddress;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < self.pid_entries.len() {
            let pid_vaddr = self.pid_entries[self.current_index];
            self.current_index += 1;

            if let Some(task_vaddr) = self.pid_to_task_vaddr(pid_vaddr)
                && self.visited_tasks.insert(task_vaddr.value())
            {
                return Some(task_vaddr);
            }
        }

        None
    }
}
