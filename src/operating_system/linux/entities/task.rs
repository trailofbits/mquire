//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{primitives::PhysicalAddress, virtual_address::VirtualAddress};

use std::collections::BTreeMap;

/// The kind of task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    /// A kernel thread (mm == NULL).
    Kthread,

    /// The leader of a thread group (mm != NULL && tgid == pid).
    ThreadGroupLeader,

    /// A non-leader thread in a thread group (mm != NULL && tgid != pid).
    Thread,
}

/// Represents a task in the kernel.
#[derive(Debug, Clone)]
pub struct Task {
    /// The (kernel) virtual address of this task entity.
    pub virtual_address: VirtualAddress,

    /// The kind of task (kthread, thread group leader, or thread).
    pub kind: TaskKind,

    /// The physical of the page table associated with this task.
    pub page_table: PhysicalAddress,

    /// The binary path.
    pub binary_path: Option<String>,

    /// The name of the task.
    pub name: Option<String>,

    /// The command line of the task.
    pub command_line: Option<String>,

    /// The environment variables of the task.
    pub environment_variable_map: BTreeMap<String, String>,

    /// The thread group identifier (task_struct::tgid)
    pub tgid: u32,

    /// The parent thread group identifier (task_struct::parent::tgid)
    pub ppid: Option<u32>,

    /// The real parent thread group identifier (task_struct::real_parent::tgid)
    pub real_ppid: Option<u32>,

    /// The thread identifier (task_struct::pid)
    pub pid: u32,

    /// The user identifier of the task.
    pub uid: u32,

    /// The group identifier of the task.
    pub gid: u32,
}
