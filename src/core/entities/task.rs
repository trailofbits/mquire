//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{primitives::PhysicalAddress, virtual_address::VirtualAddress};

use std::collections::BTreeMap;

/// Represents a task in the kernel.
#[derive(Debug, Clone)]
pub struct Task {
    /// The (kernel) virtual address of this task entity.
    pub virtual_address: VirtualAddress,

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

    /// The process identifier
    pub pid: u32,

    /// The thread identifier
    pub tid: u32,

    /// Whether this is the main thread of the process.
    pub main_thread: bool,

    /// The user identifier of the task.
    pub uid: u32,

    /// The group identifier of the task.
    pub gid: u32,
}
