//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

/// Represents a file in memory.
#[derive(Debug)]
pub struct File {
    /// The (kernel) virtual address of this file entity.
    pub virtual_address: VirtualAddress,

    /// That task virtual address
    pub task: VirtualAddress,

    /// The file path.
    pub path: String,

    /// The task pid.
    pub pid: u32,

    /// The inode number
    pub inode: Option<u64>,
}
