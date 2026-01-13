//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

/// An open file reference held by a task.
///
/// This represents an entry in a task's file descriptor table. The underlying file
/// object (`virtual_address`) may be shared across multiple tasks via fd
/// duplication, inheritance from a parent process, or inter-process transfer.
#[derive(Debug)]
pub struct File {
    /// Kernel address of the file object. Multiple tasks may reference the
    /// same file object.
    pub virtual_address: VirtualAddress,

    /// Kernel address of the task holding this file reference.
    pub task: VirtualAddress,

    /// The file path.
    pub path: String,

    /// Thread group identifier of the task holding this file reference.
    pub tgid: u32,

    /// The file descriptor.
    pub fd: u64,

    /// The inode number, if available.
    pub inode: Option<u64>,
}
