//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

use std::{ops::Range, path::PathBuf};

/// Represents memory protection flags for a memory mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryProtection {
    /// Creates a new MemoryProtection object
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }
}

/// Information about a file backing a memory mapping
#[derive(Debug, Clone)]
pub struct FileBacking {
    /// The file path
    pub path: PathBuf,

    /// File offset in pages (vm_pgoff)
    pub offset: u64,
}

/// A memory mapping entity
#[derive(Debug, Clone)]
pub struct MemoryMapping {
    /// The kernel virtual address of the vm_area_struct
    pub virtual_address: VirtualAddress,

    /// The kernel virtual address of the task_struct
    pub task: VirtualAddress,

    /// The memory region mapped for the process
    pub region: Range<VirtualAddress>,

    /// The memory protection flags (e.g., read, write, execute)
    pub protection: MemoryProtection,

    /// True if this mapping is shared
    pub shared: bool,

    /// File backing information (only present for file-backed mappings)
    pub file_backing: Option<FileBacking>,
}
