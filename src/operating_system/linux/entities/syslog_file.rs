//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{primitives::PhysicalAddress, virtual_address::VirtualAddress};

use std::ops::Range;

/// Represents the source of syslog file data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogFileDataSource {
    /// Data read from the kernel page cache
    PageCache,
    /// Data read from a process memory mapping
    MemoryMapping,
}

impl SyslogFileDataSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyslogFileDataSource::PageCache => "page_cache",
            SyslogFileDataSource::MemoryMapping => "memory_mapping",
        }
    }
}

/// Represents a syslog file region in memory
pub struct SyslogFileRegion {
    /// The file offset range for the syslog region
    pub offset_range: Range<PhysicalAddress>,

    /// The extracted valid text lines from this region
    pub lines: Vec<String>,
}

/// Represents the /var/log/syslog file data available in memory
pub struct SyslogFile {
    /// The virtual address for the file entity
    pub virtual_address: VirtualAddress,

    /// The virtual address of the task_struct
    pub task: VirtualAddress,

    /// The process iD
    pub pid: u32,

    /// The source of this syslog data
    pub data_source: SyslogFileDataSource,

    /// The available syslog regions
    pub region_list: Vec<SyslogFileRegion>,
}
