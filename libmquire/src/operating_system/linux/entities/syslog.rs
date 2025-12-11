//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{primitives::PhysicalAddress, virtual_address::VirtualAddress};

use std::ops::Range;

/// Represents a syslog region in memory
pub struct SyslogRegion {
    /// The file offset range for the syslog region
    pub offset_range: Range<PhysicalAddress>,

    /// The syslog region content. Note that this buffer may be truncated
    /// if it was not possible to read the entire pages comprising the region.
    pub buffer: Vec<u8>,
}

pub struct Syslog {
    /// The virtual address for the file entity
    pub virtual_address: VirtualAddress,

    /// The (kernel) virtual address of the task_struct
    pub task: VirtualAddress,

    /// The process iD
    pub pid: u32,

    /// The available syslog regions
    pub region_list: Vec<SyslogRegion>,
}
