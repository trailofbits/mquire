//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

/// Boot time
pub struct BootTime {
    /// The virtual address for the uptime entity
    pub virtual_address: VirtualAddress,

    /// Boot time
    pub boot_time: u64,
}
