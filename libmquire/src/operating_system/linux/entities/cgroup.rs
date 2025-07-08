//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

pub struct Cgroup {
    /// The (kernel) virtual address of the task_struct
    pub task: VirtualAddress,

    /// The cgroup name
    pub name: String,
}
