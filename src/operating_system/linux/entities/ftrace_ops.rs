//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

/// An `ftrace_ops` object
#[derive(Debug, Clone)]
pub struct FtraceOps {
    /// Virtual address of the `struct ftrace_ops`
    pub virtual_address: VirtualAddress,

    /// The callback the kernel invokes for this ops (`ops->func`)
    pub func: Option<VirtualAddress>,

    /// The `ops->flags` value
    pub flags: Option<u64>,
}
