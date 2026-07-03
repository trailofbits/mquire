//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

/// The kind of memory region a module occupies, mirroring the kernel's
/// `enum mod_mem_type` (6.4+)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelModuleMemType {
    /// Core executable text (`MOD_TEXT`)
    Text,

    /// Core writable data (`MOD_DATA`)
    Data,

    /// Core read-only data (`MOD_RODATA`)
    RoData,

    /// Core data that becomes read-only after init (`MOD_RO_AFTER_INIT`)
    RoAfterInit,

    /// Init-time executable text (`MOD_INIT_TEXT`), freed once init completes
    InitText,

    /// Init-time writable data (`MOD_INIT_DATA`), freed once init completes
    InitData,

    /// Init-time read-only data (`MOD_INIT_RODATA`), freed once init completes
    InitRoData,
}

/// A single entry of a kernel module's `mem[]` array (one contiguous range)
#[derive(Debug, Clone)]
pub struct KernelModuleMemEntry {
    /// Which kind of region this is
    pub mem_type: KernelModuleMemType,

    /// Base virtual address of the region
    pub base: VirtualAddress,

    /// Size of the region, in bytes
    pub size: u32,
}
