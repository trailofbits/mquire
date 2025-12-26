//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

/// Represents a kernel module parameter from `struct kernel_param`
#[derive(Debug, Clone)]
pub struct KernelModuleParam {
    /// Virtual address of this object
    pub virtual_address: VirtualAddress,

    /// Parameter name
    pub name: Option<String>,

    /// Parameter permissions
    pub permissions: Option<u16>,

    /// Parameter flags
    pub flags: Option<u8>,
}

/// Represents the state of a kernel module
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelModuleState {
    /// Module is fully loaded and active
    Live,

    /// Module is being loaded
    Coming,

    /// Module is being unloaded
    Going,

    /// Module structure exists but init hasn't been called
    Unformed,
}

/// Represents a Linux kernel module from `struct module`
#[derive(Debug, Clone)]
pub struct KernelModule {
    /// Virtual address of this object
    pub virtual_address: VirtualAddress,

    /// Module name
    pub name: Option<String>,

    /// Module version string
    pub version: Option<String>,

    /// Source version string
    pub src_version: Option<String>,

    /// Module taint flags
    pub taints: Option<u64>,

    /// Whether the module uses GPL-only symbols
    pub using_gpl_only_symbols: Option<bool>,

    /// Current state of the module
    pub state: Option<KernelModuleState>,

    /// List of module parameters
    pub parameter_list: Vec<KernelModuleParam>,
}
