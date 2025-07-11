//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

/// Represents the operating system version information.
pub struct SystemVersion {
    /// System version.
    pub system_version: Option<String>,

    /// Kernel version.
    pub kernel_version: Option<String>,

    /// Kernel architecture.
    pub arch: Option<String>,
}
