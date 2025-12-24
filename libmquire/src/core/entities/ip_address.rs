//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

/// IP address
#[derive(Debug, Clone)]
pub enum IPAddress {
    /// IPv4 address
    IPv4(String),

    /// IPv6 address
    IPv6(String),
}
