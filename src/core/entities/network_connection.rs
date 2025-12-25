//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{core::entities::ip_address::IPAddress, memory::virtual_address::VirtualAddress};

/// Network protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol
    TCP,
}

/// IP type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IPAddressType {
    /// IPv4 ip address type
    IPv4,

    /// IPv6 ip address type
    IPv6,
}

/// Represents a network connection
#[derive(Debug, Clone)]
pub struct NetworkConnection {
    /// Virtual address of the sock structure
    pub virtual_address: VirtualAddress,

    /// Protocol type
    pub protocol: Option<Protocol>,

    /// TCP connection state (operating system specific)
    pub state: Option<String>,

    /// Local IP address
    pub local_address: Option<IPAddress>,

    /// Local port number
    pub local_port: Option<u16>,

    /// Remote IP address
    pub remote_address: Option<IPAddress>,

    /// Remote port number
    pub remote_port: Option<u16>,

    /// IP address type
    pub ip_address_type: Option<IPAddressType>,

    /// Socket inode number
    pub inode: Option<u64>,
}
