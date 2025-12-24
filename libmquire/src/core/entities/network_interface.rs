//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{core::entities::ip_address::IPAddress, memory::virtual_address::VirtualAddress};

/// Network mask representation
#[derive(Debug, Clone)]
pub enum NetworkMask {
    /// IPv4 dotted-decimal notation (example: "255.255.255.0")
    DottedDecimal(String),

    /// IPv6 prefix length (example: 64)
    PrefixLength(usize),
}

/// IP address with its associated network mask
#[derive(Debug, Clone)]
pub struct IPAddressAndMask {
    /// IP address
    pub ip_address: IPAddress,

    /// Network mask (dotted-decimal notation for IPv4, prefix length for IPv6)
    pub mask: NetworkMask,
}

/// Network interface entity
pub struct NetworkInterface {
    /// Virtual address of the net_device structure
    pub virtual_address: VirtualAddress,

    /// Interface name
    pub name: Option<String>,

    /// Current active MAC address
    pub active_mac_address: Option<String>,

    /// Physical MAC address
    pub physical_mac_address: Option<String>,

    /// Additional MAC addresses
    pub additional_mac_addresses: Vec<String>,

    /// List of IP addresses with their masks
    pub ip_addresses: Vec<IPAddressAndMask>,

    /// Interface state (OS specific)
    pub state: Option<String>,
}
