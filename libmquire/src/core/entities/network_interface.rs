//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

/// IPv4 address with its associated network mask
pub struct IPv4Address {
    /// IPv4 address in dotted-decimal notation
    pub address: String,

    /// Network mask in dotted-decimal notation
    pub mask: String,
}

/// IPv6 address with its prefix length
pub struct IPv6Address {
    /// IPv6 address in standard notation
    pub address: String,

    /// Prefix length
    pub prefix_length: u32,
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

    /// List of IPv4 addresses with their masks
    pub ipv4_address_list: Vec<IPv4Address>,

    /// List of IPv6 addresses with their prefix lengths
    pub ipv6_address_list: Vec<IPv6Address>,

    /// Interface state (OS specific)
    pub state: Option<String>,
}
