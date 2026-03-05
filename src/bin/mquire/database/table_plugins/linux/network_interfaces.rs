//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::{Error, Result},
    table_plugin::{
        ColumnDef, ColumnType, ColumnValue, Constraints, OptionalColumnValue, RowList, TablePlugin,
    },
};

use mquire::{
    core::entities::{
        ip_address::IPAddress,
        network_interface::{NetworkInterface, NetworkMask},
    },
    memory::virtual_address::VirtualAddress,
    operating_system::linux::operating_system::LinuxOperatingSystem,
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that lists network interfaces
pub struct NetworkInterfacesTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl NetworkInterfacesTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }

    /// Attempts to parse a constraint value as a VirtualAddress, returning an error if parsing fails
    fn parse_constraint_address(
        constraints: &Constraints,
        column_name: &str,
    ) -> Result<Option<VirtualAddress>> {
        let constraint = constraints.iter().find(|c| c.column == column_name);

        match constraint {
            None => Ok(None),

            Some(c) => match &c.value {
                ColumnValue::String(s) => match s.parse() {
                    Ok(addr) => Ok(Some(addr)),

                    Err(_) => Err(Error::TablePlugin(format!(
                        "Invalid VirtualAddress format for '{}': {}",
                        column_name, s
                    ))),
                },

                other => Err(Error::TablePlugin(format!(
                    "Expected string for '{}', got {:?}",
                    column_name, other
                ))),
            },
        }
    }

    /// Generates a row from a network interface
    fn generate_row_from_interface(
        interface: &NetworkInterface,
        list_head: Option<&str>,
    ) -> BTreeMap<String, OptionalColumnValue> {
        BTreeMap::from([
            (
                String::from("name"),
                interface.name.clone().map(ColumnValue::String),
            ),
            (
                String::from("virtual_address"),
                Some(ColumnValue::String(format!(
                    "{}",
                    interface.virtual_address
                ))),
            ),
            (
                String::from("list_head"),
                list_head.map(|s| ColumnValue::String(s.to_string())),
            ),
            (
                String::from("active_mac_address"),
                interface
                    .active_mac_address
                    .clone()
                    .map(ColumnValue::String),
            ),
            (
                String::from("physical_mac_address"),
                interface
                    .physical_mac_address
                    .clone()
                    .map(ColumnValue::String),
            ),
            (
                String::from("state"),
                interface.state.clone().map(ColumnValue::String),
            ),
            (String::from("ip_type"), None),
            (String::from("ip_address"), None),
            (String::from("mask"), None),
            (String::from("additional_mac_address"), None),
        ])
    }

    /// Generates a single row for a direct interface lookup
    fn generate_single_interface_row(
        system: &LinuxOperatingSystem,
        vaddr: VirtualAddress,
    ) -> Result<RowList> {
        let interface = system.network_interface_at(vaddr).map_err(|e| {
            Error::TablePlugin(format!(
                "Failed to get network interface at {}: {:?}",
                vaddr, e
            ))
        })?;

        Self::expand_interface_to_rows(&interface, None)
    }

    /// Generates rows by enumerating interfaces from a list head
    fn generate_enumerated_rows(
        system: &LinuxOperatingSystem,
        list_head: Option<VirtualAddress>,
    ) -> Result<RowList> {
        let iter = match list_head {
            Some(list_head_vaddr) => system.iter_network_interfaces_from(list_head_vaddr),
            None => system.iter_network_interfaces(),
        }
        .map_err(|e| {
            Error::TablePlugin(format!("Failed to iterate network interfaces: {:?}", e))
        })?;

        let list_head_str = format!("{}", iter.list_head());
        let mut row_list = RowList::new();

        for interface_result in iter {
            match interface_result {
                Ok(interface) => {
                    let mut rows =
                        Self::expand_interface_to_rows(&interface, Some(&list_head_str))?;
                    row_list.append(&mut rows);
                }

                Err(error) => {
                    error!("Failed to parse network interface: {error:?}");
                }
            }
        }

        Ok(row_list)
    }

    /// Expands a single interface into multiple rows (for IP addresses and additional MACs)
    fn expand_interface_to_rows(
        interface: &NetworkInterface,
        list_head: Option<&str>,
    ) -> Result<RowList> {
        let base_row = Self::generate_row_from_interface(interface, list_head);

        // Expand the base row to include the additional mac addresses
        let base_row_list: RowList = if interface.additional_mac_addresses.is_empty() {
            vec![base_row]
        } else {
            interface
                .additional_mac_addresses
                .iter()
                .map(|mac_address| {
                    let mut row = base_row.clone();

                    row.insert(
                        String::from("additional_mac_address"),
                        Some(ColumnValue::String(mac_address.clone())),
                    );

                    row
                })
                .collect()
        };

        // Expand the base row list to include the IP addresses
        let row_list = if interface.ip_addresses.is_empty() {
            base_row_list
        } else {
            interface
                .ip_addresses
                .iter()
                .flat_map(|ip_addr_and_mask| {
                    base_row_list.iter().map(|base_row| {
                        let mut ip_address_row = base_row.clone();

                        let (ip_type, ip_address) = match &ip_addr_and_mask.ip_address {
                            IPAddress::IPv4(addr) => ("ipv4", addr.clone()),
                            IPAddress::IPv6(addr) => ("ipv6", addr.clone()),
                        };

                        ip_address_row.insert(
                            String::from("ip_type"),
                            Some(ColumnValue::String(String::from(ip_type))),
                        );

                        ip_address_row.insert(
                            String::from("ip_address"),
                            Some(ColumnValue::String(ip_address)),
                        );

                        let mask_str = match &ip_addr_and_mask.mask {
                            NetworkMask::DottedDecimal(s) => s.clone(),
                            NetworkMask::PrefixLength(len) => len.to_string(),
                        };

                        ip_address_row
                            .insert(String::from("mask"), Some(ColumnValue::String(mask_str)));

                        ip_address_row
                    })
                })
                .collect()
        };

        Ok(row_list)
    }

    #[cfg(test)]
    fn generate_rows(
        interface_list: Vec<NetworkInterface>,
        list_head: Option<&str>,
    ) -> Result<RowList> {
        let mut row_list = RowList::new();

        for interface in interface_list {
            let mut rows = Self::expand_interface_to_rows(&interface, list_head)?;
            row_list.append(&mut rows);
        }

        Ok(row_list)
    }
}

impl TablePlugin for NetworkInterfacesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("list_head"),
                ColumnDef::hidden(ColumnType::String),
            ),
            (String::from("name"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("active_mac_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("physical_mac_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("additional_mac_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("ip_type"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("ip_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (String::from("mask"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("state"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("network_interfaces")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![String::from("virtual_address"), String::from("list_head")]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let virtual_address = Self::parse_constraint_address(constraints, "virtual_address")?;
        let list_head = Self::parse_constraint_address(constraints, "list_head")?;

        match (virtual_address, list_head) {
            (Some(vaddr), None) => {
                Self::generate_single_interface_row(self.system.as_ref(), vaddr)
            }

            (None, Some(list_head_vaddr)) => {
                Self::generate_enumerated_rows(self.system.as_ref(), Some(list_head_vaddr))
            }

            (None, None) => Self::generate_enumerated_rows(self.system.as_ref(), None),

            (Some(_), Some(_)) => Err(Error::TablePlugin(
                "Cannot specify both 'virtual_address' and 'list_head' constraints together. \
                 Use 'virtual_address' to query a single interface, or 'list_head' to enumerate from a custom list head."
                    .to_string(),
            )),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use crate::sqlite::table_plugin::Row;

    use mquire::{
        core::entities::{
            ip_address::IPAddress,
            network_interface::{IPAddressAndMask, NetworkMask},
        },
        memory::{
            primitives::{PhysicalAddress, RawVirtualAddress},
            virtual_address::VirtualAddress,
        },
    };

    /// Helper function to create a mock NetworkInterface with customizable fields
    fn create_mock_interface(
        name: &str,
        additional_mac_addresses: Vec<String>,
        ipv4_addresses: Vec<(&str, &str)>,
        ipv6_addresses: Vec<(&str, u32)>,
    ) -> NetworkInterface {
        let mut ip_addresses = Vec::new();

        // Add IPv4 addresses
        for (addr, mask) in ipv4_addresses {
            ip_addresses.push(IPAddressAndMask {
                ip_address: IPAddress::IPv4(String::from(addr)),
                mask: NetworkMask::DottedDecimal(String::from(mask)),
            });
        }

        // Add IPv6 addresses
        for (addr, prefix) in ipv6_addresses {
            ip_addresses.push(IPAddressAndMask {
                ip_address: IPAddress::IPv6(String::from(addr)),
                mask: NetworkMask::PrefixLength(prefix as usize),
            });
        }

        NetworkInterface {
            virtual_address: VirtualAddress::new(
                PhysicalAddress::new(0x1000),
                RawVirtualAddress::new(0x2000),
            ),
            name: Some(String::from(name)),
            active_mac_address: Some(String::from("aa:bb:cc:dd:ee:ff")),
            physical_mac_address: Some(String::from("aa:bb:cc:dd:ee:00")),
            additional_mac_addresses,
            ip_addresses,
            state: Some(String::from("up")),
        }
    }

    /// Helper function to get a specific column value from a row
    fn get_column_value(row: &Row, column: &str) -> Option<String> {
        row.get(column).and_then(|v| match v {
            Some(ColumnValue::String(s)) => Some(s.clone()),
            _ => None,
        })
    }

    #[test]
    fn test_single_interface_no_expansion() {
        // Interface with no additional MAC addresses and no IP addresses
        let interfaces = vec![create_mock_interface("eth0", vec![], vec![], vec![])];

        // Should produce exactly 1 row
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 1);

        assert_eq!(get_column_value(&result[0], "name").unwrap(), "eth0");
        assert!(get_column_value(&result[0], "additional_mac_address").is_none());
        assert!(get_column_value(&result[0], "ip_type").is_none());
        assert!(get_column_value(&result[0], "ip_address").is_none());
        assert!(get_column_value(&result[0], "mask").is_none());
    }

    #[test]
    fn test_interface_with_additional_mac_addresses_only() {
        // Interface with 3 additional MAC addresses but no IP addresses
        let interfaces = vec![create_mock_interface(
            "eth0",
            vec![
                String::from("11:22:33:44:55:66"),
                String::from("77:88:99:aa:bb:cc"),
                String::from("dd:ee:ff:00:11:22"),
            ],
            vec![],
            vec![],
        )];

        // Should produce 3 rows (one per additional MAC)
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 3);

        for row in &result {
            assert_eq!(get_column_value(row, "name").unwrap(), "eth0");
            assert!(get_column_value(row, "ip_type").is_none());
        }

        assert_eq!(
            get_column_value(&result[0], "additional_mac_address").unwrap(),
            "11:22:33:44:55:66"
        );

        assert_eq!(
            get_column_value(&result[1], "additional_mac_address").unwrap(),
            "77:88:99:aa:bb:cc"
        );

        assert_eq!(
            get_column_value(&result[2], "additional_mac_address").unwrap(),
            "dd:ee:ff:00:11:22"
        );
    }

    #[test]
    fn test_interface_with_ipv4_addresses_only() {
        // Interface with 2 IPv4 addresses but no additional MAC addresses
        let interfaces = vec![create_mock_interface(
            "eth0",
            vec![],
            vec![("192.168.1.10", "255.255.255.0"), ("10.0.0.5", "255.0.0.0")],
            vec![],
        )];

        // Should produce 2 rows (one per IPv4)
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 2);

        for row in &result {
            assert_eq!(get_column_value(row, "name").unwrap(), "eth0");
            assert_eq!(get_column_value(row, "ip_type").unwrap(), "ipv4");
        }

        assert_eq!(
            get_column_value(&result[0], "ip_address").unwrap(),
            "192.168.1.10"
        );

        assert_eq!(
            get_column_value(&result[0], "mask").unwrap(),
            "255.255.255.0"
        );

        assert_eq!(
            get_column_value(&result[1], "ip_address").unwrap(),
            "10.0.0.5"
        );
        assert_eq!(get_column_value(&result[1], "mask").unwrap(), "255.0.0.0");
    }

    #[test]
    fn test_interface_with_ipv6_addresses_only() {
        // Interface with 2 IPv6 addresses but no additional MAC addresses
        let interfaces = vec![create_mock_interface(
            "eth0",
            vec![],
            vec![],
            vec![("fe80::1", 64), ("2001:db8::1", 128)],
        )];

        // Should produce 2 rows (one per IPv6)
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 2);

        for row in &result {
            assert_eq!(get_column_value(row, "name").unwrap(), "eth0");
            assert_eq!(get_column_value(row, "ip_type").unwrap(), "ipv6");
        }

        assert_eq!(
            get_column_value(&result[0], "ip_address").unwrap(),
            "fe80::1"
        );

        assert_eq!(get_column_value(&result[0], "mask").unwrap(), "64");

        assert_eq!(
            get_column_value(&result[1], "ip_address").unwrap(),
            "2001:db8::1"
        );

        assert_eq!(get_column_value(&result[1], "mask").unwrap(), "128");
    }

    #[test]
    fn test_interface_with_both_ipv4_and_ipv6() {
        // Interface with 2 IPv4 and 2 IPv6 addresses
        let interfaces = vec![create_mock_interface(
            "eth0",
            vec![],
            vec![("192.168.1.10", "255.255.255.0"), ("10.0.0.5", "255.0.0.0")],
            vec![("fe80::1", 64), ("2001:db8::1", 128)],
        )];

        // Should produce 4 rows (2 + 2)
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 4);

        // First 2 rows should be IPv4
        for row in &result[0..2] {
            assert_eq!(get_column_value(row, "ip_type").unwrap(), "ipv4");
        }

        // Last 2 rows should be IPv6
        for row in &result[2..4] {
            assert_eq!(get_column_value(row, "ip_type").unwrap(), "ipv6");
        }
    }

    #[test]
    fn test_interface_with_mac_and_ipv4_cartesian_product() {
        // Interface with 2 additional MAC addresses and 2 IPv4 addresses
        let interfaces = vec![create_mock_interface(
            "eth0",
            vec![
                String::from("11:22:33:44:55:66"),
                String::from("77:88:99:aa:bb:cc"),
            ],
            vec![("192.168.1.10", "255.255.255.0"), ("10.0.0.5", "255.0.0.0")],
            vec![],
        )];

        // Should produce 4 rows (2 * 2 cartesian product)
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 4);

        // All rows should have IPv4 type
        for row in &result {
            assert_eq!(get_column_value(row, "ip_type").unwrap(), "ipv4");
        }

        // Check cartesian product: each IP should appear with each MAC
        assert_eq!(
            get_column_value(&result[0], "additional_mac_address").unwrap(),
            "11:22:33:44:55:66"
        );

        assert_eq!(
            get_column_value(&result[0], "ip_address").unwrap(),
            "192.168.1.10"
        );

        assert_eq!(
            get_column_value(&result[1], "additional_mac_address").unwrap(),
            "77:88:99:aa:bb:cc"
        );

        assert_eq!(
            get_column_value(&result[1], "ip_address").unwrap(),
            "192.168.1.10"
        );

        assert_eq!(
            get_column_value(&result[2], "additional_mac_address").unwrap(),
            "11:22:33:44:55:66"
        );

        assert_eq!(
            get_column_value(&result[2], "ip_address").unwrap(),
            "10.0.0.5"
        );

        assert_eq!(
            get_column_value(&result[3], "additional_mac_address").unwrap(),
            "77:88:99:aa:bb:cc"
        );

        assert_eq!(
            get_column_value(&result[3], "ip_address").unwrap(),
            "10.0.0.5"
        );
    }

    #[test]
    fn test_interface_with_mac_ipv4_and_ipv6_full_expansion() {
        // Interface with 2 additional MAC, 1 IPv4, and 1 IPv6
        let interfaces = vec![create_mock_interface(
            "eth0",
            vec![
                String::from("11:22:33:44:55:66"),
                String::from("77:88:99:aa:bb:cc"),
            ],
            vec![("192.168.1.10", "255.255.255.0")],
            vec![("fe80::1", 64)],
        )];

        // Should produce 4 rows: 2 MAC * (1 IPv4 + 1 IPv6) = 2 * 2 = 4
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 4);

        // First 2 rows should be IPv4 with both MACs
        assert_eq!(get_column_value(&result[0], "ip_type").unwrap(), "ipv4");
        assert_eq!(
            get_column_value(&result[0], "additional_mac_address").unwrap(),
            "11:22:33:44:55:66"
        );

        assert_eq!(get_column_value(&result[1], "ip_type").unwrap(), "ipv4");
        assert_eq!(
            get_column_value(&result[1], "additional_mac_address").unwrap(),
            "77:88:99:aa:bb:cc"
        );

        // Last 2 rows should be IPv6 with both MACs
        assert_eq!(get_column_value(&result[2], "ip_type").unwrap(), "ipv6");
        assert_eq!(
            get_column_value(&result[2], "additional_mac_address").unwrap(),
            "11:22:33:44:55:66"
        );

        assert_eq!(get_column_value(&result[3], "ip_type").unwrap(), "ipv6");
        assert_eq!(
            get_column_value(&result[3], "additional_mac_address").unwrap(),
            "77:88:99:aa:bb:cc"
        );
    }

    #[test]
    fn test_multiple_interfaces() {
        // Two interfaces with different configurations
        let interfaces = vec![
            create_mock_interface(
                "eth0",
                vec![],
                vec![("192.168.1.10", "255.255.255.0")],
                vec![],
            ),
            create_mock_interface(
                "eth1",
                vec![String::from("11:22:33:44:55:66")],
                vec![],
                vec![("fe80::1", 64)],
            ),
        ];

        // Should produce 2 rows:
        //  - eth0: 1 IPv4 = 1 row
        //  - eth1: 1 MAC * 1 IPv6 = 1 row
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 2);

        // First row is from eth0
        assert_eq!(get_column_value(&result[0], "name").unwrap(), "eth0");
        assert_eq!(get_column_value(&result[0], "ip_type").unwrap(), "ipv4");

        // Second row is from eth1
        assert_eq!(get_column_value(&result[1], "name").unwrap(), "eth1");
        assert_eq!(get_column_value(&result[1], "ip_type").unwrap(), "ipv6");
    }

    #[test]
    fn test_empty_interface_list() {
        let interfaces = vec![];

        // Empty interface list should produce empty result
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces, None).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_interface_with_none_fields() {
        // Interface with None values for optional fields
        let interface = NetworkInterface {
            virtual_address: VirtualAddress::new(
                PhysicalAddress::new(0x1000),
                RawVirtualAddress::new(0x2000),
            ),
            name: None,
            active_mac_address: None,
            physical_mac_address: None,
            additional_mac_addresses: vec![],
            ip_addresses: vec![],
            state: None,
        };

        let result = NetworkInterfacesTablePlugin::generate_rows(vec![interface], None).unwrap();

        // Should produce one row, with just the virtual address
        assert_eq!(result.len(), 1);
        assert!(get_column_value(&result[0], "name").is_none());
        assert!(get_column_value(&result[0], "active_mac_address").is_none());
        assert!(get_column_value(&result[0], "physical_mac_address").is_none());
        assert!(get_column_value(&result[0], "state").is_none());
    }
}
