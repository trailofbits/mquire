//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::Result,
    table_plugin::{ColumnType, ColumnValue, Row, RowList, TablePlugin},
};

use mquire::{
    core::{entities::network_interface::NetworkInterface, operating_system::OperatingSystem},
    operating_system::linux::operating_system::LinuxOperatingSystem,
};

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

    fn generate_rows(interface_list: Vec<NetworkInterface>) -> Result<RowList> {
        let mut row_list = RowList::new();

        for interface in interface_list {
            // Create an initial base row
            let mut base_row = Row::new();
            base_row.insert(
                String::from("name"),
                interface.name.clone().map(ColumnValue::String),
            );

            base_row.insert(
                String::from("virtual_address"),
                Some(ColumnValue::String(format!(
                    "{:?}",
                    interface.virtual_address
                ))),
            );

            base_row.insert(
                String::from("active_mac_address"),
                interface
                    .active_mac_address
                    .clone()
                    .map(ColumnValue::String),
            );

            base_row.insert(
                String::from("physical_mac_address"),
                interface
                    .physical_mac_address
                    .clone()
                    .map(ColumnValue::String),
            );

            base_row.insert(
                String::from("state"),
                interface.state.clone().map(ColumnValue::String),
            );

            base_row.insert(String::from("ip_type"), None);
            base_row.insert(String::from("ip_address"), None);
            base_row.insert(String::from("mask"), None);
            base_row.insert(String::from("additional_mac_address"), None);

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

            // Expand the base row list to include the IPv4 addresses
            let ipv4_row_list: RowList = interface
                .ipv4_address_list
                .iter()
                .flat_map(|ip_address| {
                    base_row_list.iter().map(|base_row| {
                        let mut ip_address_row = base_row.clone();

                        ip_address_row.insert(
                            String::from("ip_type"),
                            Some(ColumnValue::String(String::from("ipv4"))),
                        );

                        ip_address_row.insert(
                            String::from("ip_address"),
                            Some(ColumnValue::String(ip_address.address.clone())),
                        );

                        ip_address_row.insert(
                            String::from("mask"),
                            Some(ColumnValue::String(ip_address.mask.clone())),
                        );

                        ip_address_row
                    })
                })
                .collect();

            // Expand the base row list to include the IPv6 addresses
            let ipv6_row_list: RowList = interface
                .ipv6_address_list
                .iter()
                .flat_map(|ip_address| {
                    base_row_list.iter().map(|base_row| {
                        let mut ip_address_row = base_row.clone();

                        ip_address_row.insert(
                            String::from("ip_type"),
                            Some(ColumnValue::String(String::from("ipv6"))),
                        );

                        ip_address_row.insert(
                            String::from("ip_address"),
                            Some(ColumnValue::String(ip_address.address.clone())),
                        );

                        ip_address_row.insert(
                            String::from("mask"),
                            Some(ColumnValue::String(ip_address.prefix_length.to_string())),
                        );

                        ip_address_row
                    })
                })
                .collect();

            let mut current_interface_row_list = if interface.ipv4_address_list.is_empty()
                && interface.ipv6_address_list.is_empty()
            {
                base_row_list
            } else {
                let mut row_list = ipv4_row_list;

                let mut additional_row_list = ipv6_row_list;
                row_list.append(&mut additional_row_list);

                row_list
            };

            row_list.append(&mut current_interface_row_list);
        }

        Ok(row_list)
    }
}

impl TablePlugin for NetworkInterfacesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("name"), ColumnType::String);
        schema.insert(String::from("active_mac_address"), ColumnType::String);
        schema.insert(String::from("physical_mac_address"), ColumnType::String);
        schema.insert(String::from("additional_mac_address"), ColumnType::String);
        schema.insert(String::from("ip_type"), ColumnType::String);
        schema.insert(String::from("ip_address"), ColumnType::String);
        schema.insert(String::from("mask"), ColumnType::String);
        schema.insert(String::from("state"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("network_interfaces")
    }

    fn generate(&self) -> Result<RowList> {
        Self::generate_rows(self.system.get_network_interface_list()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mquire::{
        core::entities::network_interface::{IPv4Address, IPv6Address},
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
        NetworkInterface {
            virtual_address: VirtualAddress::new(
                PhysicalAddress::new(0x1000),
                RawVirtualAddress::new(0x2000),
            ),
            name: Some(String::from(name)),
            active_mac_address: Some(String::from("aa:bb:cc:dd:ee:ff")),
            physical_mac_address: Some(String::from("aa:bb:cc:dd:ee:00")),
            additional_mac_addresses,
            ipv4_address_list: ipv4_addresses
                .into_iter()
                .map(|(addr, mask)| IPv4Address {
                    address: String::from(addr),
                    mask: String::from(mask),
                })
                .collect(),
            ipv6_address_list: ipv6_addresses
                .into_iter()
                .map(|(addr, prefix)| IPv6Address {
                    address: String::from(addr),
                    prefix_length: prefix,
                })
                .collect(),
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
        let result = NetworkInterfacesTablePlugin::generate_rows(interfaces).unwrap();
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
            ipv4_address_list: vec![],
            ipv6_address_list: vec![],
            state: None,
        };

        let result = NetworkInterfacesTablePlugin::generate_rows(vec![interface]).unwrap();

        // Should produce one row, with just the virtual address
        assert_eq!(result.len(), 1);
        assert!(get_column_value(&result[0], "name").is_none());
        assert!(get_column_value(&result[0], "active_mac_address").is_none());
        assert!(get_column_value(&result[0], "physical_mac_address").is_none());
        assert!(get_column_value(&result[0], "state").is_none());
    }
}
