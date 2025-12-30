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

use mquire::operating_system::linux::{
    entities::network_connection::IPAddressType, operating_system::LinuxOperatingSystem,
};

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that lists network connections
pub struct NetworkConnectionsTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl NetworkConnectionsTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for NetworkConnectionsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::new();
        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("protocol"), ColumnType::String);
        schema.insert(String::from("state"), ColumnType::String);
        schema.insert(String::from("local_address"), ColumnType::String);
        schema.insert(String::from("local_port"), ColumnType::SignedInteger);
        schema.insert(String::from("remote_address"), ColumnType::String);
        schema.insert(String::from("remote_port"), ColumnType::SignedInteger);
        schema.insert(String::from("type"), ColumnType::String);
        schema.insert(String::from("inode"), ColumnType::SignedInteger);
        schema
    }

    fn name(&self) -> String {
        String::from("network_connections")
    }

    fn generate(&self) -> Result<RowList> {
        let connection_list = match self.system.get_network_connection_list() {
            Ok(connection_list) => connection_list,
            Err(_) => return Ok(RowList::new()),
        };

        let row_list: RowList = connection_list
            .into_iter()
            .map(|connection| {
                let mut row = Row::new();

                row.insert(
                    String::from("virtual_address"),
                    Some(ColumnValue::String(format!(
                        "{:?}",
                        connection.virtual_address
                    ))),
                );

                row.insert(
                    String::from("protocol"),
                    connection.protocol.map(|protocol| {
                        ColumnValue::String(format!("{:?}", protocol).to_lowercase())
                    }),
                );

                row.insert(
                    String::from("state"),
                    connection.state.map(ColumnValue::String),
                );

                row.insert(
                    String::from("local_address"),
                    connection.local_address.as_ref().map(|local_address| {
                        ColumnValue::String(match local_address {
                            mquire::core::entities::ip_address::IPAddress::IPv4(addr) => {
                                addr.clone()
                            }
                            mquire::core::entities::ip_address::IPAddress::IPv6(addr) => {
                                addr.clone()
                            }
                        })
                    }),
                );

                row.insert(
                    String::from("local_port"),
                    connection
                        .local_port
                        .map(|port| ColumnValue::SignedInteger(port as i64)),
                );

                row.insert(
                    String::from("remote_address"),
                    connection.remote_address.as_ref().map(|remote_address| {
                        ColumnValue::String(match remote_address {
                            mquire::core::entities::ip_address::IPAddress::IPv4(addr) => {
                                addr.clone()
                            }
                            mquire::core::entities::ip_address::IPAddress::IPv6(addr) => {
                                addr.clone()
                            }
                        })
                    }),
                );

                row.insert(
                    String::from("remote_port"),
                    connection
                        .remote_port
                        .map(|port| ColumnValue::SignedInteger(port as i64)),
                );

                let string_type = connection.ip_address_type.map(|ip_type| match ip_type {
                    IPAddressType::IPv4 => "ipv4".to_string(),
                    IPAddressType::IPv6 => "ipv6".to_string(),
                });

                row.insert(String::from("type"), string_type.map(ColumnValue::String));

                row.insert(
                    String::from("inode"),
                    connection
                        .inode
                        .map(|inode| ColumnValue::SignedInteger(inode as i64)),
                );

                row
            })
            .collect();

        Ok(row_list)
    }
}
