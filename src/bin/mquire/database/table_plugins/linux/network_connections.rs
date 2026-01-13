//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::{Error, Result},
    table_plugin::{ColumnDef, ColumnType, ColumnValue, Constraints, RowList, TablePlugin},
};

use mquire::{
    core::entities::ip_address::IPAddress,
    operating_system::linux::{
        entities::network_connection::{IPAddressType, Protocol},
        operating_system::LinuxOperatingSystem,
    },
};

use log::error;

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

    /// Parses the optional 'protocol' constraint into a list of Protocol values
    fn parse_protocol_filter(constraints: &Constraints) -> Result<Vec<Protocol>> {
        let constraint = constraints.iter().find(|c| c.column == "protocol");

        match constraint {
            None => Ok(vec![]),

            Some(c) => match &c.value {
                ColumnValue::String(s) => match s.to_lowercase().as_str() {
                    "tcp" => Ok(vec![Protocol::TCP]),
                    "udp" => Ok(vec![Protocol::UDP]),

                    other => Err(Error::TablePlugin(format!(
                        "Invalid protocol '{}'. Valid values: tcp, udp",
                        other
                    ))),
                },

                other => Err(Error::TablePlugin(format!(
                    "Expected string for 'protocol', got {:?}",
                    other
                ))),
            },
        }
    }
}

impl TablePlugin for NetworkConnectionsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("protocol"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("state"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("local_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("local_port"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("remote_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("remote_port"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (String::from("type"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("inode"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("network_connections")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![String::from("protocol")]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let protocol_filter = Self::parse_protocol_filter(constraints)?;

        let connection_iter = match self.system.iter_network_connections(&protocol_filter) {
            Ok(iter) => iter,

            Err(e) => {
                error!("Failed to iterate network connections: {e:?}");
                return Ok(RowList::new());
            }
        };

        let row_list: RowList = connection_iter
            .filter_map(|result| {
                result
                    .inspect_err(|e| error!("Failed to read network connection: {e:?}"))
                    .ok()
            })
            .map(|connection| {
                let string_type = connection.ip_address_type.map(|ip_type| match ip_type {
                    IPAddressType::IPv4 => "ipv4".to_string(),
                    IPAddressType::IPv6 => "ipv6".to_string(),
                });

                BTreeMap::from([
                    (
                        String::from("virtual_address"),
                        Some(ColumnValue::String(format!(
                            "{}",
                            connection.virtual_address
                        ))),
                    ),
                    (
                        String::from("protocol"),
                        connection.protocol.map(|protocol| {
                            ColumnValue::String(format!("{:?}", protocol).to_lowercase())
                        }),
                    ),
                    (
                        String::from("state"),
                        connection.state.map(ColumnValue::String),
                    ),
                    (
                        String::from("local_address"),
                        connection.local_address.as_ref().map(|local_address| {
                            ColumnValue::String(match local_address {
                                IPAddress::IPv4(addr) => addr.clone(),
                                IPAddress::IPv6(addr) => addr.clone(),
                            })
                        }),
                    ),
                    (
                        String::from("local_port"),
                        connection
                            .local_port
                            .map(|port| ColumnValue::SignedInteger(port as i64)),
                    ),
                    (
                        String::from("remote_address"),
                        connection.remote_address.as_ref().map(|remote_address| {
                            ColumnValue::String(match remote_address {
                                IPAddress::IPv4(addr) => addr.clone(),
                                IPAddress::IPv6(addr) => addr.clone(),
                            })
                        }),
                    ),
                    (
                        String::from("remote_port"),
                        connection
                            .remote_port
                            .map(|port| ColumnValue::SignedInteger(port as i64)),
                    ),
                    (String::from("type"), string_type.map(ColumnValue::String)),
                    (
                        String::from("inode"),
                        connection
                            .inode
                            .map(|inode| ColumnValue::SignedInteger(inode as i64)),
                    ),
                ])
            })
            .collect();

        Ok(row_list)
    }
}
