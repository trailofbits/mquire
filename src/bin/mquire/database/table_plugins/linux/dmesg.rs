//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::Result,
    table_plugin::{ColumnDef, ColumnType, ColumnValue, Constraints, RowList, TablePlugin},
};

use mquire::operating_system::linux::operating_system::LinuxOperatingSystem;

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that outputs kernel log messages (dmesg)
pub struct DmesgTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl DmesgTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for DmesgTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("sequence"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("timestamp_ns"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("level"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("facility"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("caller_id"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("message"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("data_source"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("dmesg")
    }

    fn generate(&self, _constraints: &Constraints) -> Result<RowList> {
        let row_list: RowList = self
            .system
            .iter_dmesg_entries()?
            .filter_map(|r| {
                r.inspect_err(|e| error!("Failed to parse dmesg entry: {e:?}"))
                    .ok()
            })
            .map(|entry| {
                BTreeMap::from([
                    (
                        String::from("sequence"),
                        Some(ColumnValue::SignedInteger(entry.sequence as i64)),
                    ),
                    (
                        String::from("timestamp_ns"),
                        Some(ColumnValue::SignedInteger(entry.timestamp_ns as i64)),
                    ),
                    (
                        String::from("level"),
                        Some(ColumnValue::SignedInteger(entry.level as i64)),
                    ),
                    (
                        String::from("facility"),
                        Some(ColumnValue::SignedInteger(entry.facility as i64)),
                    ),
                    (
                        String::from("caller_id"),
                        entry
                            .caller_id
                            .map(|id| ColumnValue::SignedInteger(id as i64)),
                    ),
                    (
                        String::from("message"),
                        Some(ColumnValue::String(entry.message)),
                    ),
                    (
                        String::from("data_source"),
                        Some(ColumnValue::String(entry.data_source.as_str().to_string())),
                    ),
                ])
            })
            .collect();

        Ok(row_list)
    }
}
