//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::Result,
    table_plugin::{ColumnType, ColumnValue, OptionalColumnValue, RowList, TablePlugin},
};

use mquire::operating_system::linux::operating_system::LinuxOperatingSystem;

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
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("sequence"), ColumnType::SignedInteger);
        schema.insert(String::from("timestamp_ns"), ColumnType::SignedInteger);
        schema.insert(String::from("level"), ColumnType::SignedInteger);
        schema.insert(String::from("facility"), ColumnType::SignedInteger);
        schema.insert(String::from("caller_id"), ColumnType::SignedInteger);
        schema.insert(String::from("message"), ColumnType::String);
        schema.insert(String::from("data_source"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("dmesg")
    }

    fn generate(&self) -> Result<RowList> {
        let row_list: RowList = self
            .system
            .get_dmesg_entries()?
            .into_iter()
            .map(|entry| {
                let mut row = BTreeMap::<String, OptionalColumnValue>::new();

                row.insert(
                    String::from("sequence"),
                    Some(ColumnValue::SignedInteger(entry.sequence as i64)),
                );

                row.insert(
                    String::from("timestamp_ns"),
                    Some(ColumnValue::SignedInteger(entry.timestamp_ns as i64)),
                );

                row.insert(
                    String::from("level"),
                    Some(ColumnValue::SignedInteger(entry.level as i64)),
                );

                row.insert(
                    String::from("facility"),
                    Some(ColumnValue::SignedInteger(entry.facility as i64)),
                );

                row.insert(
                    String::from("caller_id"),
                    entry
                        .caller_id
                        .map(|id| ColumnValue::SignedInteger(id as i64)),
                );

                row.insert(
                    String::from("message"),
                    Some(ColumnValue::String(entry.message)),
                );

                row.insert(
                    String::from("data_source"),
                    Some(ColumnValue::String(entry.data_source.as_str().to_string())),
                );

                row
            })
            .collect();

        Ok(row_list)
    }
}
