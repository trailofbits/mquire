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

/// A table plugin thats list task memory mappings
pub struct MemoryMappingsTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl MemoryMappingsTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for MemoryMappingsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("task"), ColumnType::String);
        schema.insert(String::from("region_start"), ColumnType::String);
        schema.insert(String::from("region_end"), ColumnType::String);
        schema.insert(String::from("protection"), ColumnType::String);
        schema.insert(String::from("shared"), ColumnType::String);
        schema.insert(String::from("file_path"), ColumnType::String);
        schema.insert(String::from("file_offset"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("memory_mappings")
    }

    fn generate(&self) -> Result<RowList> {
        let mut row_list = RowList::new();

        for memory_mapping in self.system.get_task_memory_mappings()? {
            let mut row = BTreeMap::<String, OptionalColumnValue>::new();

            row.insert(
                String::from("virtual_address"),
                Some(ColumnValue::String(format!(
                    "{:?}",
                    memory_mapping.virtual_address
                ))),
            );

            row.insert(
                String::from("task"),
                Some(ColumnValue::String(format!("{:?}", memory_mapping.task))),
            );

            row.insert(
                String::from("region_start"),
                Some(ColumnValue::String(format!(
                    "{:?}",
                    memory_mapping.region.start
                ))),
            );

            row.insert(
                String::from("region_end"),
                Some(ColumnValue::String(format!(
                    "{:?}",
                    memory_mapping.region.end
                ))),
            );

            let protection_str = format!(
                "{}{}{}",
                if memory_mapping.protection.read {
                    "r"
                } else {
                    "-"
                },
                if memory_mapping.protection.write {
                    "w"
                } else {
                    "-"
                },
                if memory_mapping.protection.execute {
                    "x"
                } else {
                    "-"
                }
            );

            row.insert(
                String::from("protection"),
                Some(ColumnValue::String(protection_str)),
            );

            row.insert(
                String::from("shared"),
                Some(ColumnValue::String(if memory_mapping.shared {
                    String::from("true")
                } else {
                    String::from("false")
                })),
            );

            row.insert(
                String::from("file_path"),
                memory_mapping
                    .file_backing
                    .as_ref()
                    .map(|fb| ColumnValue::String(fb.path.to_string_lossy().to_string())),
            );

            row.insert(
                String::from("file_offset"),
                memory_mapping
                    .file_backing
                    .as_ref()
                    .map(|fb| ColumnValue::String(format!("{}", fb.offset))),
            );

            row_list.push(row);
        }

        Ok(row_list)
    }
}
