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

use mquire::core::operating_system::OperatingSystem;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that lists task open files
pub struct TaskOpenFilesTablePlugin {
    system: Arc<dyn OperatingSystem>,
}

impl TaskOpenFilesTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<dyn OperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for TaskOpenFilesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("pid"), ColumnType::String);
        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("task"), ColumnType::String);
        schema.insert(String::from("path"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("task_open_files")
    }

    fn generate(&self) -> Result<RowList> {
        let task_open_file_list = self.system.get_task_open_file_list()?;

        let mut row_list = Vec::new();

        for task_open_file in task_open_file_list {
            let mut row = BTreeMap::<String, OptionalColumnValue>::new();

            row.insert(
                String::from("pid"),
                Some(ColumnValue::SignedInteger(task_open_file.pid as i64)),
            );

            row.insert(
                String::from("virtual_address"),
                Some(ColumnValue::String(format!(
                    "{:?}",
                    task_open_file.virtual_address
                ))),
            );

            row.insert(
                String::from("task"),
                Some(ColumnValue::String(format!("{:?}", task_open_file.task))),
            );

            row.insert(
                String::from("path"),
                Some(ColumnValue::String(task_open_file.path)),
            );

            row_list.push(row)
        }

        Ok(row_list)
    }
}
