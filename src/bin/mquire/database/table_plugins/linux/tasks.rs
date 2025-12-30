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

/// A table plugin that lists active tasks
pub struct TasksTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl TasksTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for TasksTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("page_table"), ColumnType::String);
        schema.insert(String::from("binary_path"), ColumnType::String);
        schema.insert(String::from("comm"), ColumnType::String);
        schema.insert(String::from("command_line"), ColumnType::String);
        schema.insert(String::from("environment"), ColumnType::String);
        schema.insert(String::from("ppid"), ColumnType::SignedInteger);
        schema.insert(String::from("real_ppid"), ColumnType::SignedInteger);
        schema.insert(String::from("pid"), ColumnType::SignedInteger);
        schema.insert(String::from("tid"), ColumnType::SignedInteger);
        schema.insert(String::from("main_thread"), ColumnType::SignedInteger);
        schema.insert(String::from("uid"), ColumnType::SignedInteger);
        schema.insert(String::from("gid"), ColumnType::SignedInteger);

        schema
    }

    fn name(&self) -> String {
        String::from("tasks")
    }

    fn generate(&self) -> Result<RowList> {
        let mut row_list = RowList::new();

        for task in self.system.get_task_list()? {
            let mut row = BTreeMap::<String, OptionalColumnValue>::new();

            row.insert(
                String::from("virtual_address"),
                Some(ColumnValue::String(format!("{:?}", task.virtual_address))),
            );

            row.insert(
                String::from("page_table"),
                Some(ColumnValue::String(format!("{:?}", task.page_table))),
            );

            row.insert(
                String::from("binary_path"),
                task.binary_path.map(ColumnValue::String),
            );

            row.insert(String::from("comm"), task.name.map(ColumnValue::String));
            row.insert(
                String::from("command_line"),
                task.command_line.map(ColumnValue::String),
            );

            let mut environment = String::new();
            for (key, value) in task.environment_variable_map {
                environment.push_str(&format!("{key}={value}, "));
            }

            let environment = match environment.is_empty() {
                true => None,
                false => Some(environment),
            };

            row.insert(
                String::from("environment"),
                environment.map(ColumnValue::String),
            );

            row.insert(
                String::from("ppid"),
                task.ppid
                    .map(|parent_pid| ColumnValue::SignedInteger(parent_pid as i64)),
            );

            row.insert(
                String::from("real_ppid"),
                task.real_ppid
                    .map(|parent_pid| ColumnValue::SignedInteger(parent_pid as i64)),
            );

            row.insert(
                String::from("pid"),
                Some(ColumnValue::SignedInteger(task.pid as i64)),
            );

            row.insert(
                String::from("tid"),
                Some(ColumnValue::SignedInteger(task.tid as i64)),
            );

            row.insert(
                String::from("main_thread"),
                Some(ColumnValue::SignedInteger(if task.main_thread {
                    1
                } else {
                    0
                })),
            );

            row.insert(
                String::from("uid"),
                Some(ColumnValue::SignedInteger(task.uid as i64)),
            );

            row.insert(
                String::from("gid"),
                Some(ColumnValue::SignedInteger(task.gid as i64)),
            );

            row_list.push(row);
        }

        Ok(row_list)
    }
}
