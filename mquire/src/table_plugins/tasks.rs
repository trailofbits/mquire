//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::collections::BTreeMap;

use mquire::sys::System;

use sqlite::{
    ColumnType, ColumnValue, OptionalColumnValue, Result as DatabaseResult, RowList, TablePlugin,
};

pub struct TasksTablePlugin<'a> {
    system: &'a System<'a>,
}

impl<'a> TasksTablePlugin<'a> {
    pub fn new(system: &'a System) -> Self {
        Self { system }
    }
}

impl TablePlugin for TasksTablePlugin<'_> {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("page_table"), ColumnType::String);
        schema.insert(String::from("binary_path"), ColumnType::String);
        schema.insert(String::from("comm"), ColumnType::String);
        schema.insert(String::from("command_line"), ColumnType::String);
        schema.insert(String::from("environment"), ColumnType::String);
        schema.insert(String::from("pid"), ColumnType::SignedInteger);
        schema.insert(String::from("uid"), ColumnType::SignedInteger);
        schema.insert(String::from("gid"), ColumnType::SignedInteger);

        schema
    }

    fn name(&self) -> String {
        String::from("tasks")
    }

    fn generate(&self) -> DatabaseResult<RowList> {
        let mut row_list = RowList::new();

        for task in self.system.get_task_list().unwrap() {
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
                environment.push_str(&format!("{}={}, ", key, value));
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
                String::from("pid"),
                Some(ColumnValue::SignedInteger(task.pid as i64)),
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
