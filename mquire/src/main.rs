//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{collections::BTreeMap, env, path::Path};

use mquire::operating_system::*;
use mquire::snapshot::RawSnapshot;
use mquire::sys::System;
use mquire::{architecture::IntelArchitecture, sys::Bitness};

use sqlite::{
    ColumnType, ColumnValue, Database, OptionalColumnValue, Result as DatabaseResult, RowList,
    TablePlugin,
};

struct SystemInfoTablePlugin<'a> {
    system: &'a System<'a>,
}

impl<'a> SystemInfoTablePlugin<'a> {
    fn new(system: &'a System) -> Self {
        Self { system }
    }
}

impl TablePlugin for SystemInfoTablePlugin<'_> {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("hostname"), ColumnType::String);
        schema.insert(String::from("domain"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("system_info")
    }

    fn generate(&self) -> DatabaseResult<RowList> {
        let system_information = self.system.get_system_information().unwrap();

        let mut row = BTreeMap::<String, OptionalColumnValue>::new();
        row.insert(
            String::from("hostname"),
            Some(ColumnValue::String(system_information.hostname)),
        );

        row.insert(
            String::from("domain"),
            system_information.domain.map(ColumnValue::String),
        );

        Ok(vec![row])
    }
}

struct TaskOpenFilesTablePlugin<'a> {
    system: &'a System<'a>,
}

impl<'a> TaskOpenFilesTablePlugin<'a> {
    fn new(system: &'a System) -> Self {
        Self { system }
    }
}

impl TablePlugin for TaskOpenFilesTablePlugin<'_> {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("pid"), ColumnType::String);
        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("path"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("task_open_files")
    }

    fn generate(&self) -> DatabaseResult<RowList> {
        let task_open_file_list = self.system.get_task_open_file_list().unwrap();

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
                String::from("path"),
                Some(ColumnValue::String(task_open_file.path)),
            );

            row_list.push(row)
        }

        Ok(row_list)
    }
}

struct OSVersionTablePlugin<'a> {
    system: &'a System<'a>,
}

impl<'a> OSVersionTablePlugin<'a> {
    fn new(system: &'a System) -> Self {
        Self { system }
    }
}

impl TablePlugin for OSVersionTablePlugin<'_> {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("kernel_version"), ColumnType::String);
        schema.insert(String::from("system_version"), ColumnType::String);
        schema.insert(String::from("arch"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("os_version")
    }

    fn generate(&self) -> DatabaseResult<RowList> {
        let os_version = self.system.get_os_version().unwrap();

        let mut row = BTreeMap::<String, OptionalColumnValue>::new();
        row.insert(
            String::from("kernel_version"),
            Some(ColumnValue::String(os_version.kernel_version)),
        );

        row.insert(
            String::from("system_version"),
            Some(ColumnValue::String(os_version.system_version)),
        );

        row.insert(
            String::from("arch"),
            Some(ColumnValue::String(os_version.arch)),
        );

        Ok(vec![row])
    }
}

struct TasksTablePlugin<'a> {
    system: &'a System<'a>,
}

impl<'a> TasksTablePlugin<'a> {
    fn new(system: &'a System) -> Self {
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

fn main() {
    let argument_list: Vec<String> = env::args().collect();
    if argument_list.len() != 3 {
        println!("Usage:\n\tmquire /path/raw/linux/memory/dump.bin 'SELECT * FROM tasks;'\n");
        return;
    }

    let memory_dump_path = Path::new(&argument_list[1]);
    if !memory_dump_path.exists() {
        println!("The specified memory dump file does not exist.");
        return;
    }

    let sql_statement = &argument_list[2];
    if sql_statement.is_empty() {
        println!("The specified query is empty.");
        return;
    }

    let architecture = IntelArchitecture::new(Bitness::Bit64);
    let operating_system = LinuxOperatingSystem::new();

    let memory_dump = RawSnapshot::new(memory_dump_path).unwrap();
    let system = System::new(&memory_dump, &architecture, &operating_system).unwrap();

    let task_table_plugin = TasksTablePlugin::new(&system);
    let os_version_table_plugin = OSVersionTablePlugin::new(&system);
    let system_info_table_plugin = SystemInfoTablePlugin::new(&system);
    let task_open_files = TaskOpenFilesTablePlugin::new(&system);

    let mut database = match Database::new() {
        Ok(database) => database,
        Err(_error) => {
            println!("Failed to create the database");
            return;
        }
    };

    if let Err(_error) = database.register_table_plugin(&task_table_plugin) {
        println!("Failed to register the `task_list` table");
        return;
    }

    if let Err(_error) = database.register_table_plugin(&os_version_table_plugin) {
        println!("Failed to register the `os_version` table");
        return;
    }

    if let Err(_error) = database.register_table_plugin(&system_info_table_plugin) {
        println!("Failed to register the `system_info` table");
        return;
    }

    if let Err(_error) = database.register_table_plugin(&task_open_files) {
        println!("Failed to register the `task_open_files` table");
        return;
    }

    let query_data = database.query(sql_statement).unwrap();

    for row in &query_data.row_list {
        for column_name in &query_data.column_order {
            let opt_column_value = row.get(column_name).unwrap();

            let printable_column_value = match opt_column_value {
                None => String::from("<null>"),
                Some(column_value) => match column_value {
                    ColumnValue::Double(value) => value.to_string(),
                    ColumnValue::String(value) => value.to_string(),
                    ColumnValue::SignedInteger(value) => value.to_string(),
                },
            };

            print!("{}:\"{}\" ", column_name, printable_column_value);
        }

        println!();
    }
}
