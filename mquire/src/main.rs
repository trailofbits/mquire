//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{env, path::Path};

use mquire::{
    architecture::IntelArchitecture, operating_system::*, snapshot::RawSnapshot, sys::Bitness,
    sys::System,
};

use sqlite::{ColumnValue, Database};

mod table_plugins;
use table_plugins::*;

use std::io::{self, Write};

fn execute_query(database: &Database, query: &str) -> io::Result<()> {
    match database.query(query) {
        Ok(query_data) => {
            for row in &query_data.row_list {
                for column_name in &query_data.column_order {
                    let opt_column_value = row.get(column_name).ok_or(io::Error::new(
                        io::ErrorKind::Other,
                        "Failed to acquire the column name",
                    ))?;

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

        Err(e) => {
            println!("Error executing query: {:?}", e);
        }
    }

    Ok(())
}

fn run_interactive_shell(database: &Database) -> io::Result<()> {
    println!("Enter a query (or type 'exit' to quit)");

    loop {
        print!("mquire> ");
        io::stdout().flush()?;

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            println!("Error reading input");
            continue;
        }

        let query = input.trim();
        if query.is_empty() {
            continue;
        }

        if query.eq_ignore_ascii_case("exit") {
            break;
        }

        execute_query(database, query)?;
        println!();
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let argument_list: Vec<String> = env::args().collect();
    if argument_list.len() != 2 && argument_list.len() != 3 {
        println!("Usage:\n\tmquire /path/raw/linux/memory/dump.bin [SQL query]\n");
        return Ok(());
    }

    let memory_dump_path = Path::new(&argument_list[1]);
    if !memory_dump_path.exists() {
        println!("The specified memory dump file does not exist.");
        return Ok(());
    }

    let architecture = IntelArchitecture::new(Bitness::Bit64);
    let operating_system = LinuxOperatingSystem::new();

    let memory_dump = RawSnapshot::new(memory_dump_path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to open the memory snapshot: {:?}", error),
        )
    })?;

    let system = System::new(&memory_dump, &architecture, &operating_system).map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to create the System plugin: {:?}", error),
        )
    })?;

    let os_version_table_plugin = os_version::OSVersionTablePlugin::new(&system);
    let system_info_table_plugin = system_info::SystemInfoTablePlugin::new(&system);
    let task_open_files_table_plugin = task_open_files::TaskOpenFilesTablePlugin::new(&system);
    let task_table_plugin = tasks::TasksTablePlugin::new(&system);

    let mut database = Database::new().map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to create the database: {:?}", error),
        )
    })?;

    database
        .register_table_plugin(&os_version_table_plugin)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to register the 'os_version' table plugin: {:?}",
                    error
                ),
            )
        })?;

    database
        .register_table_plugin(&system_info_table_plugin)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to register the 'system_info' table plugin {:?}",
                    error
                ),
            )
        })?;

    database
        .register_table_plugin(&task_open_files_table_plugin)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to register the 'task_open_files' table plugin {:?}",
                    error
                ),
            )
        })?;

    database
        .register_table_plugin(&task_table_plugin)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to register the 'tasks' table plugin {:?}", error),
            )
        })?;

    if argument_list.len() == 3 {
        let query = &argument_list.get(2).ok_or(io::Error::new(
            io::ErrorKind::Other,
            "Failed to acquire the SQL query from the command line",
        ))?;

        execute_query(&database, query)?;
    } else {
        run_interactive_shell(&database)?;
    }

    Ok(())
}
