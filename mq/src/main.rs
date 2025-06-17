//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

mod database;
pub mod sqlite;

use crate::{
    database::Database,
    sqlite::{database::QueryData, table_plugin::ColumnValue},
};

use std::{
    env,
    io::{self, Write},
    path::Path,
};

fn display_query_data(query_data: &QueryData) -> Result<(), io::Error> {
    for row in &query_data.row_list {
        for column_name in &query_data.column_order {
            let opt_column_value = row
                .get(column_name)
                .ok_or(io::Error::other("Failed to acquire the column name"))?;

            let printable_column_value = match opt_column_value {
                None => String::from("<null>"),
                Some(column_value) => match column_value {
                    ColumnValue::Double(value) => value.to_string(),
                    ColumnValue::String(value) => value.to_string(),
                    ColumnValue::SignedInteger(value) => value.to_string(),
                },
            };

            print!("{column_name}:\"{printable_column_value}\" ");
        }

        println!();
    }

    Ok(())
}

fn run_interactive_shell(database: &Database) -> io::Result<()> {
    println!("Enter a query (or type '.exit' to quit)");

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

        if query.eq_ignore_ascii_case(".exit") {
            break;
        }

        match database.query(query) {
            Ok(query_data) => display_query_data(&query_data)?,

            Err(error) => {
                println!("Failed to query the mquire database: {error:?}");
            }
        }

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

    let database = Database::new(memory_dump_path).map_err(|error| {
        io::Error::other(format!("Failed to create the mquire database: {error:?}"))
    })?;

    if argument_list.len() == 3 {
        let query = &argument_list.get(2).ok_or(io::Error::other(
            "Failed to acquire the SQL query from the command line",
        ))?;

        let json = database.json(query).map_err(|error| {
            io::Error::other(format!("Failed to query the mquire database: {error:?}"))
        })?;

        println!("{json}");
    } else {
        run_interactive_shell(&database)?;
    }

    Ok(())
}
