//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    database::Database,
    utils::{display_query_data, display_table_schema},
};

use std::io::{self, Write};

pub fn run_interactive_shell(database: &Database) -> io::Result<()> {
    println!("mquire interactive shell");
    println!("Enter SQL queries or special commands:");
    println!("  .tables           - List all tables");
    println!("  .schema           - Show schema for all tables");
    println!("  .schema <table>   - Show schema for specific table");
    println!("  .exit             - Exit the shell");
    println!();

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

        if query.eq_ignore_ascii_case(".tables") {
            let table_names = database.get_table_names();
            for table_name in table_names {
                print!("{table_name} ");
            }
            println!();
        } else if query.eq_ignore_ascii_case(".schema") {
            let table_names = database.get_table_names();
            for table_name in &table_names {
                if let Some(schema) = database.get_table_schema(table_name) {
                    display_table_schema(table_name, &schema);
                }
            }
        } else if let Some(table_name) = query.strip_prefix(".schema ") {
            let table_name = table_name.trim();
            if let Some(schema) = database.get_table_schema(table_name) {
                display_table_schema(table_name, &schema);
            } else {
                println!("Table '{table_name}' not found");
            }
        } else {
            match database.query(query) {
                Ok(query_data) => display_query_data(&query_data)?,

                Err(error) => {
                    println!("Failed to query the mquire database: {error:?}");
                }
            }
        }

        println!();
    }

    Ok(())
}
