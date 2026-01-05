//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    commands::command_registry::CommandContext,
    database::Database,
    utils::{display_query_data, display_table_schema},
};

use rustyline::DefaultEditor;

use std::io;

pub fn run_interactive_shell(database: &Database) -> io::Result<()> {
    println!("mquire interactive shell");
    println!("Enter SQL queries or special commands:");
    println!("  .tables           - List all tables");
    println!("  .schema           - Show schema for all tables");
    println!("  .schema <table>   - Show schema for specific table");
    println!("  .commands         - List all available commands");
    println!("  .exit             - Exit the shell");
    println!();

    let mut editor = DefaultEditor::new()
        .map_err(|e| io::Error::other(format!("Failed to create editor: {e}")))?;

    loop {
        let readline = editor.readline("mquire> ");
        let query = match readline {
            Ok(line) => {
                editor.add_history_entry(&line).ok();
                line
            }

            Err(_) => break,
        };

        let input = query.trim();
        if input.is_empty() {
            continue;
        }

        if input.starts_with('.') {
            if input.eq_ignore_ascii_case(".exit") {
                break;
            }

            process_command(database, input);
        } else {
            match database.query(input) {
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

fn process_command(database: &Database, input: &str) {
    if input.eq_ignore_ascii_case(".tables") {
        let table_names = database.get_table_names();
        for table_name in table_names {
            print!("{table_name} ");
        }
    } else if input.eq_ignore_ascii_case(".commands") {
        let commands = database.command_registry().list_commands();

        println!("Available commands:");
        for (name, description) in commands {
            println!("  .{:<20} {}", name, description);
        }
    } else if input.eq_ignore_ascii_case(".schema") {
        for table_name in &database.get_table_names() {
            if let Some(schema) = database.get_table_schema(table_name) {
                display_table_schema(table_name, &schema);
            }
        }
    } else if let Some(table_name) = input.strip_prefix(".schema ") {
        let table_name = table_name.trim();
        if let Some(schema) = database.get_table_schema(table_name) {
            display_table_schema(table_name, &schema);
        } else {
            println!("Table '{table_name}' not found");
        }
    } else {
        let context = CommandContext {
            system: database.system().clone(),
        };

        if let Err(error) = database.command_registry().execute(input, &context) {
            println!("Command execution failed: {error}");
        }
    }

    println!();
}
