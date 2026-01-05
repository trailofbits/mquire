//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{commands::command_registry::CommandContext, database::Database};

use std::io;

pub fn execute_command(database: &Database, input: &str) -> io::Result<()> {
    let input = input.trim();

    if input.eq_ignore_ascii_case(".commands") {
        let commands = database.command_registry().list_commands();

        println!("Available commands:");
        for (name, description) in commands {
            println!("  .{:<20} {}", name, description);
        }
    } else if input.starts_with('.') {
        let context = CommandContext {
            system: database.system().clone(),
        };

        database.command_registry().execute(input, &context)?;
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid command: '{}'. Commands must start with '.' (e.g., '.task_tree')",
                input
            ),
        ));
    }

    Ok(())
}
