//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::commands::command_registry::{CommandContext, CommandRegistry};

use std::io;

/// Executes a command and handles errors appropriately.
///
/// For InvalidInput errors (e.g., argument parsing failures), the error message
/// is printed directly to stderr and the process exits with code 1. This provides
/// cleaner output for user-facing errors like missing arguments.
///
/// For other errors, they are propagated up to the caller.
pub fn execute_command(
    command_registry: &CommandRegistry,
    context: &CommandContext,
    input: &str,
) -> io::Result<()> {
    let input = input.trim();

    let result = if input.eq_ignore_ascii_case(".commands") {
        let commands = command_registry.list_commands();

        println!("Available commands:");
        for (name, description) in commands {
            println!("  .{:<20} {}", name, description);
        }

        Ok(())
    } else if input.starts_with('.') {
        command_registry.execute(input, context)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid command: '{}'. Commands must start with '.' (e.g., '.task_tree')",
                input
            ),
        ))
    };

    if let Err(ref error) = result
        && error.kind() == io::ErrorKind::InvalidInput
    {
        eprintln!("{}", error);
        Ok(())
    } else {
        result
    }
}
