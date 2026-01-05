//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::commands::command_registry::{Command, CommandContext};

use std::io;

/// A shortcut command that prints the system version
pub struct SystemVersionCommand;

impl SystemVersionCommand {
    /// Creates a new SystemVersionCommand instance
    pub fn new() -> Self {
        Self
    }
}

impl Command for SystemVersionCommand {
    fn name(&self) -> &str {
        "system_version"
    }

    fn description(&self) -> &str {
        "Display the operating system version"
    }

    fn execute(&self, _args: &str, context: &CommandContext) -> io::Result<()> {
        let version = context
            .system
            .get_os_version()
            .map_err(|e| io::Error::other(format!("Failed to get OS version: {:?}", e)))?;

        if let Some(system_version) = &version.system_version {
            println!("System Version: {}", system_version);
        }

        if let Some(kernel_version) = &version.kernel_version {
            println!("Kernel Version: {}", kernel_version);
        }

        if let Some(arch) = &version.arch {
            println!("Architecture: {}", arch);
        }

        Ok(())
    }
}

impl Default for SystemVersionCommand {
    fn default() -> Self {
        Self::new()
    }
}
