//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    commands::{common, linux},
    utils::{ArchitectureType, OperatingSystemType},
};

use mquire::{
    core::{architecture::Architecture, operating_system::OperatingSystem},
    memory::readable::Readable,
};

use std::{io, sync::Arc};

/// Context provided to commands for accessing the snapshot and system
pub struct CommandContext {
    /// The operating system plugin
    pub system: Arc<dyn OperatingSystem>,

    /// The target architecture
    pub architecture: Arc<dyn Architecture>,

    /// The memory dump
    pub snapshot: Arc<dyn Readable>,
}

/// Trait for implementing custom commands that can be invoked from the shell or query interface
pub trait Command: Send + Sync {
    /// Returns the command name (e.g., "process_tree" for ".process_tree")
    fn name(&self) -> &str;

    /// Executes the command with the given arguments and context
    fn execute(&self, args: &str, context: &CommandContext) -> io::Result<()>;

    /// Returns a short description of what the command does
    fn description(&self) -> &str;
}

/// Registry for managing available commands
pub struct CommandRegistry {
    commands: Vec<Box<dyn Command>>,
}

impl CommandRegistry {
    /// Creates a new empty command registry
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    /// Registers a command with the registry
    pub fn register(&mut self, command: Box<dyn Command>) {
        self.commands.push(command);
    }

    /// Executes the given command
    pub fn execute(&self, input: &str, context: &CommandContext) -> io::Result<()> {
        let input = input.trim();

        let input_without_dot = &input[1..];
        let (command_name, args) =
            if let Some(space_idx) = input_without_dot.find(char::is_whitespace) {
                (
                    &input_without_dot[..space_idx],
                    input_without_dot[space_idx..].trim(),
                )
            } else {
                (input_without_dot, "")
            };

        if let Some(command) = self
            .commands
            .iter()
            .find(|&command| command.name().eq_ignore_ascii_case(command_name))
        {
            command.execute(args, context)
        } else {
            Err(io::Error::other(format!("Command not found: {input}")))
        }
    }

    /// Returns a list of all registered commands with their descriptions
    pub fn list_commands(&self) -> Vec<(&str, &str)> {
        self.commands
            .iter()
            .map(|cmd| (cmd.name(), cmd.description()))
            .collect()
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory function types for creating commands
enum CommandFactory {
    /// Command that works with any OperatingSystem
    Common(fn() -> Box<dyn Command>),

    /// Command that requires LinuxOperatingSystem
    Linux(fn() -> Box<dyn Command>),
}

/// Command plugin metadata
struct CommandMetadata {
    required_arch: Option<ArchitectureType>,
    factory: CommandFactory,
}

/// Generates the command registry
macro_rules! generate_command_registry {
    (
        $(
            $os_type:ident, $arch:ident => {
                $(
                    $command:ty
                ),* $(,)?
            }
        ),* $(,)?
    ) => {
        const COMMAND_REGISTRY: &[CommandMetadata] = &[
            $(
                $(
                    CommandMetadata {
                        required_arch: generate_command_registry!(@arch $arch),
                        factory: generate_command_registry!(@factory $os_type, $command),
                    },
                )*
            )*
        ];
    };

    (@arch Common) => {
        None
    };

    (@arch $arch:ident) => {
        Some(ArchitectureType::$arch)
    };

    (@factory Common, $command:ty) => {
        CommandFactory::Common(|| Box::new(<$command>::new()))
    };

    (@factory Linux, $command:ty) => {
        CommandFactory::Linux(|| Box::new(<$command>::new()))
    };
}

// Central registry of all available commands
generate_command_registry! {
    Common, Common => {
        common::carve::CarveCommand,
        common::system_version::SystemVersionCommand,
    },

    Linux, Common => {
        linux::dump::DumpCommand,
        linux::task_tree::TaskTreeCommand,
    },
}

/// Checks if a command's architecture requirement is compatible
fn is_command_compatible_arch(
    required: Option<ArchitectureType>,
    actual: ArchitectureType,
) -> bool {
    match required {
        None => true,
        Some(required) => required == actual,
    }
}

/// Checks if a command's factory is compatible with the specified OS
fn is_command_compatible_os(factory: &CommandFactory, os_type: OperatingSystemType) -> bool {
    match factory {
        CommandFactory::Common(_) => true,
        CommandFactory::Linux(_) => os_type == OperatingSystemType::Linux,
    }
}

/// Collects all commands compatible with the specified OS and architecture
fn collect_commands_for(
    os_type: OperatingSystemType,
    arch_type: ArchitectureType,
) -> Vec<&'static CommandMetadata> {
    COMMAND_REGISTRY
        .iter()
        .filter(|cmd| {
            is_command_compatible_os(&cmd.factory, os_type)
                && is_command_compatible_arch(cmd.required_arch, arch_type)
        })
        .collect()
}

/// Registers all commands compatible with the specified OS and architecture
pub fn register_all_commands(
    os_type: OperatingSystemType,
    arch_type: ArchitectureType,
    registry: &mut CommandRegistry,
) {
    let commands = collect_commands_for(os_type, arch_type);

    for cmd_meta in commands {
        let command = match &cmd_meta.factory {
            CommandFactory::Common(factory_fn) => factory_fn(),
            CommandFactory::Linux(factory_fn) => factory_fn(),
        };

        registry.register(command);
    }
}
