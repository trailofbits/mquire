//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

mod command;
mod commands;
mod database;
mod logger;
mod query;
mod shell;
mod sqlite;
mod utils;

use {
    commands::command_registry::CommandContext,
    database::Database,
    utils::{ArchitectureType, OperatingSystemType},
};

use clap::{Parser, Subcommand};

use mquire::{
    architecture::intel::architecture::IntelArchitecture,
    core::{architecture::Architecture, operating_system::OperatingSystem},
    memory::readable::Readable,
    operating_system::linux::operating_system::LinuxOperatingSystem,
    snapshot::open_memory,
};

use std::{io, path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(name = "mquire")]
#[command(about = "Memory forensics and analysis tool", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable debug logging
    #[arg(short, long, global = true)]
    debug: bool,

    /// Operating system type (linux)
    #[arg(long, global = true, default_value = "linux")]
    operating_system: String,

    /// Architecture type (intel)
    #[arg(long, global = true, default_value = "intel")]
    architecture: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Start an interactive SQL shell for querying snapshots
    Shell {
        /// Path to the memory snapshot (.raw or .lime)
        snapshot: PathBuf,
    },

    /// Execute a SQL query against a snapshot
    Query {
        /// Path to the memory snapshot (.raw or .lime)
        snapshot: PathBuf,

        /// SQL query to execute (or special commands like .tables, .schema)
        query: String,

        /// Output format (either `json` or `table`)
        #[arg(short, long, value_name = "FORMAT", default_value = "json")]
        format: String,
    },

    /// Executes a built-in command on the given snapshot
    Command {
        /// Path to the memory snapshot (.raw or .lime)
        snapshot: PathBuf,

        /// Command to execute (defaults to .commands to list available commands)
        #[arg(default_value = ".commands")]
        command_line: String,
    },
}

fn parse_operating_system(os_str: &str) -> io::Result<OperatingSystemType> {
    match os_str.to_lowercase().as_str() {
        "linux" => Ok(OperatingSystemType::Linux),

        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid operating system '{}'. Valid options: linux",
                os_str
            ),
        )),
    }
}

fn parse_architecture(arch_str: &str) -> io::Result<ArchitectureType> {
    match arch_str.to_lowercase().as_str() {
        "intel" => Ok(ArchitectureType::Intel),

        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid architecture '{}'. Valid options: intel", arch_str),
        )),
    }
}

/// Creates an Architecture instance based on the specified architecture type
fn create_architecture(arch_type: ArchitectureType) -> Arc<dyn Architecture> {
    match arch_type {
        ArchitectureType::Intel => IntelArchitecture::new(),
    }
}

/// Creates an OperatingSystem instance based on the specified OS type
fn create_operating_system(
    os_type: OperatingSystemType,
    memory_dump: Arc<dyn Readable>,
    architecture: Arc<dyn Architecture>,
) -> io::Result<Arc<dyn OperatingSystem>> {
    match os_type {
        OperatingSystemType::Linux => {
            let system = LinuxOperatingSystem::new(memory_dump, architecture).map_err(|e| {
                io::Error::other(format!("Failed to create operating system: {e:?}"))
            })?;

            Ok(system as Arc<dyn OperatingSystem>)
        }
    }
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    logger::Logger::initialize(cli.debug);

    let os_type = parse_operating_system(&cli.operating_system)?;
    let arch_type = parse_architecture(&cli.architecture)?;

    match cli.command {
        Commands::Shell { snapshot } => {
            if !snapshot.exists() {
                eprintln!(
                    "Error: Snapshot file does not exist: {}",
                    snapshot.display()
                );

                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Snapshot file not found",
                ));
            }

            let readable = open_memory(&snapshot)?;
            let architecture = create_architecture(arch_type);
            let system = create_operating_system(os_type, readable.clone(), architecture.clone())?;

            let database = Database::new(os_type, arch_type, system.clone()).map_err(|error| {
                io::Error::other(format!("Failed to create the mquire database: {error:?}"))
            })?;

            shell::run_interactive_shell(
                system.clone(),
                architecture.clone(),
                readable.clone(),
                &database,
            )?;
        }

        Commands::Query {
            snapshot,
            query,
            format,
        } => {
            if !snapshot.exists() {
                eprintln!(
                    "Error: Snapshot file does not exist: {}",
                    snapshot.display()
                );

                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Snapshot file not found",
                ));
            }

            let output_format = query::OutputFormat::from_str(&format)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

            let readable = open_memory(&snapshot)?;
            let architecture = create_architecture(arch_type);
            let system = create_operating_system(os_type, readable, architecture)?;

            let database = Database::new(os_type, arch_type, system).map_err(|error| {
                io::Error::other(format!("Failed to create the mquire database: {error:?}"))
            })?;

            query::execute_query(&database, &query, output_format)?;
        }

        Commands::Command {
            snapshot,
            command_line,
        } => {
            if !snapshot.exists() {
                eprintln!(
                    "Error: Snapshot file does not exist: {}",
                    snapshot.display()
                );

                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Snapshot file not found",
                ));
            }

            let readable = open_memory(&snapshot)?;
            let architecture = create_architecture(arch_type);
            let system = create_operating_system(os_type, readable.clone(), architecture.clone())?;

            let database = Database::new(os_type, arch_type, system.clone()).map_err(|error| {
                io::Error::other(format!("Failed to create the mquire database: {error:?}"))
            })?;

            let context = CommandContext {
                system,
                architecture,
                snapshot: readable,
            };

            command::execute_command(database.command_registry(), &context, &command_line)?;
        }
    }

    Ok(())
}
