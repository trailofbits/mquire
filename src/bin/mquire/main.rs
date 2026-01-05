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
mod dump;
mod logger;
mod query;
mod shell;
mod sqlite;
mod utils;

use crate::dump::dump_task_open_files;

use {
    database::Database,
    utils::{ArchitectureType, OperatingSystemType},
};

use clap::{Parser, Subcommand};

use std::{io, path::PathBuf};

#[derive(Parser)]
#[command(name = "mquire")]
#[command(about = "Memory forensics and analysis tool", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Operating system type (linux, all)
    #[arg(long, global = true, default_value = "linux")]
    operating_system: String,

    /// Architecture type (intel, all)
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

    /// Extract all open files from a snapshot to disk
    Dump {
        /// Path to the memory snapshot (.raw or .lime)
        snapshot: PathBuf,

        /// Output directory for extracted files
        output: PathBuf,
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

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    logger::Logger::initialize();

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

            let database = Database::new(&snapshot, os_type, arch_type).map_err(|error| {
                io::Error::other(format!("Failed to create the mquire database: {error:?}"))
            })?;

            shell::run_interactive_shell(&database)?;
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

            let database = Database::new(&snapshot, os_type, arch_type).map_err(|error| {
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

            let database = Database::new(&snapshot, os_type, arch_type).map_err(|error| {
                io::Error::other(format!("Failed to create the mquire database: {error:?}"))
            })?;

            command::execute_command(&database, &command_line)?;
        }

        Commands::Dump { snapshot, output } => {
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

            dump_task_open_files(&snapshot, &output)?;
        }
    }

    Ok(())
}
