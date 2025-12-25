//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

mod database;
mod dump;
mod logger;
mod query;
mod shell;
mod sqlite;
mod utils;

use clap::{Parser, Subcommand};
use database::Database;
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

    /// Extract all open files from a snapshot to disk
    Dump {
        /// Path to the memory snapshot (.raw or .lime)
        snapshot: PathBuf,

        /// Output directory for extracted files
        output: PathBuf,
    },
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    logger::Logger::initialize();

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

            let database = Database::new(&snapshot).map_err(|error| {
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

            let database = Database::new(&snapshot).map_err(|error| {
                io::Error::other(format!("Failed to create the mquire database: {error:?}"))
            })?;

            query::execute_query(&database, &query, output_format)?;
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

            dump::dump_files(&snapshot, &output)?;
        }
    }

    Ok(())
}
