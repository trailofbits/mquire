//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

mod table_plugins;
mod table_registry;

use crate::{
    commands::command_registry::{self as commands, CommandRegistry},
    sqlite::{
        database::{Database as SqliteDatabase, QueryData},
        error::{Error, Result},
        table_plugin::ColumnType,
    },
    utils::{ArchitectureType, OperatingSystemType},
};

use mquire::{
    architecture::intel::architecture::IntelArchitecture,
    core::{architecture::Architecture, operating_system::OperatingSystem},
    memory::readable::Readable,
    operating_system::linux::operating_system::LinuxOperatingSystem,
    snapshot::{lime_snapshot::LimeSnapshot, raw_snapshot::RawSnapshot},
};

use std::{path::Path, sync::Arc};

/// Creates an Architecture instance based on the specified architecture type
fn create_architecture(arch_type: ArchitectureType) -> Result<Arc<dyn Architecture>> {
    match arch_type {
        ArchitectureType::Intel => Ok(IntelArchitecture::new()),
    }
}

/// Creates an OperatingSystem instance based on the specified OS type
fn create_operating_system(
    os_type: OperatingSystemType,
    memory_dump: Arc<dyn Readable>,
    architecture: Arc<dyn Architecture>,
) -> Result<Arc<dyn OperatingSystem>> {
    match os_type {
        OperatingSystemType::Linux => {
            let system = LinuxOperatingSystem::new(memory_dump, architecture)?;
            Ok(system as Arc<dyn OperatingSystem>)
        }
    }
}

/// Provides database-like access to an mquire OperatingSystem object
pub struct Database {
    sqlite_db: SqliteDatabase,
    command_registry: CommandRegistry,
    system: Arc<dyn OperatingSystem>,
}

impl Database {
    /// Creates a new database instance by opening the specified memory dump
    pub fn new(
        memory_dump_path: &Path,
        os_type: OperatingSystemType,
        arch_type: ArchitectureType,
    ) -> Result<Self> {
        let memory_dump: Arc<dyn Readable> = match memory_dump_path
            .extension()
            .and_then(|extension| extension.to_str())
        {
            Some("raw") => RawSnapshot::new(memory_dump_path)?,
            Some("lime") => LimeSnapshot::new(memory_dump_path)?,

            _ => {
                return Err(Error::Internal(
                    "Unsupported memory dump format".to_string(),
                ));
            }
        };

        let architecture = create_architecture(arch_type)?;
        let system = create_operating_system(os_type, memory_dump, architecture)?;

        let mut sqlite_db = SqliteDatabase::new()?;

        table_registry::register_all_tables(os_type, arch_type, &mut sqlite_db, system.clone())?;
        sqlite_db.load_autostart_files();

        let mut command_registry = CommandRegistry::new();
        commands::register_all_commands(os_type, arch_type, &mut command_registry);

        Ok(Self {
            sqlite_db,
            command_registry,
            system,
        })
    }

    /// Executes the given SQL query, returning raw query data
    pub fn query(&self, query: &str) -> Result<QueryData> {
        self.sqlite_db.query(query)
    }

    /// Executes the given SQL query, returning serialized JSON
    pub fn json(&self, query: &str) -> Result<String> {
        let query_data = self.sqlite_db.query(query)?;
        let json_query_data = serde_json::to_string_pretty(&query_data)
            .map_err(|error| Error::Internal(format!("JSON serialization error: {error:?}")))?;

        Ok(json_query_data)
    }

    /// Returns a list of all registered table names
    pub fn get_table_names(&self) -> Vec<String> {
        self.sqlite_db.get_table_names()
    }

    /// Returns the schema for a specific table
    pub fn get_table_schema(
        &self,
        table_name: &str,
    ) -> Option<std::collections::BTreeMap<String, ColumnType>> {
        self.sqlite_db.get_table_schema(table_name)
    }

    /// Returns a reference to the command registry
    pub fn command_registry(&self) -> &CommandRegistry {
        &self.command_registry
    }

    /// Returns a reference to the operating system
    pub fn system(&self) -> &Arc<dyn OperatingSystem> {
        &self.system
    }
}
