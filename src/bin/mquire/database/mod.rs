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
        table_plugin::ColumnDef,
    },
    utils::{ArchitectureType, OperatingSystemType},
};

use mquire::core::operating_system::OperatingSystem;

use std::sync::Arc;

/// Provides database-like access to an mquire OperatingSystem object
pub struct Database {
    sqlite_db: SqliteDatabase,
    command_registry: CommandRegistry,
}

impl Database {
    /// Creates a new database instance from pre-created components
    pub fn new(
        os_type: OperatingSystemType,
        arch_type: ArchitectureType,
        system: Arc<dyn OperatingSystem>,
    ) -> Result<Self> {
        let mut sqlite_db = SqliteDatabase::new()?;

        table_registry::register_all_tables(os_type, arch_type, &mut sqlite_db, system.clone())?;
        sqlite_db.load_autostart_files();

        let mut command_registry = CommandRegistry::new();
        commands::register_all_commands(os_type, arch_type, &mut command_registry);

        Ok(Self {
            sqlite_db,
            command_registry,
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
    ) -> Option<std::collections::BTreeMap<String, ColumnDef>> {
        self.sqlite_db.get_table_schema(table_name)
    }

    /// Returns a reference to the command registry
    pub fn command_registry(&self) -> &CommandRegistry {
        &self.command_registry
    }
}
