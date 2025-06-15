//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

mod table_plugins;

use crate::{
    database::table_plugins::{
        os_version::OSVersionTablePlugin, system_info::SystemInfoTablePlugin,
        task_open_files::TaskOpenFilesTablePlugin, tasks::TasksTablePlugin,
    },
    sqlite::{
        database::{Database as SqliteDatabase, QueryData},
        error::{Error, ErrorKind, Result},
    },
};

use mquire::{
    architecture::intel::architecture::IntelArchitecture,
    operating_system::linux::operating_system::LinuxOperatingSystem,
    snapshot::raw_snapshot::RawSnapshot,
};

use std::path::Path;

pub struct Database {
    sqlite_db: SqliteDatabase,
}

impl Database {
    pub fn new(memory_dump: &Path) -> Result<Self> {
        let memory_dump = RawSnapshot::new(memory_dump)?;
        let system = LinuxOperatingSystem::new(memory_dump, IntelArchitecture::new())?;

        let mut sqlite_db = SqliteDatabase::new()?;
        sqlite_db.register_table_plugin(OSVersionTablePlugin::new(system.clone()))?;
        sqlite_db.register_table_plugin(SystemInfoTablePlugin::new(system.clone()))?;
        sqlite_db.register_table_plugin(TaskOpenFilesTablePlugin::new(system.clone()))?;
        sqlite_db.register_table_plugin(TasksTablePlugin::new(system.clone()))?;

        Ok(Self { sqlite_db })
    }

    pub fn query(&self, query: &str) -> Result<QueryData> {
        self.sqlite_db.query(query)
    }

    pub fn json(&self, query: &str) -> Result<String> {
        let query_data = self.sqlite_db.query(query)?;
        let json_query_data = serde_json::to_string_pretty(&query_data).map_err(|error| {
            Error::new(
                ErrorKind::InternalError,
                &format!("JSON serialization error: {:?}", error),
            )
        })?;

        Ok(json_query_data)
    }
}
