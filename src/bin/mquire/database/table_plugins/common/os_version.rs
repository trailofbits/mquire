//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::Result,
    table_plugin::{ColumnDef, ColumnType, ColumnValue, Constraints, RowList, TablePlugin},
};

use mquire::core::operating_system::OperatingSystem;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that outputs the OS version
pub struct OSVersionTablePlugin {
    system: Arc<dyn OperatingSystem>,
}

impl OSVersionTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<dyn OperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for OSVersionTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("kernel_version"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("system_version"),
                ColumnDef::visible(ColumnType::String),
            ),
            (String::from("arch"), ColumnDef::visible(ColumnType::String)),
        ])
    }

    fn name(&self) -> String {
        String::from("os_version")
    }

    fn generate(&self, _constraints: &Constraints) -> Result<RowList> {
        let os_version = self.system.get_os_version()?;
        let row = BTreeMap::from([
            (
                String::from("kernel_version"),
                os_version.kernel_version.map(ColumnValue::String),
            ),
            (
                String::from("system_version"),
                os_version.system_version.map(ColumnValue::String),
            ),
            (
                String::from("arch"),
                os_version.arch.map(ColumnValue::String),
            ),
        ]);

        Ok(vec![row])
    }
}
