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

/// A table plugin that outputs the system hostname and domain name
pub struct SystemInfoTablePlugin {
    system: Arc<dyn OperatingSystem>,
}

impl SystemInfoTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<dyn OperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for SystemInfoTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("hostname"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("domain"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("system_info")
    }

    fn generate(&self, _constraints: &Constraints) -> Result<RowList> {
        let system_information = self.system.get_system_information()?;
        let row = BTreeMap::from([
            (
                String::from("hostname"),
                system_information.hostname.map(ColumnValue::String),
            ),
            (
                String::from("domain"),
                system_information.domain.map(ColumnValue::String),
            ),
        ]);

        Ok(vec![row])
    }
}
