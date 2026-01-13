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

use mquire::operating_system::linux::operating_system::LinuxOperatingSystem;

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that exposes the system boot time
pub struct BootTimeTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl BootTimeTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for BootTimeTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("boot_time"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("boot_time")
    }

    fn generate(&self, _constraints: &Constraints) -> Result<RowList> {
        let boot_time = match self.system.get_boot_time() {
            Ok(boot_time) => boot_time,

            Err(e) => {
                error!("Failed to get boot time: {e:?}");
                return Ok(RowList::new());
            }
        };

        let row = BTreeMap::from([
            (
                String::from("virtual_address"),
                Some(ColumnValue::String(format!(
                    "{}",
                    boot_time.virtual_address
                ))),
            ),
            (
                String::from("boot_time"),
                Some(ColumnValue::SignedInteger(boot_time.boot_time as i64)),
            ),
        ]);

        Ok(vec![row])
    }
}
