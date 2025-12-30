//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::Result,
    table_plugin::{ColumnType, ColumnValue, OptionalColumnValue, RowList, TablePlugin},
};

use mquire::operating_system::linux::operating_system::LinuxOperatingSystem;

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
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("boot_time"), ColumnType::SignedInteger);

        schema
    }

    fn name(&self) -> String {
        String::from("boot_time")
    }

    fn generate(&self) -> Result<RowList> {
        let boot_times = match self.system.get_boot_time() {
            Ok(boot_times) => boot_times,
            Err(_) => return Ok(RowList::new()),
        };

        let row_list: RowList = boot_times
            .into_iter()
            .map(|boot_time| {
                let mut row = BTreeMap::<String, OptionalColumnValue>::new();

                row.insert(
                    String::from("virtual_address"),
                    Some(ColumnValue::String(format!(
                        "{}",
                        boot_time.virtual_address
                    ))),
                );

                row.insert(
                    String::from("boot_time"),
                    Some(ColumnValue::SignedInteger(boot_time.boot_time as i64)),
                );

                row
            })
            .collect();

        Ok(row_list)
    }
}
