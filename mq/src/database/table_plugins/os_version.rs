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

use mquire::core::operating_system::OperatingSystem;

use std::{collections::BTreeMap, rc::Rc};

/// A table plugin that outputs the OS version
pub struct OSVersionTablePlugin {
    system: Rc<dyn OperatingSystem>,
}

impl OSVersionTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Rc<dyn OperatingSystem>) -> Rc<Self> {
        Rc::new(Self { system })
    }
}

impl TablePlugin for OSVersionTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("kernel_version"), ColumnType::String);
        schema.insert(String::from("system_version"), ColumnType::String);
        schema.insert(String::from("arch"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("os_version")
    }

    fn generate(&self) -> Result<RowList> {
        let os_version = self.system.get_os_version()?;

        let mut row = BTreeMap::<String, OptionalColumnValue>::new();
        row.insert(
            String::from("kernel_version"),
            os_version.kernel_version.map(ColumnValue::String),
        );

        row.insert(
            String::from("system_version"),
            os_version.system_version.map(ColumnValue::String),
        );

        row.insert(
            String::from("arch"),
            os_version.arch.map(ColumnValue::String),
        );

        Ok(vec![row])
    }
}
