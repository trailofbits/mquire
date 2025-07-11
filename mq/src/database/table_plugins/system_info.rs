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

/// A table plugin that outputs the system hostname and domain name
pub struct SystemInfoTablePlugin {
    system: Rc<dyn OperatingSystem>,
}

impl SystemInfoTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Rc<dyn OperatingSystem>) -> Rc<Self> {
        Rc::new(Self { system })
    }
}

impl TablePlugin for SystemInfoTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("hostname"), ColumnType::String);
        schema.insert(String::from("domain"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("system_info")
    }

    fn generate(&self) -> Result<RowList> {
        let system_information = self.system.get_system_information()?;

        let mut row = BTreeMap::<String, OptionalColumnValue>::new();
        row.insert(
            String::from("hostname"),
            system_information.hostname.map(ColumnValue::String),
        );

        row.insert(
            String::from("domain"),
            system_information.domain.map(ColumnValue::String),
        );

        Ok(vec![row])
    }
}
