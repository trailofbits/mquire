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

/// A table plugin that exposes kernel symbols from kallsyms
pub struct KallsymsTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl KallsymsTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for KallsymsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("symbol_name"), ColumnType::String);
        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("symbol_type"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("kallsyms")
    }

    fn generate(&self) -> Result<RowList> {
        let symbols = match self.system.get_kallsyms_symbols() {
            Ok(symbols) => symbols,
            Err(_) => return Ok(RowList::new()),
        };

        let row_list: RowList = symbols
            .into_iter()
            .map(|symbol| {
                let mut row = BTreeMap::<String, OptionalColumnValue>::new();

                row.insert(
                    String::from("symbol_name"),
                    Some(ColumnValue::String(symbol.symbol_name)),
                );

                row.insert(
                    String::from("virtual_address"),
                    Some(ColumnValue::String(format!("{}", symbol.virtual_address))),
                );

                row.insert(
                    String::from("symbol_type"),
                    Some(ColumnValue::String(symbol.symbol_type.to_string())),
                );

                row
            })
            .collect();

        Ok(row_list)
    }
}
