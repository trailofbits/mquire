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
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("symbol_name"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("symbol_type"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("kallsyms")
    }

    fn generate(&self, _constraints: &Constraints) -> Result<RowList> {
        let symbols = match self.system.iter_kallsyms_symbols() {
            Ok(iter) => iter,
            Err(e) => {
                error!("Failed to iterate kallsyms symbols: {e:?}");
                return Ok(RowList::new());
            }
        };

        let row_list: RowList = symbols
            .map(|symbol| {
                BTreeMap::from([
                    (
                        String::from("symbol_name"),
                        Some(ColumnValue::String(symbol.symbol_name)),
                    ),
                    (
                        String::from("virtual_address"),
                        Some(ColumnValue::String(format!("{}", symbol.virtual_address))),
                    ),
                    (
                        String::from("symbol_type"),
                        Some(ColumnValue::String(symbol.symbol_type.to_string())),
                    ),
                ])
            })
            .collect();

        Ok(row_list)
    }
}
