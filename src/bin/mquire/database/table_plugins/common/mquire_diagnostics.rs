//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    logger::Logger,
    sqlite::{
        error::Result,
        table_plugin::{ColumnDef, ColumnType, ColumnValue, Constraints, RowList, TablePlugin},
    },
};

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that exports mquire's internal diagnostics
pub struct MquireDiagnosticsTablePlugin;

impl MquireDiagnosticsTablePlugin {
    /// Creates a new table plugin instance
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}

impl TablePlugin for MquireDiagnosticsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (String::from("time"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("location"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("level"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (String::from("type"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("message"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("mquire_diagnostics")
    }

    fn generate(&self, _constraints: &Constraints) -> Result<RowList> {
        let row_list = Logger::get_messages()
            .into_iter()
            .map(|entry| {
                BTreeMap::from([
                    (
                        "time".to_string(),
                        Some(ColumnValue::String(
                            entry
                                .time
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        )),
                    ),
                    (
                        "location".to_string(),
                        Some(ColumnValue::String(entry.location)),
                    ),
                    (
                        "type".to_string(),
                        Some(ColumnValue::String(entry.level.to_string())),
                    ),
                    (
                        "level".to_string(),
                        Some(ColumnValue::SignedInteger(entry.level as i64)),
                    ),
                    (
                        "message".to_string(),
                        Some(ColumnValue::String(entry.message)),
                    ),
                ])
            })
            .collect();

        Ok(row_list)
    }
}
