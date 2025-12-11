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
        table_plugin::{ColumnType, ColumnValue, RowList, TablePlugin},
    },
};

use std::{collections::BTreeMap, rc::Rc};

/// A table plugin that exports the internal logger output
pub struct LogMessagesTablePlugin;

impl LogMessagesTablePlugin {
    /// Creates a new table plugin instance
    pub fn new() -> Rc<Self> {
        Rc::new(Self {})
    }
}

impl TablePlugin for LogMessagesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("time"), ColumnType::String);
        schema.insert(String::from("location"), ColumnType::String);
        schema.insert(String::from("level"), ColumnType::SignedInteger);
        schema.insert(String::from("type"), ColumnType::String);
        schema.insert(String::from("message"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("log_messages")
    }

    fn generate(&self) -> Result<RowList> {
        let mut row_list = RowList::new();

        for entry in Logger::get_messages() {
            let mut row = BTreeMap::new();
            row.insert(
                "time".to_string(),
                Some(ColumnValue::String(
                    entry
                        .time
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                )),
            );
            row.insert(
                "location".to_string(),
                Some(ColumnValue::String(entry.location.clone())),
            );

            row.insert(
                "type".to_string(),
                Some(ColumnValue::String(entry.level.to_string())),
            );

            row.insert(
                "level".to_string(),
                Some(ColumnValue::SignedInteger(entry.level as i64)),
            );

            row.insert(
                "message".to_string(),
                Some(ColumnValue::String(entry.message.clone())),
            );

            row_list.push(row);
        }

        Ok(row_list)
    }
}
