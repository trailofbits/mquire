//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::collections::BTreeMap;

use mquire::sys::System;

use sqlite::{
    ColumnType, ColumnValue, OptionalColumnValue, Result as DatabaseResult, RowList, TablePlugin,
};

pub struct SystemInfoTablePlugin<'a> {
    system: &'a System<'a>,
}

impl<'a> SystemInfoTablePlugin<'a> {
    pub fn new(system: &'a System) -> Self {
        Self { system }
    }
}

impl TablePlugin for SystemInfoTablePlugin<'_> {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("hostname"), ColumnType::String);
        schema.insert(String::from("domain"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("system_info")
    }

    fn generate(&self) -> DatabaseResult<RowList> {
        let system_information = self.system.get_system_information().unwrap();

        let mut row = BTreeMap::<String, OptionalColumnValue>::new();
        row.insert(
            String::from("hostname"),
            Some(ColumnValue::String(system_information.hostname)),
        );

        row.insert(
            String::from("domain"),
            system_information.domain.map(ColumnValue::String),
        );

        Ok(vec![row])
    }
}
