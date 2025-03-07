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

pub struct OSVersionTablePlugin<'a> {
    system: &'a System<'a>,
}

impl<'a> OSVersionTablePlugin<'a> {
    pub fn new(system: &'a System) -> Self {
        Self { system }
    }
}

impl TablePlugin for OSVersionTablePlugin<'_> {
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

    fn generate(&self) -> DatabaseResult<RowList> {
        let os_version = self.system.get_os_version().unwrap();

        let mut row = BTreeMap::<String, OptionalColumnValue>::new();
        row.insert(
            String::from("kernel_version"),
            Some(ColumnValue::String(os_version.kernel_version)),
        );

        row.insert(
            String::from("system_version"),
            Some(ColumnValue::String(os_version.system_version)),
        );

        row.insert(
            String::from("arch"),
            Some(ColumnValue::String(os_version.arch)),
        );

        Ok(vec![row])
    }
}
