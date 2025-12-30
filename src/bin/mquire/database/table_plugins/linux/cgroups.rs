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

/// A table plugin that lists the task cgroups
pub struct CgroupsTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl CgroupsTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TablePlugin for CgroupsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("task"), ColumnType::String);
        schema.insert(String::from("name"), ColumnType::SignedInteger);

        schema
    }

    fn name(&self) -> String {
        String::from("cgroups")
    }

    fn generate(&self) -> Result<RowList> {
        let mut row_list = RowList::new();

        for cgroup in self.system.get_cgroup_list()? {
            let mut row = BTreeMap::<String, OptionalColumnValue>::new();

            row.insert(
                String::from("task"),
                Some(ColumnValue::String(format!("{:?}", cgroup.task))),
            );

            row.insert(
                String::from("name"),
                Some(ColumnValue::String(format!("{:?}", cgroup.name))),
            );

            row_list.push(row);
        }

        Ok(row_list)
    }
}
