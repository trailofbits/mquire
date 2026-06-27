//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::{Error, Result},
    table_plugin::{
        ColumnDef, ColumnType, ColumnValue, Constraints, OptionalColumnValue, RowList, TablePlugin,
    },
};

use mquire::{
    memory::virtual_address::VirtualAddress,
    operating_system::linux::{
        entities::task_ptrace_state::PtraceFlag, operating_system::LinuxOperatingSystem,
    },
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that displays the ptrace state of a given task
pub struct TaskPtraceFlagsTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl TaskPtraceFlagsTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }

    /// Parses the required 'task' constraint as a VirtualAddress
    fn parse_task_constraint(constraints: &Constraints) -> Result<Option<VirtualAddress>> {
        constraints
            .iter()
            .find_map(|constraint| {
                (constraint.column == "task").then(|| match &constraint.value {
                    ColumnValue::String(value) => value.parse().map_err(|_| {
                        Error::TablePlugin(format!(
                            "Invalid VirtualAddress format for 'task': {}",
                            value
                        ))
                    }),

                    other => Err(Error::TablePlugin(format!(
                        "Expected string for 'task', got {:?}",
                        other
                    ))),
                })
            })
            .transpose()
    }

    /// Builds a (task, name, value) row
    fn row(task: &str, name: &str, value: String) -> BTreeMap<String, OptionalColumnValue> {
        BTreeMap::from([
            (
                String::from("task"),
                Some(ColumnValue::String(task.to_string())),
            ),
            (
                String::from("name"),
                Some(ColumnValue::String(name.to_string())),
            ),
            (String::from("value"), Some(ColumnValue::String(value))),
        ])
    }
}

impl TablePlugin for TaskPtraceFlagsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (String::from("task"), ColumnDef::visible(ColumnType::String)),
            (String::from("name"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("value"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("task_ptrace_flags")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![String::from("task")]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let task_vaddr = Self::parse_task_constraint(constraints)?.ok_or_else(|| {
            Error::TablePlugin(
                "task_ptrace_flags requires a 'task' constraint (the task_struct virtual \
                 address); join it against tasks/processes, e.g. \
                 JOIN task_ptrace_flags f ON f.task = p.virtual_address"
                    .to_string(),
            )
        })?;

        let ptrace = match self.system.task_ptrace(task_vaddr) {
            Ok(ptrace) => ptrace,

            Err(error) => {
                error!("Failed to read ptrace for task {}: {:?}", task_vaddr, error);
                return Ok(Vec::new());
            }
        };

        let task = format!("{}", task_vaddr);
        let mut rows: RowList = Vec::new();

        for &flag in PtraceFlag::ALL {
            let value = String::from(if ptrace.flags.contains(&flag) {
                "1"
            } else {
                "0"
            });

            rows.push(Self::row(&task, flag.name(), value));
        }

        rows.push(Self::row(
            &task,
            "unused",
            format!("{:#010x}", ptrace.unused),
        ));

        rows.push(Self::row(&task, "raw", format!("{:#010x}", ptrace.raw)));
        Ok(rows)
    }
}
