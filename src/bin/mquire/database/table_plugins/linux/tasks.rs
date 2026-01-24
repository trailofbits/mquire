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
    operating_system::linux::{entities::task::Task, operating_system::LinuxOperatingSystem},
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that lists active tasks
pub struct TasksTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl TasksTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }
}

impl TasksTablePlugin {
    /// Attempts to parse a constraint value as a VirtualAddress, returning an error if parsing fails
    fn parse_constraint_address(
        constraints: &Constraints,
        column_name: &str,
    ) -> Result<Option<VirtualAddress>> {
        let constraint = constraints.iter().find(|c| c.column == column_name);

        match constraint {
            None => Ok(None),

            Some(c) => match &c.value {
                ColumnValue::String(s) => match s.parse() {
                    Ok(addr) => Ok(Some(addr)),

                    Err(_) => Err(Error::TablePlugin(format!(
                        "Invalid VirtualAddress format for '{}': {}",
                        column_name, s
                    ))),
                },

                other => Err(Error::TablePlugin(format!(
                    "Expected string for '{}', got {:?}",
                    column_name, other
                ))),
            },
        }
    }

    /// Generates a row from a task
    fn generate_row_from_task(
        task: &Task,
        root_task: Option<&str>,
    ) -> BTreeMap<String, OptionalColumnValue> {
        let mut environment = String::new();
        for (key, value) in &task.environment_variable_map {
            environment.push_str(&format!("{key}={value}, "));
        }

        let environment = match environment.is_empty() {
            true => None,
            false => Some(environment),
        };

        BTreeMap::from([
            (
                String::from("virtual_address"),
                Some(ColumnValue::String(format!("{}", task.virtual_address))),
            ),
            (
                String::from("root_task"),
                root_task.map(|s| ColumnValue::String(s.to_string())),
            ),
            (
                String::from("page_table"),
                Some(ColumnValue::String(format!("{}", task.page_table))),
            ),
            (
                String::from("binary_path"),
                task.binary_path.clone().map(ColumnValue::String),
            ),
            (
                String::from("comm"),
                task.name.clone().map(ColumnValue::String),
            ),
            (
                String::from("command_line"),
                task.command_line.clone().map(ColumnValue::String),
            ),
            (
                String::from("environment"),
                environment.map(ColumnValue::String),
            ),
            (
                String::from("ppid"),
                task.ppid
                    .map(|parent_pid| ColumnValue::SignedInteger(parent_pid as i64)),
            ),
            (
                String::from("real_ppid"),
                task.real_ppid
                    .map(|parent_pid| ColumnValue::SignedInteger(parent_pid as i64)),
            ),
            (
                String::from("tgid"),
                Some(ColumnValue::SignedInteger(task.tgid as i64)),
            ),
            (
                String::from("pid"),
                Some(ColumnValue::SignedInteger(task.pid as i64)),
            ),
            (
                String::from("main_thread"),
                Some(ColumnValue::SignedInteger(if task.tgid == task.pid {
                    1
                } else {
                    0
                })),
            ),
            (
                String::from("uid"),
                Some(ColumnValue::SignedInteger(task.uid as i64)),
            ),
            (
                String::from("gid"),
                Some(ColumnValue::SignedInteger(task.gid as i64)),
            ),
        ])
    }

    /// Generates a single row for a direct task lookup
    fn generate_single_task_row(
        system: &LinuxOperatingSystem,
        vaddr: VirtualAddress,
    ) -> Result<RowList> {
        let task = match system.task_at(vaddr) {
            Ok(task) => task,

            Err(error) => {
                error!("Failed to get task at {}: {:?}", vaddr, error);
                return Ok(Vec::new());
            }
        };

        Ok(vec![Self::generate_row_from_task(&task, None)])
    }

    /// Generates rows by enumerating tasks from a root
    fn generate_enumerated_rows(
        system: &LinuxOperatingSystem,
        root: Option<VirtualAddress>,
    ) -> Result<RowList> {
        let iter = match root {
            Some(root_vaddr) => system.iter_tasks_from(root_vaddr),
            None => system.iter_tasks(),
        }
        .map_err(|e| Error::TablePlugin(format!("Failed to iterate tasks: {:?}", e)))?;

        let root_task = format!("{}", iter.root_task());
        let row_list = iter
            .filter_map(|r| {
                r.inspect_err(|e| error!("Failed to parse task: {e:?}"))
                    .ok()
            })
            .map(|task| Self::generate_row_from_task(&task, Some(&root_task)))
            .collect();

        Ok(row_list)
    }
}

impl TablePlugin for TasksTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("root_task"),
                ColumnDef::hidden(ColumnType::String),
            ),
            (
                String::from("page_table"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("binary_path"),
                ColumnDef::visible(ColumnType::String),
            ),
            (String::from("comm"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("command_line"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("environment"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("ppid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("real_ppid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("tgid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("pid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("main_thread"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("uid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("gid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("tasks")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![String::from("virtual_address"), String::from("root_task")]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let virtual_address = Self::parse_constraint_address(constraints, "virtual_address")?;
        let root_task = Self::parse_constraint_address(constraints, "root_task")?;

        match (virtual_address, root_task) {
            (Some(vaddr), None) => Self::generate_single_task_row(self.system.as_ref(), vaddr),

            (None, Some(root_vaddr)) => {
                Self::generate_enumerated_rows(self.system.as_ref(), Some(root_vaddr))
            }

            (None, None) => Self::generate_enumerated_rows(self.system.as_ref(), None),

            (Some(_), Some(_)) => Err(Error::TablePlugin(
                "Cannot specify both 'virtual_address' and 'root_task' constraints together. \
                 Use 'virtual_address' to query a single task, or 'root_task' to enumerate from a custom root."
                    .to_string(),
            )),
        }
    }
}
