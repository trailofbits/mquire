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
        entities::task::{Task, TaskKind},
        operating_system::LinuxOperatingSystem,
    },
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
    fn parse_address_constraint(
        constraints: &Constraints,
        column_name: &str,
    ) -> Result<Option<VirtualAddress>> {
        if let Some(string) = Self::parse_string_constraint(constraints, column_name) {
            let virtual_address: VirtualAddress = string.parse().map_err(|error| {
                Error::TablePlugin(format!(
                    "Invalid VirtualAddress format for '{}': {}. {error:?}",
                    column_name, string
                ))
            })?;

            Ok(Some(virtual_address))
        } else {
            Ok(None)
        }
    }

    /// Attempts to parse a constraint value as a string
    fn parse_string_constraint(constraints: &Constraints, column_name: &str) -> Option<String> {
        constraints
            .iter()
            .find(|c| c.column == column_name)
            .and_then(|c| match &c.value {
                ColumnValue::String(s) => Some(s.clone()),
                _ => None,
            })
    }

    /// Generates a row from a task
    fn generate_row_from_task(
        task: &Task,
        root_task: Option<&str>,
        source: &str,
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
                String::from("type"),
                Some(ColumnValue::String(
                    match task.kind {
                        TaskKind::Kthread => "kthread",
                        TaskKind::ThreadGroupLeader => "thread_group_leader",
                        TaskKind::Thread => "thread",
                    }
                    .to_string(),
                )),
            ),
            (
                String::from("uid"),
                Some(ColumnValue::SignedInteger(task.uid as i64)),
            ),
            (
                String::from("gid"),
                Some(ColumnValue::SignedInteger(task.gid as i64)),
            ),
            (
                String::from("start_time"),
                task.start_time
                    .map(|t| ColumnValue::SignedInteger(t as i64)),
            ),
            (
                String::from("start_boottime"),
                task.start_boottime
                    .map(|t| ColumnValue::SignedInteger(t as i64)),
            ),
            (
                String::from("source"),
                Some(ColumnValue::String(source.to_string())),
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

        // Single task lookup doesn't have a source context
        Ok(vec![Self::generate_row_from_task(&task, None, "direct")])
    }

    /// Generates rows by enumerating tasks from the task list
    fn generate_task_list_rows(
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
            .map(|task| Self::generate_row_from_task(&task, Some(&root_task), "task_list"))
            .collect();

        Ok(row_list)
    }

    /// Generates rows by enumerating tasks from the PID namespace IDR
    fn generate_pid_ns_rows(system: &LinuxOperatingSystem) -> Result<RowList> {
        let iter = system.iter_pid_ns_tasks().map_err(|e| {
            Error::TablePlugin(format!("Failed to iterate PID namespace tasks: {:?}", e))
        })?;

        let row_list = iter
            .filter_map(|r| {
                r.inspect_err(|e| error!("Failed to parse task from PID namespace: {e:?}"))
                    .ok()
            })
            .map(|task| Self::generate_row_from_task(&task, None, "pid_ns"))
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
            (String::from("type"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("uid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("gid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("start_time"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("start_boottime"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("source"),
                ColumnDef::hidden(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("tasks")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![
            String::from("virtual_address"),
            String::from("root_task"),
            String::from("source"),
        ]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let virtual_address = Self::parse_address_constraint(constraints, "virtual_address")?;
        let root_task = Self::parse_address_constraint(constraints, "root_task")?;
        let source = Self::parse_string_constraint(constraints, "source");

        match (virtual_address, root_task, source.as_deref()) {
            // Direct task lookup by virtual address
            (Some(vaddr), None, None) => Self::generate_single_task_row(self.system.as_ref(), vaddr),

            // Implicit task_list source with custom root
            (None, Some(root_vaddr), None) => {
                Self::generate_task_list_rows(self.system.as_ref(), Some(root_vaddr))
            }

            // Explicit task_list source with custom root
            (None, Some(root_vaddr), Some("task_list")) => {
                Self::generate_task_list_rows(self.system.as_ref(), Some(root_vaddr))
            }

            // Task list enumeration with default root
            (None, None, Some("task_list")) => {
                Self::generate_task_list_rows(self.system.as_ref(), None)
            }

            // Combined enumeration from both task list and PID namespace (default)
            (None, None, None) => {
                let mut row_list = Self::generate_task_list_rows(self.system.as_ref(), None)?;
                let pid_ns_rows = Self::generate_pid_ns_rows(self.system.as_ref())?;
                row_list.extend(pid_ns_rows);

                Ok(row_list)
            }

            // PID namespace enumeration
            (None, None, Some("pid_ns")) => Self::generate_pid_ns_rows(self.system.as_ref()),

            //
            // Invalid combinations
            //

            (Some(_), Some(_), _) => Err(Error::TablePlugin(
                "Cannot specify both 'virtual_address' and 'root_task' constraints together. \
                 Use 'virtual_address' to query a single task, or 'root_task' to enumerate from a custom root."
                    .to_string(),
            )),

            (Some(_), _, Some(_)) => Err(Error::TablePlugin(
                "Cannot use 'source' constraint with 'virtual_address'. \
                 Use 'virtual_address' for direct task lookup, or 'source' for enumeration."
                    .to_string(),
            )),

            (None, Some(_), Some("pid_ns")) => Err(Error::TablePlugin(
                "Cannot use 'root_task' with source='pid_ns'. \
                 PID namespace enumeration does not support custom roots."
                    .to_string(),
            )),

            (_, _, Some(other)) => Err(Error::TablePlugin(format!(
                "Invalid source: '{}'. Valid sources are 'task_list' or 'pid_ns'.",
                other
            ))),
        }
    }
}
