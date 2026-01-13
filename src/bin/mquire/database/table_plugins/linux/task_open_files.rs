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
    operating_system::linux::{entities::file::File, operating_system::LinuxOperatingSystem},
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that lists task open files
pub struct TaskOpenFilesTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl TaskOpenFilesTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }

    /// Parses the optional 'task' constraint as a VirtualAddress
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

    /// Generates a row from an open file
    fn generate_row_from_file(file: &File) -> BTreeMap<String, OptionalColumnValue> {
        BTreeMap::from([
            (
                String::from("tgid"),
                Some(ColumnValue::SignedInteger(file.tgid as i64)),
            ),
            (
                String::from("fd"),
                Some(ColumnValue::SignedInteger(file.fd as i64)),
            ),
            (
                String::from("virtual_address"),
                Some(ColumnValue::String(format!("{}", file.virtual_address))),
            ),
            (
                String::from("task"),
                Some(ColumnValue::String(format!("{}", file.task))),
            ),
            (
                String::from("path"),
                Some(ColumnValue::String(file.path.clone())),
            ),
            (
                String::from("inode"),
                file.inode.map(|i| ColumnValue::SignedInteger(i as i64)),
            ),
        ])
    }

    /// Generates rows for open files of a single task
    fn generate_for_single_task(
        system: &LinuxOperatingSystem,
        task: VirtualAddress,
    ) -> Result<RowList> {
        let files_iter = match system.iter_task_open_files(task) {
            Ok(iter) => iter,

            Err(e) => {
                error!("Failed to iterate open files for task {}: {:?}", task, e);
                return Ok(Vec::new());
            }
        };

        let row_list = files_iter
            .filter_map(|r| {
                r.inspect_err(|e| error!("Failed to parse open file: {e:?}"))
                    .ok()
            })
            .map(|file| Self::generate_row_from_file(&file))
            .collect();

        Ok(row_list)
    }

    /// Generates rows for open files across all tasks
    fn generate_for_all_tasks(system: &LinuxOperatingSystem) -> Result<RowList> {
        let row_list: RowList = system
            .iter_tasks()
            .map_err(|error| Error::TablePlugin(format!("Failed to iterate tasks: {:?}", error)))?
            .filter_map(|task_result| match task_result {
                Ok(task) => match Self::generate_for_single_task(system, task.virtual_address) {
                    Ok(row_list) => Some(row_list),

                    Err(error) => {
                        error!("Failed to generate the task rows: {error:?}");
                        None
                    }
                },

                Err(error) => {
                    error!("Failed to parse the task: {error:?}");
                    None
                }
            })
            .flatten()
            .collect();

        Ok(row_list)
    }
}

impl TablePlugin for TaskOpenFilesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("tgid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("fd"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (String::from("task"), ColumnDef::visible(ColumnType::String)),
            (String::from("path"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("inode"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("task_open_files")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![String::from("task")]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        if let Some(task_vaddr) = Self::parse_task_constraint(constraints)? {
            Self::generate_for_single_task(self.system.as_ref(), task_vaddr)
        } else {
            Self::generate_for_all_tasks(self.system.as_ref())
        }
    }
}
