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
        entities::memory_mapping::MemoryMapping, operating_system::LinuxOperatingSystem,
    },
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that lists task memory mappings
pub struct MemoryMappingsTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl MemoryMappingsTablePlugin {
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

    /// Generates a row from a memory mapping
    fn generate_row_from_mapping(mapping: &MemoryMapping) -> BTreeMap<String, OptionalColumnValue> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                Some(ColumnValue::String(format!("{}", mapping.virtual_address))),
            ),
            (
                String::from("task"),
                Some(ColumnValue::String(format!("{}", mapping.task))),
            ),
            (
                String::from("region_start"),
                Some(ColumnValue::String(format!("{}", mapping.region.start))),
            ),
            (
                String::from("region_end"),
                Some(ColumnValue::String(format!("{}", mapping.region.end))),
            ),
            (
                String::from("readable"),
                Some(ColumnValue::SignedInteger(if mapping.protection.read {
                    1
                } else {
                    0
                })),
            ),
            (
                String::from("writable"),
                Some(ColumnValue::SignedInteger(if mapping.protection.write {
                    1
                } else {
                    0
                })),
            ),
            (
                String::from("executable"),
                Some(ColumnValue::SignedInteger(if mapping.protection.execute {
                    1
                } else {
                    0
                })),
            ),
            (
                String::from("shared"),
                Some(ColumnValue::SignedInteger(if mapping.shared {
                    1
                } else {
                    0
                })),
            ),
            (
                String::from("file_path"),
                mapping
                    .file_backing
                    .as_ref()
                    .map(|fb| ColumnValue::String(fb.path.to_string_lossy().to_string())),
            ),
            (
                String::from("file_offset"),
                mapping
                    .file_backing
                    .as_ref()
                    .map(|fb| ColumnValue::String(format!("{}", fb.offset))),
            ),
        ])
    }

    /// Generates rows for memory mappings of a single task
    fn generate_for_single_task(
        system: &LinuxOperatingSystem,
        task: VirtualAddress,
    ) -> Result<RowList> {
        let mappings_iter = match system.iter_task_memory_mappings(task) {
            Ok(iter) => iter,

            Err(error) => {
                error!(
                    "Failed to iterate memory mappings for task {}: {:?}",
                    task, error
                );

                return Ok(Vec::new());
            }
        };

        let row_list = mappings_iter
            .filter_map(|r| {
                r.inspect_err(|e| error!("Failed to parse memory mapping: {e:?}"))
                    .ok()
            })
            .map(|mapping| Self::generate_row_from_mapping(&mapping))
            .collect();

        Ok(row_list)
    }

    /// Generates rows for memory mappings across all tasks
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

impl TablePlugin for MemoryMappingsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (String::from("task"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("region_start"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("region_end"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("readable"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("writable"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("executable"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("shared"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("file_path"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("file_offset"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("memory_mappings")
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
