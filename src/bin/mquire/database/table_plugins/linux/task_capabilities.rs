//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::{Error, Result},
    table_plugin::{ColumnDef, ColumnType, ColumnValue, Constraints, Row, RowList, TablePlugin},
};

use mquire::{
    memory::virtual_address::VirtualAddress,
    operating_system::linux::{
        entities::capabilities::{Capability, CapabilitySet},
        operating_system::LinuxOperatingSystem,
    },
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// The available capability set names
const CAPABILITY_SET_NAME_LIST: &[&str] = &[
    "effective",
    "permitted",
    "inheritable",
    "bounding",
    "ambient",
];

/// A table plugin that decodes a single task's capability sets into named flags
pub struct TaskCapabilitiesTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl TaskCapabilitiesTablePlugin {
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
}

impl TablePlugin for TaskCapabilitiesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        let mut schema = BTreeMap::from([
            (String::from("task"), ColumnDef::visible(ColumnType::String)),
            (String::from("name"), ColumnDef::visible(ColumnType::String)),
        ]);

        for capability_set_name in CAPABILITY_SET_NAME_LIST {
            schema.insert(
                String::from(*capability_set_name),
                ColumnDef::visible(ColumnType::SignedInteger),
            );
        }

        schema
    }

    fn name(&self) -> String {
        String::from("task_capabilities")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![String::from("task")]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let task_vaddr = Self::parse_task_constraint(constraints)?.ok_or_else(|| {
            Error::TablePlugin(
                "task_capabilities requires a 'task' constraint (the task_struct virtual \
                 address); join it against tasks/processes, e.g. \
                 JOIN task_capabilities c ON c.task = p.virtual_address"
                    .to_string(),
            )
        })?;

        let capabilities = match self.system.task_capabilities(task_vaddr) {
            Ok(capabilities) => capabilities,

            Err(error) => {
                error!(
                    "Failed to read capabilities for task {}: {:?}",
                    task_vaddr, error
                );

                return Ok(Vec::new());
            }
        };

        let capability_set_list: [Option<CapabilitySet>; 5] = [
            capabilities.effective.map(CapabilitySet::from_raw),
            capabilities.permitted.map(CapabilitySet::from_raw),
            capabilities.inheritable.map(CapabilitySet::from_raw),
            capabilities.bounding.map(CapabilitySet::from_raw),
            capabilities.ambient.map(CapabilitySet::from_raw),
        ];

        let task_vaddr = format!("{}", capabilities.task);
        let generate_base_row = |capability_name: String| -> Row {
            BTreeMap::from([
                (
                    String::from("task"),
                    Some(ColumnValue::String(task_vaddr.clone())),
                ),
                (
                    String::from("name"),
                    Some(ColumnValue::String(capability_name)),
                ),
            ])
        };

        let mut rows: RowList = Vec::new();

        for &capability in Capability::ALL {
            let mut row = generate_base_row(capability.name().to_string());

            for (column, decoded) in CAPABILITY_SET_NAME_LIST.iter().zip(&capability_set_list) {
                let cell = decoded.as_ref().map(|set| {
                    ColumnValue::SignedInteger(i64::from(set.flags.contains(&capability)))
                });

                row.insert(String::from(*column), cell);
            }

            rows.push(row);
        }

        let combined_unused_bits = capability_set_list
            .iter()
            .flatten()
            .fold(0u64, |accumulator, set| accumulator | set.unused);

        for bit in 0..u64::BITS {
            let mask = 1u64 << bit;
            if combined_unused_bits & mask == 0 {
                continue;
            }

            let mut row = generate_base_row(format!("CAP_UNKNOWN_BIT_{bit}"));

            for (column_name, capability_set) in
                CAPABILITY_SET_NAME_LIST.iter().zip(&capability_set_list)
            {
                let column_value = capability_set
                    .as_ref()
                    .map(|set| ColumnValue::SignedInteger(i64::from(set.unused & mask != 0)));

                row.insert(String::from(*column_name), column_value);
            }

            rows.push(row);
        }

        Ok(rows)
    }
}
