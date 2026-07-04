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
        entities::ftrace_ops::FtraceOps, operating_system::LinuxOperatingSystem,
    },
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that returns `ftrace_ops` nodes
pub struct FtraceOpsTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl FtraceOpsTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }

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

    /// Generates a row from a single `ftrace_ops` node
    fn generate_row_from_ops(
        ops: &FtraceOps,
        start_vaddr: Option<&str>,
        end_vaddr: Option<&str>,
    ) -> BTreeMap<String, OptionalColumnValue> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                Some(ColumnValue::String(format!("{}", ops.virtual_address))),
            ),
            (
                String::from("start_vaddr"),
                start_vaddr.map(|s| ColumnValue::String(s.to_string())),
            ),
            (
                String::from("end_vaddr"),
                end_vaddr.map(|s| ColumnValue::String(s.to_string())),
            ),
            (
                String::from("func"),
                ops.func.map(|f| ColumnValue::String(format!("{}", f))),
            ),
            (
                // Zero-pad the hex callback address so we can use SQLite range comparisons
                String::from("func_addr"),
                ops.func
                    .map(|f| ColumnValue::String(format!("{:016x}", f.value().value()))),
            ),
            (
                String::from("flags"),
                ops.flags.map(|v| ColumnValue::SignedInteger(v as i64)),
            ),
        ])
    }

    /// Generates a single row for a direct `ftrace_ops` lookup
    fn generate_ftrace_ops_at(
        system: &LinuxOperatingSystem,
        vaddr: VirtualAddress,
    ) -> Result<RowList> {
        let ops = system.ftrace_ops_at(vaddr).map_err(|e| {
            Error::TablePlugin(format!("Failed to get ftrace_ops at {}: {:?}", vaddr, e))
        })?;

        Ok(vec![Self::generate_row_from_ops(&ops, None, None)])
    }

    /// Generates rows by enumerating `ftrace_ops` nodes from a starting node until either
    /// `end_vaddr` or null is found
    fn enumerate_ftrace_ops_from(
        system: &LinuxOperatingSystem,
        start_vaddr: Option<VirtualAddress>,
        end_vaddr: Option<VirtualAddress>,
    ) -> Result<RowList> {
        let iter = match start_vaddr {
            Some(start_vaddr) => system.iter_ftrace_ops_from(start_vaddr, end_vaddr),
            None => system.iter_ftrace_ops(),
        }
        .map_err(|e| Error::TablePlugin(format!("Failed to iterate ftrace_ops: {:?}", e)))?;

        let start_vaddr_str = format!("{}", iter.start_vaddr());
        let end_vaddr_str = end_vaddr.map(|v| format!("{}", v));

        let row_list = iter
            .filter_map(|ops| {
                ops.inspect_err(|e| error!("Failed to parse ftrace_ops: {e:?}"))
                    .ok()
            })
            .map(|ops| {
                Self::generate_row_from_ops(&ops, Some(&start_vaddr_str), end_vaddr_str.as_deref())
            })
            .collect();

        Ok(row_list)
    }
}

impl TablePlugin for FtraceOpsTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("start_vaddr"),
                ColumnDef::hidden(ColumnType::String),
            ),
            (
                String::from("end_vaddr"),
                ColumnDef::hidden(ColumnType::String),
            ),
            (String::from("func"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("func_addr"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("flags"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("ftrace_ops")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![
            String::from("virtual_address"),
            String::from("start_vaddr"),
            String::from("end_vaddr"),
        ]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let virtual_address = Self::parse_constraint_address(constraints, "virtual_address")?;

        let start_vaddr = Self::parse_constraint_address(constraints, "start_vaddr")?;
        let end_vaddr = Self::parse_constraint_address(constraints, "end_vaddr")?;

        if virtual_address.is_some() && (start_vaddr.is_some() || end_vaddr.is_some()) {
            return Err(Error::TablePlugin(
                "Cannot combine 'virtual_address' with 'start_vaddr'/'end_vaddr'. Use \
                 'virtual_address' to query a single ftrace_ops, or 'start_vaddr' (with an \
                 optional 'end_vaddr') to enumerate from a custom node."
                    .to_string(),
            ));
        }

        if end_vaddr.is_some() && start_vaddr.is_none() {
            return Err(Error::TablePlugin(
                "'end_vaddr' requires 'start_vaddr'; it bounds a walk started from 'start_vaddr'."
                    .to_string(),
            ));
        }

        match virtual_address {
            Some(vaddr) => Self::generate_ftrace_ops_at(self.system.as_ref(), vaddr),
            None => Self::enumerate_ftrace_ops_from(self.system.as_ref(), start_vaddr, end_vaddr),
        }
    }
}
