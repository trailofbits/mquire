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
        entities::kernel_module_mem_entry::{KernelModuleMemEntry, KernelModuleMemType},
        operating_system::LinuxOperatingSystem,
    },
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that exposes the `mem` entries of the `struct module` object
pub struct KernelModuleMemEntriesTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl KernelModuleMemEntriesTablePlugin {
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

    /// Renders a memory entry type as a stable, lowercase column value
    fn mem_type_str(mem_type: KernelModuleMemType) -> &'static str {
        match mem_type {
            KernelModuleMemType::Text => "text",
            KernelModuleMemType::Data => "data",
            KernelModuleMemType::RoData => "rodata",
            KernelModuleMemType::RoAfterInit => "ro_after_init",
            KernelModuleMemType::InitText => "init_text",
            KernelModuleMemType::InitData => "init_data",
            KernelModuleMemType::InitRoData => "init_rodata",
        }
    }

    /// Generates a row from a single memory entry
    fn generate_row_from_entry(
        kernel_module: &str,
        entry: &KernelModuleMemEntry,
    ) -> BTreeMap<String, OptionalColumnValue> {
        let start = entry.base.value().value();
        let end = start + entry.size as u64;

        BTreeMap::from([
            (
                String::from("kernel_module"),
                Some(ColumnValue::String(kernel_module.to_string())),
            ),
            (
                String::from("mem_type"),
                Some(ColumnValue::String(
                    Self::mem_type_str(entry.mem_type).to_string(),
                )),
            ),
            (
                String::from("start"),
                Some(ColumnValue::String(format!("{start:016x}"))),
            ),
            (
                String::from("end"),
                Some(ColumnValue::String(format!("{end:016x}"))),
            ),
            (
                String::from("size"),
                Some(ColumnValue::SignedInteger(entry.size as i64)),
            ),
        ])
    }
}

impl TablePlugin for KernelModuleMemEntriesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("kernel_module"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("mem_type"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("start"),
                ColumnDef::visible(ColumnType::String),
            ),
            (String::from("end"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("size"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("kernel_module_mem_entries")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![String::from("kernel_module")]
    }

    fn validate_constraints(&self, constraints: &Constraints) -> Result<()> {
        if !constraints.iter().any(|c| c.column == "kernel_module") {
            return Err(Error::TablePlugin(
                "kernel_module_mem_entries requires a 'kernel_module' constraint. \
                 Join against kernel_modules, e.g. `SELECT r.* FROM kernel_modules m \
                 JOIN kernel_module_mem_entries r ON r.kernel_module = m.virtual_address`."
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let module_vaddr = Self::parse_constraint_address(constraints, "kernel_module")?
            .ok_or_else(|| {
                Error::TablePlugin(
                    "kernel_module_mem_entries requires a 'kernel_module' constraint".to_string(),
                )
            })?;

        let kernel_module_str = format!("{}", module_vaddr);

        let iter = self
            .system
            .iter_kernel_module_mem_entries(module_vaddr)
            .map_err(|e| {
                Error::TablePlugin(format!(
                    "Failed to iterate memory entries for module at {}: {:?}",
                    module_vaddr, e
                ))
            })?;

        let row_list = iter
            .filter_map(|entry| {
                entry
                    .inspect_err(|e| error!("Failed to parse module memory entry: {e:?}"))
                    .ok()
            })
            .map(|entry| Self::generate_row_from_entry(&kernel_module_str, &entry))
            .collect();

        Ok(row_list)
    }
}
