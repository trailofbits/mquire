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
        entities::kernel_module::{KernelModule, KernelModuleState},
        operating_system::LinuxOperatingSystem,
    },
};

use log::error;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that exposes loaded kernel modules
pub struct KernelModulesTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

impl KernelModulesTablePlugin {
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

    /// Generates a row from a kernel module
    fn generate_row_from_module(
        module: &KernelModule,
        list_head: Option<&str>,
    ) -> BTreeMap<String, OptionalColumnValue> {
        let module_state = module.state.as_ref().map(|state| {
            ColumnValue::String(match state {
                KernelModuleState::Live => "live".to_string(),
                KernelModuleState::Coming => "coming".to_string(),
                KernelModuleState::Going => "going".to_string(),
                KernelModuleState::Unformed => "unformed".to_string(),
            })
        });

        let parameters = if module.parameter_list.is_empty() {
            None
        } else {
            let params_str = module
                .parameter_list
                .iter()
                .filter_map(|param| {
                    param.name.as_ref().map(|name| {
                        let perm = param
                            .permissions
                            .map(|p| format!("0o{:o}", p))
                            .unwrap_or_else(|| "?".to_string());

                        format!("{} (perm: {})", name, perm)
                    })
                })
                .collect::<Vec<_>>()
                .join(", ");

            if params_str.is_empty() {
                None
            } else {
                Some(params_str)
            }
        };

        BTreeMap::from([
            (
                String::from("virtual_address"),
                Some(ColumnValue::String(format!("{}", module.virtual_address))),
            ),
            (
                String::from("list_head"),
                list_head.map(|s| ColumnValue::String(s.to_string())),
            ),
            (
                String::from("name"),
                module.name.clone().map(ColumnValue::String),
            ),
            (String::from("state"), module_state),
            (
                String::from("version"),
                module.version.clone().map(ColumnValue::String),
            ),
            (
                String::from("src_version"),
                module.src_version.clone().map(ColumnValue::String),
            ),
            (
                String::from("taints"),
                module.taints.map(|v| ColumnValue::SignedInteger(v as i64)),
            ),
            (
                String::from("gpl_only_symbols"),
                module
                    .using_gpl_only_symbols
                    .map(|v| ColumnValue::SignedInteger(if v { 1 } else { 0 })),
            ),
            (
                String::from("parameters"),
                parameters.map(ColumnValue::String),
            ),
        ])
    }

    /// Generates a single row for a direct kernel module lookup
    fn generate_single_module_row(
        system: &LinuxOperatingSystem,
        vaddr: VirtualAddress,
    ) -> Result<RowList> {
        let module = system.kernel_module_at(vaddr).map_err(|e| {
            Error::TablePlugin(format!("Failed to get kernel module at {}: {:?}", vaddr, e))
        })?;

        Ok(vec![Self::generate_row_from_module(&module, None)])
    }

    /// Generates rows by enumerating kernel modules from a list head
    fn generate_enumerated_rows(
        system: &LinuxOperatingSystem,
        list_head: Option<VirtualAddress>,
    ) -> Result<RowList> {
        let iter = match list_head {
            Some(list_head_vaddr) => system.iter_kernel_modules_from(list_head_vaddr),
            None => system.iter_kernel_modules(),
        }
        .map_err(|e| Error::TablePlugin(format!("Failed to iterate kernel modules: {:?}", e)))?;

        let list_head_str = format!("{}", iter.list_head());
        let row_list = iter
            .filter_map(|module| {
                module
                    .inspect_err(|e| error!("Failed to parse kernel module: {e:?}"))
                    .ok()
            })
            .map(|module| Self::generate_row_from_module(&module, Some(&list_head_str)))
            .collect();

        Ok(row_list)
    }
}

impl TablePlugin for KernelModulesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("list_head"),
                ColumnDef::hidden(ColumnType::String),
            ),
            (String::from("name"), ColumnDef::visible(ColumnType::String)),
            (
                String::from("state"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("version"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("src_version"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("taints"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("gpl_only_symbols"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("parameters"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("kernel_modules")
    }

    fn generator_inputs(&self) -> Vec<String> {
        vec![String::from("virtual_address"), String::from("list_head")]
    }

    fn generate(&self, constraints: &Constraints) -> Result<RowList> {
        let virtual_address = Self::parse_constraint_address(constraints, "virtual_address")?;
        let list_head = Self::parse_constraint_address(constraints, "list_head")?;

        match (virtual_address, list_head) {
            (Some(vaddr), None) => Self::generate_single_module_row(self.system.as_ref(), vaddr),

            (None, Some(list_head_vaddr)) => {
                Self::generate_enumerated_rows(self.system.as_ref(), Some(list_head_vaddr))
            }

            (None, None) => Self::generate_enumerated_rows(self.system.as_ref(), None),

            (Some(_), Some(_)) => Err(Error::TablePlugin(
                "Cannot specify both 'virtual_address' and 'list_head' constraints together. \
                 Use 'virtual_address' to query a single module, or 'list_head' to enumerate from a custom list head."
                    .to_string(),
            )),
        }
    }
}
