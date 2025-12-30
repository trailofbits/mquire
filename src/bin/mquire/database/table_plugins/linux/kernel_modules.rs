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

use mquire::operating_system::linux::{
    entities::kernel_module::KernelModuleState, operating_system::LinuxOperatingSystem,
};

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
}

impl TablePlugin for KernelModulesTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("virtual_address"), ColumnType::String);
        schema.insert(String::from("name"), ColumnType::String);
        schema.insert(String::from("state"), ColumnType::String);
        schema.insert(String::from("version"), ColumnType::String);
        schema.insert(String::from("src_version"), ColumnType::String);
        schema.insert(String::from("taints"), ColumnType::SignedInteger);
        schema.insert(String::from("gpl_only_symbols"), ColumnType::SignedInteger);
        schema.insert(String::from("parameters"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("kernel_modules")
    }

    fn generate(&self) -> Result<RowList> {
        let kernel_modules = match self.system.get_kernel_module_list() {
            Ok(modules) => modules,
            Err(_) => return Ok(RowList::new()),
        };

        let row_list: RowList = kernel_modules
            .into_iter()
            .map(|module| {
                let mut row = BTreeMap::<String, OptionalColumnValue>::new();

                row.insert(
                    String::from("virtual_address"),
                    Some(ColumnValue::String(format!("{}", module.virtual_address))),
                );

                row.insert(String::from("name"), module.name.map(ColumnValue::String));

                row.insert(
                    String::from("state"),
                    module.state.map(|s| {
                        ColumnValue::String(match s {
                            KernelModuleState::Live => "live".to_string(),
                            KernelModuleState::Coming => "coming".to_string(),
                            KernelModuleState::Going => "going".to_string(),
                            KernelModuleState::Unformed => "unformed".to_string(),
                        })
                    }),
                );

                row.insert(
                    String::from("version"),
                    module.version.map(ColumnValue::String),
                );

                row.insert(
                    String::from("src_version"),
                    module.src_version.map(ColumnValue::String),
                );

                row.insert(
                    String::from("taints"),
                    module.taints.map(|v| ColumnValue::SignedInteger(v as i64)),
                );

                row.insert(
                    String::from("gpl_only_symbols"),
                    module
                        .using_gpl_only_symbols
                        .map(|v| ColumnValue::SignedInteger(if v { 1 } else { 0 })),
                );

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

                row.insert(
                    String::from("parameters"),
                    parameters.map(ColumnValue::String),
                );

                row
            })
            .collect();

        Ok(row_list)
    }
}
