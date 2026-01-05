//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    database::table_plugins::{
        common::{
            log_messages::LogMessagesTablePlugin, network_interfaces::NetworkInterfacesTablePlugin,
            os_version::OSVersionTablePlugin, system_info::SystemInfoTablePlugin,
        },
        linux::{
            boot_time::BootTimeTablePlugin, cgroups::CgroupsTablePlugin, dmesg::DmesgTablePlugin,
            kallsyms::KallsymsTablePlugin, kernel_modules::KernelModulesTablePlugin,
            memory_mappings::MemoryMappingsTablePlugin,
            network_connections::NetworkConnectionsTablePlugin, syslog_file::SyslogFileTablePlugin,
            task_open_files::TaskOpenFilesTablePlugin, tasks::TasksTablePlugin,
        },
    },
    sqlite::{
        database::Database as SqliteDatabase,
        error::{Error, Result},
        table_plugin::TablePlugin,
    },
    utils::{ArchitectureType, OperatingSystemType},
};

use mquire::{
    core::operating_system::OperatingSystem,
    operating_system::linux::operating_system::LinuxOperatingSystem,
};

use std::sync::Arc;

/// Factory function types for creating table plugins
enum TableFactory {
    /// Table that works with the OperatingSystem trait
    Common(fn(Arc<dyn OperatingSystem>) -> Arc<dyn TablePlugin>),

    /// Table that requires LinuxOperatingSystem
    Linux(fn(Arc<LinuxOperatingSystem>) -> Arc<dyn TablePlugin>),

    /// Table that requires no OS instance
    Standalone(fn() -> Arc<dyn TablePlugin>),
}

/// Table plugin metadata
struct TableMetadata {
    name: &'static str,
    required_arch: Option<ArchitectureType>,
    factory: TableFactory,
}

/// Generates the table registry
macro_rules! generate_table_registry {
    (
        $(
            $factory_type:ident, $arch:ident => {
                $(
                    $name:ident: $plugin:ty
                ),* $(,)?
            }
        ),* $(,)?
    ) => {
        const TABLE_REGISTRY: &[TableMetadata] = &[
            $(
                $(
                    TableMetadata {
                        name: stringify!($name),
                        required_arch: generate_table_registry!(@arch $arch),
                        factory: generate_table_registry!(@factory $factory_type, $plugin),
                    },
                )*
            )*
        ];
    };

    (@arch Common) => {
        None
    };

    (@arch $arch:ident) => {
        Some(ArchitectureType::$arch)
    };

    (@factory Common, $plugin:ty) => {
        TableFactory::Common(|sys| <$plugin>::new(sys))
    };

    (@factory Linux, $plugin:ty) => {
        TableFactory::Linux(|sys| <$plugin>::new(sys))
    };

    (@factory Standalone, $plugin:ty) => {
        TableFactory::Standalone(|| <$plugin>::new())
    };
}

// Central registry of all available tables with their requirements
generate_table_registry! {
    Common, Common => {
        os_version: OSVersionTablePlugin,
        system_info: SystemInfoTablePlugin,
        network_interfaces: NetworkInterfacesTablePlugin,
    },

    Standalone, Common => {
        log_messages: LogMessagesTablePlugin,
    },

    Linux, Common => {
        tasks: TasksTablePlugin,
        task_open_files: TaskOpenFilesTablePlugin,
        boot_time: BootTimeTablePlugin,
        cgroups: CgroupsTablePlugin,
        dmesg: DmesgTablePlugin,
        kallsyms: KallsymsTablePlugin,
        kernel_modules: KernelModulesTablePlugin,
        memory_mappings: MemoryMappingsTablePlugin,
        network_connections: NetworkConnectionsTablePlugin,
        syslog_file: SyslogFileTablePlugin,
    },
}

/// Checks if a table's architecture requirement is compatible with the specified architecture
fn is_compatible_arch(required: Option<ArchitectureType>, actual: ArchitectureType) -> bool {
    match required {
        None => true,
        Some(required) => required == actual,
    }
}

/// Checks if a table's factory is compatible with the specified OS
fn is_compatible_os(factory: &TableFactory, os_type: OperatingSystemType) -> bool {
    match factory {
        TableFactory::Common(_) | TableFactory::Standalone(_) => true,
        TableFactory::Linux(_) => os_type == OperatingSystemType::Linux,
    }
}

/// Collects all tables compatible with the specified OS and architecture
fn collect_tables_for(
    os_type: OperatingSystemType,
    arch_type: ArchitectureType,
) -> Vec<&'static TableMetadata> {
    TABLE_REGISTRY
        .iter()
        .filter(|table| {
            is_compatible_os(&table.factory, os_type)
                && is_compatible_arch(table.required_arch, arch_type)
        })
        .collect()
}

/// Registers all table plugins based on the operating system and architecture types
pub fn register_all_tables(
    os_type: OperatingSystemType,
    arch_type: ArchitectureType,
    sqlite_db: &mut SqliteDatabase,
    system: Arc<dyn OperatingSystem>,
) -> Result<()> {
    let tables = collect_tables_for(os_type, arch_type);

    for table_meta in tables {
        let plugin = match &table_meta.factory {
            TableFactory::Common(factory_fn) => factory_fn(system.clone()),

            TableFactory::Linux(factory_fn) => {
                let any_system = system.clone().as_any_arc();
                let linux_system = any_system.downcast::<LinuxOperatingSystem>().map_err(|_| {
                    Error::Internal(format!(
                        "Failed to downcast to LinuxOperatingSystem for table '{}'",
                        table_meta.name
                    ))
                })?;

                factory_fn(linux_system)
            }

            TableFactory::Standalone(factory_fn) => factory_fn(),
        };

        sqlite_db.register_table_plugin(plugin)?;
    }

    Ok(())
}
