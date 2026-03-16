//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    database::QueryData,
    table_plugin::{ColumnDef, ColumnType, ColumnValue},
};

use std::{fmt, io};

/// Represents the operating system type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingSystemType {
    /// Linux operating system
    Linux,
}

impl fmt::Display for OperatingSystemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperatingSystemType::Linux => write!(f, "linux"),
        }
    }
}

/// Represents the architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchitectureType {
    /// Intel/x86_64 architecture
    Intel,
}

impl fmt::Display for ArchitectureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchitectureType::Intel => write!(f, "intel"),
        }
    }
}

/// Displays the schema for the given table
pub fn display_table_schema(
    table_name: &str,
    schema: &std::collections::BTreeMap<String, ColumnDef>,
) {
    let columns: Vec<String> = schema
        .iter()
        .map(|(col_name, col_def)| {
            format!(
                "  {} {},",
                col_name,
                column_type_to_sql_type(&col_def.column_type)
            )
        })
        .collect();

    println!("CREATE TABLE {table_name}\n{}\n);", columns.join("\n"));
}

/// Displays the query output
pub fn display_query_data(query_data: &QueryData) -> Result<(), io::Error> {
    for row in &query_data.row_list {
        for column_name in &query_data.column_order {
            let opt_column_value = row
                .get(column_name)
                .ok_or(io::Error::other("Failed to acquire the column name"))?;

            let printable_column_value = match opt_column_value {
                None => String::from("<null>"),
                Some(column_value) => match column_value {
                    ColumnValue::Double(value) => value.to_string(),
                    ColumnValue::String(value) => value.to_string(),
                    ColumnValue::SignedInteger(value) => value.to_string(),
                },
            };

            print!("{column_name}:\"{printable_column_value}\" ");
        }

        println!();
    }

    Ok(())
}

/// Converts the given column type to a sqlite type
fn column_type_to_sql_type(column_type: &ColumnType) -> &str {
    match column_type {
        ColumnType::SignedInteger => "INTEGER",
        ColumnType::String => "TEXT",
        ColumnType::Double => "REAL",
    }
}
