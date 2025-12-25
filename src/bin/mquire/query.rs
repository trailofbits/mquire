//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    database::Database,
    utils::{display_query_data, display_table_schema},
};

use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Table,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "table" => Ok(OutputFormat::Table),
            _ => Err(format!("Invalid format: {}", s)),
        }
    }
}

pub fn execute_query(database: &Database, query: &str, format: OutputFormat) -> io::Result<()> {
    if query.eq_ignore_ascii_case(".tables") {
        let table_names = database.get_table_names();

        for table_name in table_names {
            print!("{table_name} ");
        }

        println!();
    } else if query.eq_ignore_ascii_case(".schema") {
        let table_names = database.get_table_names();

        for table_name in &table_names {
            if let Some(schema) = database.get_table_schema(table_name) {
                display_table_schema(table_name, &schema);
            }
        }
    } else if let Some(table_name) = query.strip_prefix(".schema ") {
        let table_name = table_name.trim();

        if let Some(schema) = database.get_table_schema(table_name) {
            display_table_schema(table_name, &schema);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Table '{}' not found", table_name),
            ));
        }
    } else {
        match format {
            OutputFormat::Json => {
                let json = database.json(query).map_err(|error| {
                    io::Error::other(format!("Failed to query the mquire database: {error:?}"))
                })?;

                println!("{json}");
            }

            OutputFormat::Table => {
                let query_data = database.query(query).map_err(|error| {
                    io::Error::other(format!("Failed to query the mquire database: {error:?}"))
                })?;

                display_query_data(&query_data)?;
            }
        }
    }

    Ok(())
}
