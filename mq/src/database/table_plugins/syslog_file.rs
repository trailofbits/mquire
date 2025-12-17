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

use mquire::operating_system::linux::operating_system::LinuxOperatingSystem;

use std::{collections::BTreeMap, sync::Arc};

/// A table plugin that outputs the system log file (/var/log/syslog)
pub struct SyslogFileTablePlugin {
    system: Arc<LinuxOperatingSystem>,
}

/// Parsed syslog line components
struct ParsedSyslogLine {
    timestamp: String,
    hostname: String,
    process: String,
    message: String,
}

impl SyslogFileTablePlugin {
    /// Creates a new table plugin instance
    pub fn new(system: Arc<LinuxOperatingSystem>) -> Arc<Self> {
        Arc::new(Self { system })
    }

    fn parse_syslog_line(line: &str) -> ParsedSyslogLine {
        let parts: Vec<&str> = line.splitn(4, ' ').collect();

        if parts.len() >= 4 {
            let timestamp = parts[0].to_string();
            let hostname = parts[1].to_string();
            let process = parts[2].to_string();
            let message = parts[3].to_string();

            ParsedSyslogLine {
                timestamp,
                hostname,
                process,
                message,
            }
        } else {
            ParsedSyslogLine {
                timestamp: String::new(),
                hostname: String::new(),
                process: String::new(),
                message: line.to_string(),
            }
        }
    }
}

impl TablePlugin for SyslogFileTablePlugin {
    fn schema(&self) -> BTreeMap<String, ColumnType> {
        let mut schema = BTreeMap::<String, ColumnType>::new();

        schema.insert(String::from("file_virtual_address"), ColumnType::String);
        schema.insert(String::from("task_virtual_address"), ColumnType::String);
        schema.insert(String::from("pid"), ColumnType::SignedInteger);
        schema.insert(String::from("data_source"), ColumnType::String);
        schema.insert(String::from("region_start"), ColumnType::String);
        schema.insert(String::from("region_end"), ColumnType::String);
        schema.insert(String::from("timestamp"), ColumnType::String);
        schema.insert(String::from("hostname"), ColumnType::String);
        schema.insert(String::from("process"), ColumnType::String);
        schema.insert(String::from("message"), ColumnType::String);

        schema
    }

    fn name(&self) -> String {
        String::from("syslog_file")
    }

    fn generate(&self) -> Result<RowList> {
        let syslog_list = self.system.get_syslog_file_regions()?;

        let mut rows = Vec::new();

        for syslog in syslog_list {
            for region in &syslog.region_list {
                for line in &region.lines {
                    let parsed = Self::parse_syslog_line(line);

                    let mut row = BTreeMap::<String, OptionalColumnValue>::new();

                    row.insert(
                        String::from("file_virtual_address"),
                        Some(ColumnValue::String(format!("{:?}", syslog.virtual_address))),
                    );

                    row.insert(
                        String::from("task_virtual_address"),
                        Some(ColumnValue::String(format!("{:?}", syslog.task))),
                    );

                    row.insert(
                        String::from("pid"),
                        Some(ColumnValue::SignedInteger(syslog.pid as i64)),
                    );

                    row.insert(
                        String::from("data_source"),
                        Some(ColumnValue::String(syslog.data_source.as_str().to_string())),
                    );

                    row.insert(
                        String::from("region_start"),
                        Some(ColumnValue::String(format!(
                            "{:?}",
                            region.offset_range.start
                        ))),
                    );

                    row.insert(
                        String::from("region_end"),
                        Some(ColumnValue::String(format!(
                            "{:?}",
                            region.offset_range.end
                        ))),
                    );

                    row.insert(
                        String::from("timestamp"),
                        Some(ColumnValue::String(parsed.timestamp)),
                    );

                    row.insert(
                        String::from("hostname"),
                        Some(ColumnValue::String(parsed.hostname)),
                    );

                    row.insert(
                        String::from("process"),
                        Some(ColumnValue::String(parsed.process)),
                    );

                    row.insert(
                        String::from("message"),
                        Some(ColumnValue::String(parsed.message)),
                    );

                    rows.push(row);
                }
            }
        }

        Ok(rows)
    }
}
