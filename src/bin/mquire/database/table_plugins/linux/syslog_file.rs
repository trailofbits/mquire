//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::sqlite::{
    error::Result,
    table_plugin::{ColumnDef, ColumnType, ColumnValue, Constraints, RowList, TablePlugin},
};

use mquire::operating_system::linux::operating_system::LinuxOperatingSystem;

use log::error;

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
    fn schema(&self) -> BTreeMap<String, ColumnDef> {
        BTreeMap::from([
            (
                String::from("file_virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("task_virtual_address"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("tgid"),
                ColumnDef::visible(ColumnType::SignedInteger),
            ),
            (
                String::from("data_source"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("region_start"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("region_end"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("timestamp"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("hostname"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("process"),
                ColumnDef::visible(ColumnType::String),
            ),
            (
                String::from("message"),
                ColumnDef::visible(ColumnType::String),
            ),
        ])
    }

    fn name(&self) -> String {
        String::from("syslog_file")
    }

    fn generate(&self, _constraints: &Constraints) -> Result<RowList> {
        let rows = self
            .system
            .iter_syslog_file_regions()?
            .filter_map(|r| {
                r.inspect_err(|e| error!("Failed to parse syslog file region: {e:?}"))
                    .ok()
            })
            .flat_map(|syslog| {
                let virtual_address = syslog.virtual_address;
                let task = syslog.task;
                let tgid = syslog.tgid;
                let data_source = syslog.data_source;

                syslog.region_list.into_iter().flat_map(move |region| {
                    let offset_range_start = region.offset_range.start;
                    let offset_range_end = region.offset_range.end;

                    region.lines.into_iter().map(move |line| {
                        let parsed = Self::parse_syslog_line(&line);

                        BTreeMap::from([
                            (
                                String::from("file_virtual_address"),
                                Some(ColumnValue::String(format!("{:?}", virtual_address))),
                            ),
                            (
                                String::from("task_virtual_address"),
                                Some(ColumnValue::String(format!("{:?}", task))),
                            ),
                            (
                                String::from("tgid"),
                                Some(ColumnValue::SignedInteger(tgid as i64)),
                            ),
                            (
                                String::from("data_source"),
                                Some(ColumnValue::String(data_source.as_str().to_string())),
                            ),
                            (
                                String::from("region_start"),
                                Some(ColumnValue::String(format!("{:?}", offset_range_start))),
                            ),
                            (
                                String::from("region_end"),
                                Some(ColumnValue::String(format!("{:?}", offset_range_end))),
                            ),
                            (
                                String::from("timestamp"),
                                Some(ColumnValue::String(parsed.timestamp)),
                            ),
                            (
                                String::from("hostname"),
                                Some(ColumnValue::String(parsed.hostname)),
                            ),
                            (
                                String::from("process"),
                                Some(ColumnValue::String(parsed.process)),
                            ),
                            (
                                String::from("message"),
                                Some(ColumnValue::String(parsed.message)),
                            ),
                        ])
                    })
                })
            })
            .collect();

        Ok(rows)
    }
}
