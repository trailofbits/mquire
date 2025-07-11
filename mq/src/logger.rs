//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{
    io::Write,
    sync::{Mutex, OnceLock},
};

use chrono::Utc;

/// The global logger instance
static LOGGER: OnceLock<Logger> = OnceLock::new();

/// Represents a single logged message
#[derive(Clone)]
pub struct LogEntry {
    pub time: chrono::DateTime<Utc>,
    pub level: log::Level,
    pub location: String,
    pub message: String,
}

/// A logger that saves messages and optionally outputs to stderr
pub struct Logger {
    log_entry_list: Mutex<Vec<LogEntry>>,
    enable_stderr_logging: bool,
}

impl Logger {
    /// Creates a new logger instance
    fn new(enable_stderr_logging: bool) -> Self {
        Self {
            log_entry_list: Mutex::new(Vec::new()),
            enable_stderr_logging,
        }
    }

    /// Initializes the global logger
    pub fn initialize(enable_stderr_logging: bool) {
        log::set_logger(LOGGER.get_or_init(|| Logger::new(enable_stderr_logging))).unwrap();

        let max_level = if enable_stderr_logging {
            log::LevelFilter::Error
        } else {
            log::LevelFilter::Debug
        };

        log::set_max_level(max_level);
    }

    /// Retrieves a vector containing all log entries collected by the logger.
    pub fn get_messages() -> Vec<LogEntry> {
        if let Some(logger) = LOGGER.get() {
            if let Ok(logs) = logger.log_entry_list.lock() {
                return logs.clone();
            }
        }

        Vec::new()
    }
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let path = record.file().unwrap_or("<unknown>").to_owned();
        let line = record.line().unwrap_or_default();
        let location = format!("{path}@{line}");

        if self.enable_stderr_logging {
            eprintln!(
                "{} {} [{}] {}",
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                record.level(),
                location,
                record.args()
            );
        }

        if let Ok(mut log_entry_list) = self.log_entry_list.lock() {
            log_entry_list.push(LogEntry {
                time: chrono::Utc::now(),
                level: record.level(),
                location,
                message: format!("{}", record.args()),
            });
        }
    }

    fn flush(&self) {
        if self.enable_stderr_logging {
            let _ = std::io::stderr().flush();
        }
    }
}
