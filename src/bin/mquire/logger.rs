//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use chrono::Utc;

use std::sync::{Mutex, OnceLock};

/// The global logger instance
static LOGGER: OnceLock<Logger> = OnceLock::new();

/// Represents a single logged message
#[derive(Clone)]
pub struct LogEntry {
    /// Timestamp when the message was logged
    pub time: chrono::DateTime<Utc>,

    /// Log level (debug, info, warn, error)
    pub level: log::Level,

    /// Source location (file@line)
    pub location: String,

    /// The log message content
    pub message: String,
}

/// A logger that captures messages for later retrieval via the log_messages table
pub struct Logger {
    /// List of captured log entries
    log_entry_list: Mutex<Vec<LogEntry>>,

    /// Whether to also print log messages to stderr
    stderr_output: bool,
}

impl Logger {
    /// Initializes the global logger with the specified level
    pub fn initialize(debug: bool, stderr_output: bool) {
        log::set_logger(LOGGER.get_or_init(|| Logger {
            log_entry_list: Mutex::new(Vec::new()),
            stderr_output,
        }))
        .expect("Failed to initialize the logger");

        let level = if debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        };

        log::set_max_level(level);
    }

    /// Retrieves a vector containing all log entries collected by the logger.
    pub fn get_messages() -> Vec<LogEntry> {
        if let Some(logger) = LOGGER.get()
            && let Ok(logs) = logger.log_entry_list.lock()
        {
            return logs.clone();
        }

        Vec::new()
    }
}

impl log::Log for Logger {
    /// Returns whether logging is enabled for the given metadata
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    /// Logs a record by storing it in the internal list
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let path = record.file().unwrap_or("<unknown>").to_owned();
        let line = record.line().unwrap_or_default();
        let location = format!("{path}@{line}");

        let message = format!("{}", record.args());

        if self.stderr_output {
            eprintln!("[{}] {}: {}", record.level(), location, message);
        }

        if let Ok(mut log_entry_list) = self.log_entry_list.lock() {
            log_entry_list.push(LogEntry {
                time: chrono::Utc::now(),
                level: record.level(),
                location,
                message,
            });
        }
    }

    /// Flushes buffered records (no-op for this logger)
    fn flush(&self) {}
}
