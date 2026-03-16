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

/// Tracks the entry budget state after initialization
struct BudgetState {
    /// Maximum total entries allowed
    max_entries: usize,

    /// Cumulative count of evicted entries
    evicted_count: usize,
}

/// A logger that captures messages for later retrieval via the mquire_diagnostics table
pub struct Logger {
    /// List of captured log entries
    entries: Mutex<Vec<LogEntry>>,

    /// Whether to also print log messages to stderr
    stderr_output: bool,

    /// Entry budget, None means unbounded
    budget: Mutex<Option<BudgetState>>,
}

impl Logger {
    /// Initializes the global logger with the specified level
    pub fn initialize(debug: bool, stderr_output: bool) {
        log::set_logger(LOGGER.get_or_init(|| Logger {
            entries: Mutex::new(Vec::new()),
            stderr_output,
            budget: Mutex::new(None),
        }))
        .expect("Failed to initialize the logger");

        let level = if debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        };

        log::set_max_level(level);
    }

    /// Sets the entry budget. No eviction happens immediately, it will start
    /// on the next `log()` call that exceeds the limit.
    /// This is used to preserve all initialization messages until new entries
    /// push the total over budget.
    pub fn set_entry_budget(max_entries: usize) {
        let Some(logger) = LOGGER.get() else {
            return;
        };

        if let Ok(mut budget) = logger.budget.lock() {
            *budget = Some(BudgetState {
                max_entries,
                evicted_count: 0,
            });
        }
    }

    /// Retrieves all log entries. If entries have been evicted, a synthetic
    /// service message is prepended to indicate how many were removed.
    pub fn get_messages() -> Vec<LogEntry> {
        let Some(logger) = LOGGER.get() else {
            return Vec::new();
        };

        let Ok(entries) = logger.entries.lock() else {
            return Vec::new();
        };

        let budget = logger.budget.lock().ok();
        let budget_ref = budget.as_ref().and_then(|b| b.as_ref());

        Self::collect_messages(&entries, budget_ref)
    }

    /// Builds the message list from entries and optional budget state.
    /// Prepends a synthetic service message if entries have been evicted.
    fn collect_messages(entries: &[LogEntry], budget: Option<&BudgetState>) -> Vec<LogEntry> {
        let mut result = Vec::with_capacity(entries.len() + 1);

        if let Some(state) = budget
            && state.evicted_count > 0
        {
            result.push(LogEntry {
                time: chrono::Utc::now(),
                level: log::Level::Warn,
                location: String::from("mquire::logger"),
                message: format!(
                    "{} older diagnostic entries have been removed (budget: {})",
                    state.evicted_count, state.max_entries
                ),
            });
        }

        result.extend_from_slice(entries);
        result
    }

    /// Enforces the entry budget by evicting the oldest entries from the front.
    /// Must be called while holding the entries lock.
    fn enforce_budget(entries: &mut Vec<LogEntry>, budget: &mut BudgetState) {
        if entries.len() <= budget.max_entries {
            return;
        }

        let excess = entries.len() - budget.max_entries;
        entries.drain(0..excess);
        budget.evicted_count += excess;
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

        if let Ok(mut entries) = self.entries.lock() {
            entries.push(LogEntry {
                time: chrono::Utc::now(),
                level: record.level(),
                location,
                message,
            });

            if let Ok(mut budget) = self.budget.lock()
                && let Some(state) = budget.as_mut()
            {
                Self::enforce_budget(&mut entries, state);
            }
        }
    }

    /// Flushes buffered records (no-op for this logger)
    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(msg: &str) -> LogEntry {
        LogEntry {
            time: chrono::Utc::now(),
            level: log::Level::Info,
            location: String::from("test@0"),
            message: String::from(msg),
        }
    }

    fn make_entries(count: usize) -> Vec<LogEntry> {
        (0..count).map(|i| make_entry(&format!("msg{i}"))).collect()
    }

    #[test]
    fn test_enforce_budget_no_eviction() {
        let mut entries = make_entries(3);
        let mut budget = BudgetState {
            max_entries: 5,
            evicted_count: 0,
        };

        Logger::enforce_budget(&mut entries, &mut budget);

        assert_eq!(entries.len(), 3);
        assert_eq!(budget.evicted_count, 0);
    }

    #[test]
    fn test_enforce_budget_at_capacity() {
        let mut entries = make_entries(5);
        let mut budget = BudgetState {
            max_entries: 5,
            evicted_count: 0,
        };

        Logger::enforce_budget(&mut entries, &mut budget);

        assert_eq!(entries.len(), 5);
        assert_eq!(budget.evicted_count, 0);
    }

    #[test]
    fn test_enforce_budget_evicts_oldest() {
        let mut entries = make_entries(7);
        let mut budget = BudgetState {
            max_entries: 5,
            evicted_count: 0,
        };

        Logger::enforce_budget(&mut entries, &mut budget);

        assert_eq!(entries.len(), 5);
        assert_eq!(budget.evicted_count, 2);
        assert_eq!(entries[0].message, "msg2");
        assert_eq!(entries[4].message, "msg6");
    }

    #[test]
    fn test_enforce_budget_cumulative_eviction() {
        let mut entries = make_entries(7);
        let mut budget = BudgetState {
            max_entries: 5,
            evicted_count: 0,
        };

        Logger::enforce_budget(&mut entries, &mut budget);
        assert_eq!(budget.evicted_count, 2);

        // Add 3 more, enforce again
        entries.extend(make_entries(3).into_iter().enumerate().map(|(i, mut e)| {
            e.message = format!("new{i}");
            e
        }));

        Logger::enforce_budget(&mut entries, &mut budget);

        assert_eq!(entries.len(), 5);
        assert_eq!(budget.evicted_count, 5);
        assert_eq!(entries[0].message, "msg5");
    }

    #[test]
    fn test_enforce_budget_evicts_all_but_budget() {
        let mut entries = make_entries(10);
        let mut budget = BudgetState {
            max_entries: 1,
            evicted_count: 0,
        };

        Logger::enforce_budget(&mut entries, &mut budget);

        assert_eq!(entries.len(), 1);
        assert_eq!(budget.evicted_count, 9);
        assert_eq!(entries[0].message, "msg9");
    }

    #[test]
    fn test_collect_messages_no_budget() {
        let entries = make_entries(3);

        let result = Logger::collect_messages(&entries, None);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].message, "msg0");
    }

    #[test]
    fn test_collect_messages_budget_no_eviction() {
        let entries = make_entries(3);
        let budget = BudgetState {
            max_entries: 5,
            evicted_count: 0,
        };

        let result = Logger::collect_messages(&entries, Some(&budget));

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].message, "msg0");
    }

    #[test]
    fn test_collect_messages_with_eviction() {
        let entries = make_entries(3);
        let budget = BudgetState {
            max_entries: 5,
            evicted_count: 10,
        };

        let result = Logger::collect_messages(&entries, Some(&budget));

        assert_eq!(result.len(), 4);
        assert_eq!(result[0].level, log::Level::Warn);
        assert_eq!(result[0].location, "mquire::logger");
        assert_eq!(result[1].message, "msg0");
        assert_eq!(result[3].message, "msg2");
    }

    #[test]
    fn test_collect_messages_service_message_content() {
        let entries = make_entries(1);
        let budget = BudgetState {
            max_entries: 1000,
            evicted_count: 42,
        };

        let result = Logger::collect_messages(&entries, Some(&budget));

        assert_eq!(
            result[0].message,
            "42 older diagnostic entries have been removed (budget: 1000)"
        );
    }
}
