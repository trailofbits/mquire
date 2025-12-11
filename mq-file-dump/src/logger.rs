//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::sync::OnceLock;

/// The global logger instance
static LOGGER: OnceLock<Logger> = OnceLock::new();

/// A simple logger that prints to stderr
#[derive(Default)]
pub struct Logger;

impl Logger {
    /// Initializes the global logger
    pub fn initialize() {
        log::set_logger(LOGGER.get_or_init(Logger::default)).unwrap();
        log::set_max_level(log::LevelFilter::Error);
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

        eprintln!("[{}] {}", record.level(), record.args());
    }

    fn flush(&self) {}
}
