//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use {log::error, serde::Deserialize};

use std::path::PathBuf;

/// Default maximum number of diagnostic log entries to retain
const DEFAULT_MQUIRE_DIAGNOSTICS_MAX_ENTRIES: usize = 1000;

/// Returns the default value for `mquire_diagnostics_max_entries` (used by serde)
fn default_mquire_diagnostics_max_entries() -> usize {
    DEFAULT_MQUIRE_DIAGNOSTICS_MAX_ENTRIES
}

/// Top-level configuration
#[derive(Deserialize, Default)]
pub struct Config {
    /// Database settings
    #[serde(default)]
    pub database: DatabaseConfig,
}

/// Configuration for database-related settings
#[derive(Deserialize)]
pub struct DatabaseConfig {
    /// Maximum number of entries in the mquire_diagnostics table after initialization
    #[serde(default = "default_mquire_diagnostics_max_entries")]
    pub mquire_diagnostics_max_entries: usize,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            mquire_diagnostics_max_entries: default_mquire_diagnostics_max_entries(),
        }
    }
}

/// Returns the path to the configuration file
fn config_path() -> Option<PathBuf> {
    let home_dir = std::env::var("HOME").ok()?;

    Some(
        PathBuf::from(home_dir)
            .join(".config")
            .join("trailofbits")
            .join("mquire")
            .join("config.toml"),
    )
}

impl Config {
    /// Loads configuration from `$HOME/.config/trailofbits/mquire/config.toml`.
    /// Returns defaults if the file is missing or `$HOME` is unset.
    /// Prints a warning to stderr and returns defaults if the file exists but cannot be parsed.
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                error!(
                    "Failed to read config file {:?}: {}. Using defaults.",
                    path, e
                );
                return Self::default();
            }
        };

        match toml::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                error!(
                    "Failed to parse config file {:?}: {}. Using defaults.",
                    path, e
                );
                Self::default()
            }
        }
    }
}
