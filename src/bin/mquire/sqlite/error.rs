//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use mquire::{core::error::Error as CoreError, memory::error::Error as MemoryError};

use thiserror::Error;

/// Error type for SQLite database operations
#[derive(Debug, Error)]
pub enum Error {
    /// The database file could not be created
    #[error("Failed to create database")]
    DatabaseCreationFailed,

    /// The table plugin name is not valid
    #[error("Invalid table plugin name: {0}")]
    InvalidTablePluginName(String),

    /// The table plugin could not be registered
    #[error("Failed to register table plugin: {0}")]
    TablePluginRegistration(String),

    /// The table plugin name is already in use
    #[error("Table name already exists: {0}")]
    DuplicatedTableName(String),

    /// The SQL statement was not valid
    #[error("Invalid SQL statement: {0}")]
    InvalidSqlStatement(String),

    /// An error has occurred while a table plugin was generating its rows
    #[error("Table plugin error: {0}")]
    TablePlugin(String),

    /// Internal errors
    #[error("Internal error: {0}")]
    Internal(String),

    /// An mquire core error
    #[error("Core error: {0:?}")]
    CoreError(CoreError),

    /// An mquire memory error
    #[error("Memory error: {0:?}")]
    MemoryError(MemoryError),
}

impl From<CoreError> for Error {
    fn from(error: CoreError) -> Self {
        Error::CoreError(error)
    }
}

impl From<MemoryError> for Error {
    fn from(error: MemoryError) -> Self {
        Error::MemoryError(error)
    }
}

/// A result type for SQLite database operations.
pub type Result<T> = std::result::Result<T, Error>;
