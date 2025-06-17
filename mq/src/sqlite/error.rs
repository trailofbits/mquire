//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use mquire::{core::error::Error as CoreError, memory::error::Error as MemoryError};

use std::result::Result as StandardResult;

/// Error kinds for architecture operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// The database file could not be created
    DatabaseCreationFailed,

    /// The table plugin name is not valid
    InvalidTablePluginName,

    /// The table plugin could not be registered
    TablePluginRegistrationError,

    /// The table plugin name is already in use
    DuplicatedTableName,

    /// The SQL statement was not valid
    InvalidSqlStatement,

    /// An error has occurred while a table plugin was generating its rows
    TablePluginError,

    /// Internal errors
    InternalError,

    /// An mquire core error
    CoreError,
}

/// Error type for architecture operations
#[derive(Debug)]
pub struct Error {
    /// Error kind.
    kind: ErrorKind,

    /// Error message.
    message: String,
}

/// A result type for architecture operations.
pub type Result<T> = StandardResult<T, Error>;

impl Error {
    /// Creates a new architecture error.
    pub fn new(kind: ErrorKind, message: &str) -> Error {
        Error {
            kind,
            message: message.to_owned(),
        }
    }

    /// Returns the error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<CoreError> for Error {
    /// Converts a CoreError into a database Error.
    fn from(memory_error: CoreError) -> Self {
        Self::new(
            ErrorKind::CoreError,
            &format!("Core error: {memory_error:?}"),
        )
    }
}

impl From<MemoryError> for Error {
    /// Converts a MemoryError into a database Error.
    fn from(memory_error: MemoryError) -> Self {
        Self::new(
            ErrorKind::CoreError,
            &format!("Memory error: {memory_error:?}"),
        )
    }
}
