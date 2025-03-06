//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::result;

/// Error kinds for database operations
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
}

/// Error type for database operations
#[derive(Debug)]
pub struct Error {
    /// Error kind
    kind: ErrorKind,

    /// Error message
    message: String,
}

/// A result type for database operations
pub type Result<T> = result::Result<T, Error>;

impl Error {
    /// Creates a new database error
    pub fn new(kind: ErrorKind, message: &str) -> Error {
        Error {
            kind,
            message: message.to_owned(),
        }
    }

    /// Returns the error kind
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Returns the error message
    pub fn message(&self) -> &str {
        &self.message
    }
}
