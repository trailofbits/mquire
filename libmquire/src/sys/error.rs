//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::result;

use crate::memory::Error as MemoryError;

/// Error kinds for memory operations
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A memory error has occurred
    MemoryError,

    /// The memory is not mapped
    MemoryNotMapped,

    /// The operating system plugin has failed initialization
    OperatingSystemInitializationFailed,

    /// Invalid data encountered
    InvalidData,

    /// A type information error, such as an invalid type ID/type name
    TypeInformationError,

    /// Invalid offset
    InvalidOffset,

    /// The requested operation is not supported
    NotSupported,
}

/// Error type for memory operations
#[derive(Debug)]
pub struct Error {
    /// Error kind
    kind: ErrorKind,

    /// Error message
    message: String,
}

/// A result type for memory operations
pub type Result<T> = result::Result<T, Error>;

impl Error {
    /// Creates a new memory error
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

impl From<MemoryError> for Error {
    /// Converts a MemoryError into a system error
    fn from(error: MemoryError) -> Self {
        Error {
            kind: ErrorKind::MemoryError,
            message: format!("{:?}", error),
        }
    }
}
