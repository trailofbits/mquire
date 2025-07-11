//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::error::Error as MemoryError;

use std::result::Result as StandardResult;

/// Error kinds for core operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A memory error has occurred.
    MemoryError,

    /// The memory is not mapped.
    MemoryNotMapped,

    /// The operating system plugin has failed initialization.
    OperatingSystemInitializationFailed,

    /// Invalid data encountered.
    InvalidData,

    /// A type information error, such as an invalid type ID/type name.
    TypeInformationError,

    /// Invalid offset.
    InvalidOffset,

    /// The requested operation is not supported.
    NotSupported,

    /// Type traversal error.
    TypeTraversalError,

    /// Invalid page table entry.
    InvalidPageTableEntry,

    /// Failed to locate the root page directory.
    NoRootPageDirectoryFound,
}

/// Error type for core operations
#[derive(Debug)]
pub struct Error {
    /// Error kind.
    kind: ErrorKind,

    /// Error message.
    message: String,
}

/// A result type for core operations.
pub type Result<T> = StandardResult<T, Error>;

impl Error {
    /// Creates a new core error.
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

impl From<MemoryError> for Error {
    /// Converts a MemoryError into a core Error.
    fn from(memory_error: MemoryError) -> Self {
        Self::new(ErrorKind::MemoryError, &format!("{memory_error:?}"))
    }
}
