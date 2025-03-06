//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{io, result};

/// Error kinds for memory operations
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An IO error has occurred while accessing the lower memory backing store
    IOError,

    /// The operations could not be completed because the page tables are different
    InvalidAddressSpace,
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

impl From<io::Error> for Error {
    /// Converts an io::Error into a memory error
    fn from(error: io::Error) -> Self {
        Error {
            kind: ErrorKind::IOError,
            message: error.to_string(),
        }
    }
}
