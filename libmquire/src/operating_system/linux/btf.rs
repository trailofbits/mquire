//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{error::Error as MemoryError, primitives::PhysicalAddress, readable::Readable};

use btfparse::{
    Error as BTFParseError, ErrorKind as BTFParseErrorKind, Readable as BTFParseReadable,
    Result as BTFParseResult,
};

/// Makes the Snapshot object compatible with the btfparse library.
pub struct BtfparseReadableAdapter<'a> {
    readable: &'a dyn Readable,
    base_offset: u64,
}

impl<'a> BtfparseReadableAdapter<'a> {
    /// Creates a new BtfparseReadableAdapter object
    pub fn new(readable: &'a dyn Readable, base_offset: u64) -> Self {
        BtfparseReadableAdapter {
            readable,
            base_offset,
        }
    }
}

impl From<MemoryError> for BTFParseError {
    /// Converts a MemoryError into a BTFParseError
    fn from(error: MemoryError) -> Self {
        BTFParseError::new(BTFParseErrorKind::IOError, &format!("{:?}", error))
    }
}

impl<'a> BTFParseReadable for BtfparseReadableAdapter<'a> {
    /// Reads from the snapshot
    fn read(&self, offset: u64, buffer: &mut [u8]) -> BTFParseResult<()> {
        let physical_address = PhysicalAddress::new(self.base_offset + offset);

        self.readable
            .read(buffer, physical_address)
            .map_err(|memory_error| memory_error.into())
    }
}
