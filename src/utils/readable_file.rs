//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{error::Result, primitives::PhysicalAddress, readable::Readable};

use std::fs::File;

#[cfg(unix)]
use std::os::unix::fs::FileExt;

#[cfg(windows)]
use std::os::windows::fs::FileExt;

/// Provides a convenient interface for reading from a Readable instance
pub struct ReadableFile<'a> {
    /// The Readable instance
    file: &'a mut File,
}

impl<'a> ReadableFile<'a> {
    /// Creates a new ReadableFile instance
    pub fn new(file: &'a mut File) -> Self {
        Self { file }
    }
}

impl<'a> Readable for ReadableFile<'a> {
    /// Reads data from the given physical address
    #[cfg(unix)]
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
        self.file
            .read_at(buffer, physical_address.into())
            .map_err(|error| error.into())
    }

    /// Reads data from the given physical address
    #[cfg(windows)]
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
        self.file
            .seek_read(buffer, physical_address.into())
            .map_err(|error| error.into())
    }

    /// Returns the size of the memory backing store
    fn len(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}
