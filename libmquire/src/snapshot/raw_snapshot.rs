//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{fs::File, os::unix::fs::FileExt, path::Path};

use crate::memory::{PhysicalAddress, Readable, Result as MemoryResult};

/// Represents a raw snapshot of the memory
pub struct RawSnapshot {
    /// The file containing the raw snapshot
    file: File,
}

impl RawSnapshot {
    /// Creates a new raw snapshot from the given path
    pub fn new(file_path: &Path) -> MemoryResult<Self> {
        Ok(RawSnapshot {
            file: File::open(file_path)?,
        })
    }
}

impl Readable for RawSnapshot {
    /// Reads the specified number of bytes from the given physical address
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> MemoryResult<()> {
        Ok(self.file.read_exact_at(buffer, physical_address.get())?)
    }

    /// Returns the size of the snapshot
    fn len(&self) -> MemoryResult<u64> {
        Ok(self.file.metadata().map(|metadata| metadata.len())?)
    }

    /// Returns true if the snapshot is empty
    fn is_empty(&self) -> MemoryResult<bool> {
        self.len().map(|len| len == 0)
    }
}
