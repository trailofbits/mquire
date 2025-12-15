//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{error::Result, primitives::PhysicalAddress, readable::Readable};

use std::{fs::File, os::unix::fs::FileExt, path::Path, sync::Arc};

/// Represents a raw snapshot of the memory
pub struct RawSnapshot {
    /// The file containing the raw snapshot
    file: File,
}

impl RawSnapshot {
    /// Creates a new raw snapshot from the given path
    pub fn new(file_path: &Path) -> Result<Arc<Self>> {
        Ok(Arc::new(RawSnapshot {
            file: File::open(file_path)?,
        }))
    }
}

impl Readable for RawSnapshot {
    /// Reads the specified number of bytes from the given physical address
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
        Ok(self.file.read_at(buffer, physical_address.into())?)
    }

    /// Returns the size of the snapshot
    fn len(&self) -> Result<u64> {
        Ok(self.file.metadata().map(|metadata| metadata.len())?)
    }
}
