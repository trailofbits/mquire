//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{error::Result, primitives::PhysicalAddress, readable::Readable};

use memmap2::Mmap;

use std::{fs::File, path::Path, sync::Arc};

/// Represents a raw snapshot of the memory
pub struct RawSnapshot {
    /// Memory-mapped view of the snapshot file
    mmap: Mmap,
}

impl RawSnapshot {
    /// Creates a new raw snapshot from the given path
    pub fn new(file_path: &Path) -> Result<Arc<Self>> {
        let file = File::open(file_path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        Ok(Arc::new(RawSnapshot { mmap }))
    }
}

impl Readable for RawSnapshot {
    /// Reads the specified number of bytes from the given physical address
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
        let offset: u64 = physical_address.into();

        let start = offset as usize;
        let end = (start + buffer.len()).min(self.mmap.len());

        let bytes_to_read = end - start;
        if bytes_to_read > 0 {
            buffer[..bytes_to_read].copy_from_slice(&self.mmap[start..end]);
        }

        Ok(bytes_to_read)
    }

    /// Returns the size of the snapshot
    fn len(&self) -> Result<u64> {
        Ok(self.mmap.len() as u64)
    }
}
