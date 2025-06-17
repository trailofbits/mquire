//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{
    error::{Error, ErrorKind, Result},
    primitives::PhysicalAddress,
};

use std::ops::Range;

/// A trait used for the (physical) memory backing store
pub trait Readable {
    /// Reads data from the given physical address
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize>;

    /// Reads the exact amount of data from the given physical address
    fn read_exact(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<()> {
        let bytes_read = self.read(buffer, physical_address)?;

        if bytes_read != buffer.len() {
            Err(Error::new(
                ErrorKind::IOError,
                &format!("Failed to read more than {bytes_read} bytes"),
            ))
        } else {
            Ok(())
        }
    }

    /// Returns the size of the memory backing store
    fn len(&self) -> Result<u64>;

    /// Returns true if the memory backing store is empty
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Returns the list of mapped regions
    fn regions(&self) -> Result<Vec<Range<PhysicalAddress>>> {
        Ok(vec![Range {
            start: PhysicalAddress::default(),
            end: PhysicalAddress::new(self.len()?),
        }])
    }
}
