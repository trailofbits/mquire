//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{PhysicalAddress, Result};

/// A trait used for the (physical) memory backing store
pub trait Readable {
    /// Reads data from the given physical address
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<()>;

    /// Returns the size of the memory backing store
    fn len(&self) -> Result<u64>;

    /// Returns true if the memory backing store is empty
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}
