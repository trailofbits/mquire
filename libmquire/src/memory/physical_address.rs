//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{cmp, fmt, ops};

/// A physical address
#[derive(Copy, Clone)]
pub struct PhysicalAddress(u64);

impl PhysicalAddress {
    /// Creates a new physical address
    pub fn new(address: u64) -> Self {
        Self(address)
    }

    /// Returns the raw physical address
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PhysicalAddress {
    /// Formats the physical address for debugging
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PhysicalAddress({:#08x})", self.0)
    }
}

impl ops::Add<u64> for PhysicalAddress {
    /// The output type of the addition operation
    type Output = PhysicalAddress;

    /// Adds the specified u64 value to the physical address
    fn add(self, rhs: u64) -> PhysicalAddress {
        PhysicalAddress::new(self.0 + rhs)
    }
}

impl ops::Sub<u64> for PhysicalAddress {
    /// The output type of the subtraction operation
    type Output = PhysicalAddress;

    /// Subtracts the specified u64 value from the physical address
    fn sub(self, rhs: u64) -> PhysicalAddress {
        PhysicalAddress::new(self.0 - rhs)
    }
}

impl cmp::PartialEq<PhysicalAddress> for PhysicalAddress {
    /// Returns true if the physical address is equal to the specified u64 value
    fn eq(&self, other: &PhysicalAddress) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_physical_address() {
        let physical_address = PhysicalAddress::new(0x1122334455667788);
        assert_eq!(physical_address.get(), 0x1122334455667788);
    }

    #[test]
    fn test_physical_address_add() {
        let physical_address = PhysicalAddress::new(0x1122334455667788);

        assert_eq!(
            physical_address + 1,
            PhysicalAddress::new(0x1122334455667789)
        );
    }

    #[test]
    fn test_physical_address_sub() {
        let physical_address = PhysicalAddress::new(0x1122334455667788);

        assert_eq!(
            physical_address - 1,
            PhysicalAddress::new(0x1122334455667787)
        );
    }
}
