//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{fmt, ops};

use crate::memory::{Error, ErrorKind, PhysicalAddress, Result};

/// A raw virtual address, either 32-bit or 64-bit
#[derive(Clone, Copy, PartialEq)]
pub enum RawVirtualAddress {
    /// A 32-bit unsigned integer
    U32(u32),

    /// A 64-bit unsigned integer
    U64(u64),
}

/// Prints the virtual address in hexadecimal format with leading zeroes
impl fmt::Debug for RawVirtualAddress {
    /// Formats the virtual address for debugging purposes
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RawVirtualAddress::U32(value) => {
                write!(f, "0x{:08x}", value,)
            }

            RawVirtualAddress::U64(value) => {
                write!(f, "0x{:16x}", value,)
            }
        }
    }
}

/// A virtual address, along with the required page table address
#[derive(Clone, Copy, PartialEq)]
pub struct VirtualAddress {
    /// The address of the table table used to for paging operations
    page_table: PhysicalAddress,

    /// The virtual address
    raw_virtual_address: RawVirtualAddress,
}

impl VirtualAddress {
    /// Creates a new virtual address
    pub fn new(
        page_table: PhysicalAddress,
        raw_virtual_address: RawVirtualAddress,
    ) -> VirtualAddress {
        Self {
            page_table,
            raw_virtual_address,
        }
    }

    /// Returns the address of the page table
    pub fn page_table(&self) -> PhysicalAddress {
        self.page_table
    }

    /// Returns the raw virtual address
    pub fn get(&self) -> RawVirtualAddress {
        self.raw_virtual_address
    }

    /// Returns true if this ptr is null
    pub fn is_null(&self) -> bool {
        match self.raw_virtual_address {
            RawVirtualAddress::U32(value) => value == 0,
            RawVirtualAddress::U64(value) => value == 0,
        }
    }
}

impl fmt::Debug for VirtualAddress {
    /// Formats the virtual address for debugging purposes
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "VirtualAddress {{ page_table: {:?}, address: {:?} }}",
            self.page_table, self.raw_virtual_address,
        )
    }
}

impl ops::Add<u32> for VirtualAddress {
    /// The output type of the addition operation
    type Output = VirtualAddress;

    /// Adds the specified u32 value to the virtual address
    fn add(self, rhs: u32) -> Self::Output {
        self + (rhs as u64)
    }
}

impl ops::Add<usize> for VirtualAddress {
    /// The output type of the addition operation
    type Output = VirtualAddress;

    /// Adds the specified usize value to the virtual address
    fn add(self, rhs: usize) -> Self::Output {
        self + (rhs as u64)
    }
}

impl ops::Add<u64> for VirtualAddress {
    /// The output type of the addition operation
    type Output = VirtualAddress;

    /// Adds the specified u64 value to the virtual address
    fn add(self, rhs: u64) -> Self::Output {
        let raw_virtual_address = match self.raw_virtual_address {
            RawVirtualAddress::U32(value) => RawVirtualAddress::U32(value.wrapping_add(rhs as u32)),
            RawVirtualAddress::U64(value) => RawVirtualAddress::U64(value.wrapping_add(rhs)),
        };

        VirtualAddress::new(self.page_table, raw_virtual_address)
    }
}

impl ops::Sub<u32> for VirtualAddress {
    /// The output type of the subtraction operation
    type Output = VirtualAddress;

    /// Subtracts the specified u32 value from the virtual address
    fn sub(self, rhs: u32) -> Self::Output {
        self - (rhs as u64)
    }
}

impl ops::Sub<usize> for VirtualAddress {
    /// The output type of the subtraction operation
    type Output = VirtualAddress;

    /// Subtracts the specified usize value from the virtual address
    fn sub(self, rhs: usize) -> Self::Output {
        self - (rhs as u64)
    }
}

impl ops::Sub<u64> for VirtualAddress {
    /// The output type of the addition operation
    type Output = VirtualAddress;

    /// Subtracts the specified u64 value from the virtual address
    fn sub(self, rhs: u64) -> Self::Output {
        let raw_virtual_address = match self.raw_virtual_address {
            RawVirtualAddress::U32(value) => RawVirtualAddress::U32(value.wrapping_sub(rhs as u32)),
            RawVirtualAddress::U64(value) => RawVirtualAddress::U64(value.wrapping_sub(rhs)),
        };

        VirtualAddress::new(self.page_table, raw_virtual_address)
    }
}

impl ops::Sub<VirtualAddress> for VirtualAddress {
    /// The output type of the subtraction operation
    type Output = Result<usize>;

    /// Subtracts one VirtualAddress value from the other
    fn sub(self, rhs: VirtualAddress) -> Self::Output {
        if self.page_table != rhs.page_table {
            return Err(Error::new(
                ErrorKind::InvalidAddressSpace,
                "The page tables are different",
            ));
        }

        let diff = match (self.raw_virtual_address, rhs.raw_virtual_address) {
            (RawVirtualAddress::U32(lhs), RawVirtualAddress::U32(rhs)) => {
                lhs.wrapping_sub(rhs) as usize
            }

            (RawVirtualAddress::U64(lhs), RawVirtualAddress::U64(rhs)) => {
                lhs.wrapping_sub(rhs) as usize
            }

            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidAddressSpace,
                    "The bitness settings are different",
                ))
            }
        };

        Ok(diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_address() {
        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U32(0x02));
        assert_eq!(virtual_address.page_table().get(), 0x01);
        assert_eq!(virtual_address.get(), RawVirtualAddress::U32(0x02));

        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U64(0x02));
        assert_eq!(virtual_address.page_table().get(), 0x01);
        assert_eq!(virtual_address.get(), RawVirtualAddress::U64(0x02));
    }

    #[test]
    fn test_virtual_address_u32_addition() {
        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U32(0x02));
        let result = virtual_address + 0x01u32;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U32(0x03));

        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U64(0x02));
        let result = virtual_address + 0x01u32;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U64(0x03));
    }

    #[test]
    fn test_virtual_address_usize_addition() {
        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U32(0x02));
        let result = virtual_address + 0x01usize;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U32(0x03));

        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U64(0x02));
        let result = virtual_address + 0x01usize;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U64(0x03));
    }

    #[test]
    fn test_virtual_address_u64_addition() {
        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U32(0x02));
        let result = virtual_address + 0x01u64;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U32(0x03));

        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U64(0x02));
        let result = virtual_address + 0x01u64;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U64(0x03));
    }

    #[test]
    fn test_virtual_address_u32_subtraction() {
        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U32(0x02));
        let result = virtual_address - 0x01u32;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U32(0x01));

        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U64(0x02));
        let result = virtual_address - 0x01u32;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U64(0x01));
    }

    #[test]
    fn test_virtual_address_usize_subtraction() {
        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U32(0x02));
        let result = virtual_address - 0x01usize;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U32(0x01));

        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U64(0x02));
        let result = virtual_address - 0x01usize;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U64(0x01));
    }

    #[test]
    fn test_virtual_address_u64_subtraction() {
        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U32(0x02));
        let result = virtual_address - 0x01u64;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U32(0x01));

        let virtual_address =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U64(0x02));
        let result = virtual_address - 0x01u64;
        assert_eq!(result.page_table().get(), 0x01);
        assert_eq!(result.get(), RawVirtualAddress::U64(0x01));
    }

    #[test]
    fn test_virtual_address_subtraction() {
        let virtual_address32 =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U32(0x02));
        let diff = (virtual_address32 - virtual_address32).unwrap();
        assert_eq!(diff, 0usize);

        let virtual_address64 =
            VirtualAddress::new(PhysicalAddress::new(0x01), RawVirtualAddress::U64(0x02));
        let diff = (virtual_address64 - virtual_address64).unwrap();
        assert_eq!(diff, 0usize);

        let error = (virtual_address32 - virtual_address64).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::InvalidAddressSpace);

        let error = (virtual_address32
            - VirtualAddress::new(PhysicalAddress::new(0x02), RawVirtualAddress::U32(0x02)))
        .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::InvalidAddressSpace);

        let error = (virtual_address64
            - VirtualAddress::new(PhysicalAddress::new(0x02), RawVirtualAddress::U64(0x02)))
        .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::InvalidAddressSpace);
    }
}
