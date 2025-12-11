//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{
    error::{Error, ErrorKind, Result},
    primitives::{PhysicalAddress, RawVirtualAddress},
};

use std::{
    cmp::Ordering,
    {fmt, ops},
};

/// A virtual address, containing the physical address for the root page table.
#[derive(Clone, Copy, Eq, Default)]
pub struct VirtualAddress {
    /// The physical address for the root page table.
    root_page_table: PhysicalAddress,

    /// The raw virtual address.
    raw_virtual_address: RawVirtualAddress,
}

impl VirtualAddress {
    /// Creates a new virtual address.
    pub const fn new(
        page_table: PhysicalAddress,
        raw_virtual_addr: RawVirtualAddress,
    ) -> VirtualAddress {
        VirtualAddress {
            root_page_table: page_table,
            raw_virtual_address: raw_virtual_addr,
        }
    }

    /// Returns the physical address of the root page table.
    pub fn root_page_table(&self) -> PhysicalAddress {
        self.root_page_table
    }

    /// Returns the raw virtual address value.
    pub fn value(&self) -> RawVirtualAddress {
        self.raw_virtual_address
    }

    /// Returns true if the raw virtual address is zero.
    pub fn is_null(&self) -> bool {
        self.raw_virtual_address.value() == 0
    }

    /// Returns the canonicalized version of this VirtualAddress
    pub fn canonicalized(&self) -> Self {
        VirtualAddress::new(
            self.root_page_table,
            self.raw_virtual_address.canonicalized(),
        )
    }

    /// Compares two virtual addresses.
    fn try_cmp(&self, rhs: &Self) -> Result<Ordering> {
        if self.root_page_table != rhs.root_page_table {
            return Err(Error::new(
                ErrorKind::InvalidAddressSpace,
                &format!("Page table mismatch in compare operation: {self:?}, {rhs:?}",),
            ));
        }

        Ok(self.raw_virtual_address.cmp(&rhs.raw_virtual_address))
    }
}

impl fmt::Display for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "VirtualAddress {{ root_page_table: {}, raw_virtual_address: {} }}",
            self.root_page_table, self.raw_virtual_address
        )
    }
}

impl fmt::Debug for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl ops::Sub<VirtualAddress> for VirtualAddress {
    type Output = Result<u64>;

    /// Subtracts two virtual address and get an offset.
    fn sub(self, rhs: VirtualAddress) -> Self::Output {
        if self.root_page_table != rhs.root_page_table {
            return Err(Error::new(
                ErrorKind::InvalidAddressSpace,
                &format!("Page table mismatch in subtraction operation: {self:?}, {rhs:?}",),
            ));
        }

        Ok(self.raw_virtual_address - rhs.raw_virtual_address)
    }
}

impl PartialEq for VirtualAddress {
    fn eq(&self, other: &Self) -> bool {
        self.try_cmp(other)
            .map(|o| o == Ordering::Equal)
            .unwrap_or(false)
    }
}

impl PartialOrd for VirtualAddress {
    #[allow(clippy::non_canonical_partial_ord_impl)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.try_cmp(other).ok()
    }
}

macro_rules! generate_arithmetic_ops {
    ("main", $($primitive_type:ty),*) => {
        $(
            impl ops::Add<$primitive_type> for VirtualAddress {
                type Output = VirtualAddress;

                fn add(self, rhs: $primitive_type) -> Self::Output {
                    Self::new(self.root_page_table, self.raw_virtual_address + rhs)
                }
            }

            impl ops::Sub<$primitive_type> for VirtualAddress {
                type Output = VirtualAddress;

                fn sub(self, rhs: $primitive_type) -> Self::Output {
                    Self::new(self.root_page_table, self.raw_virtual_address - rhs)
                }
            }
        )*
    };

    () => {
        generate_arithmetic_ops!("main", u8, u16, u32, u64, usize);
    };
}

generate_arithmetic_ops!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_value() {
        let addr = VirtualAddress::new(
            PhysicalAddress::new(0xAAAAAAAA),
            RawVirtualAddress::new(0xBBBBBBBB),
        );

        assert_eq!(addr.root_page_table(), PhysicalAddress::new(0xAAAAAAAA));
        assert_eq!(addr.value(), RawVirtualAddress::new(0xBBBBBBBB));
    }

    #[test]
    fn test_display_format() {
        let expected_output = format!(
            "{}{}",
            "VirtualAddress { root_page_table: PhysicalAddress(0x0000000000000000), ",
            "raw_virtual_address: RawVirtualAddress(0x0000000000000000) }"
        );

        let addr = VirtualAddress::new(PhysicalAddress::default(), RawVirtualAddress::default());
        assert_eq!(format!("{addr}"), expected_output);
    }

    #[test]
    fn test_debug_format() {
        let expected_output = format!(
            "{}{}",
            "VirtualAddress { root_page_table: PhysicalAddress(0x0000000000000000), ",
            "raw_virtual_address: RawVirtualAddress(0x0000000000000000) }"
        );

        let addr = VirtualAddress::new(PhysicalAddress::default(), RawVirtualAddress::default());
        assert_eq!(format!("{addr:?}"), expected_output);
    }

    #[test]
    fn test_equality_and_ordering() {
        let a = VirtualAddress::new(PhysicalAddress::default(), RawVirtualAddress::default());
        let b = VirtualAddress::new(PhysicalAddress::default(), RawVirtualAddress::new(1));

        assert!(a < b);
        assert!(b > a);
        assert!(a == a);

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));
        assert_eq!(a.partial_cmp(&a), Some(Ordering::Equal));

        let c = VirtualAddress::new(PhysicalAddress::new(1), RawVirtualAddress::new(1));

        assert!(a.partial_cmp(&c).is_none());
        assert!(c.partial_cmp(&a).is_none());
    }

    #[test]
    fn test_default() {
        let addr = VirtualAddress::default();
        assert_eq!(addr.root_page_table(), PhysicalAddress::default());
        assert_eq!(addr.value(), RawVirtualAddress::default());
    }

    #[test]
    fn test_is_null() {
        let null_addr = VirtualAddress::default();
        assert!(null_addr.is_null());

        let non_null_addr =
            VirtualAddress::new(PhysicalAddress::default(), RawVirtualAddress::new(1));

        assert!(!non_null_addr.is_null());
    }

    #[test]
    fn test_addition() {
        let addr = VirtualAddress::new(PhysicalAddress::default(), RawVirtualAddress::new(100));
        let result = addr + 1u64;

        assert_eq!(result.value(), RawVirtualAddress::new(101));
    }

    #[test]
    fn test_subtraction() {
        let addr = VirtualAddress::new(PhysicalAddress::default(), RawVirtualAddress::new(100));
        let result = addr - 1u64;

        assert_eq!(result.value(), RawVirtualAddress::new(99));
    }

    #[test]
    fn test_wrapping_add() {
        let addr =
            VirtualAddress::new(PhysicalAddress::default(), RawVirtualAddress::new(u64::MAX));
        let result = addr + 1u64;

        assert_eq!(result.value(), RawVirtualAddress::default());
    }

    #[test]
    fn test_wrapping_sub() {
        let addr = VirtualAddress::default();
        let result = addr - 1u64;

        assert_eq!(result.value(), RawVirtualAddress::new(u64::MAX));
    }
}
