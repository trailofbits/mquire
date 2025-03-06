//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::PhysicalAddress;

/// Page size flag bit in the table entry
const PAGE_SIZE_FLAG: u64 = 0x80;

/// Address mask for normal sized pages
const NORMAL_PAGE_ADDRESS_MASK: u64 = 0x000FFFFFFFFFF000;

/// Address mask for huge 2MB pages
const HUGE_PAGE_2MB_ADDRESS_MASK: u64 = 0x000FFFFFFFE00000;

/// Address mask for huge 1GB pages
const HUGE_PAGE_1GB_ADDRESS_MASK: u64 = 0x000FFFFFC0000000;

/// Table type, either a PML4, PDPTE, PDE or PTE
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TableType {
    /// PML4 table entry
    Pml4,

    /// PDPT table entry
    Pdpt,

    /// PD table entry
    Pd,

    /// PT table entry
    Pt,
}

/// A table entry, either a PML4E, PDPTE, PDE or PTE
#[derive(Clone, Copy, Debug)]
pub struct TableEntry {
    /// True if the page is marked as present
    present: bool,

    /// The address component of the table entry
    address: u64,

    /// True if the page is a large page
    large_page: bool,
}

impl TableEntry {
    /// Create a new table entry from a u64 value
    pub fn new(table_type: TableType, value: u64) -> Self {
        let present = (value & 1) == 1;
        let large_page_bit = (value & PAGE_SIZE_FLAG) != 0;

        let address = match (table_type, large_page_bit) {
            (TableType::Pml4, false) => value & NORMAL_PAGE_ADDRESS_MASK,
            (TableType::Pml4, true) => value & NORMAL_PAGE_ADDRESS_MASK,

            (TableType::Pdpt, false) => value & NORMAL_PAGE_ADDRESS_MASK,
            (TableType::Pdpt, true) => value & HUGE_PAGE_1GB_ADDRESS_MASK,

            (TableType::Pd, false) => value & NORMAL_PAGE_ADDRESS_MASK,
            (TableType::Pd, true) => value & HUGE_PAGE_2MB_ADDRESS_MASK,

            (TableType::Pt, false) => value & NORMAL_PAGE_ADDRESS_MASK,
            (TableType::Pt, true) => value & NORMAL_PAGE_ADDRESS_MASK,
        };

        let large_page = match table_type {
            TableType::Pml4 => false,
            TableType::Pdpt => large_page_bit,
            TableType::Pd => large_page_bit,
            TableType::Pt => false,
        };

        Self {
            present,
            address,
            large_page,
        }
    }

    /// Returns true if the page is marked as present
    pub fn present(&self) -> bool {
        self.present
    }

    /// Returns the address component of the table entry
    pub fn address(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.address)
    }

    /// Retruns true if the page is a large page
    pub fn large_page(&self) -> bool {
        self.large_page
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pml4_table_entry() {
        let table_entry = TableEntry::new(TableType::Pml4, 0x0000000000001000);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000000001000)
        );
        assert!(!table_entry.present());
        assert!(!table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pml4, 0x0000000000001001);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000000001000)
        );
        assert!(table_entry.present());
        assert!(!table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pml4, 0x0000000000001080);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000000001000)
        );
        assert!(!table_entry.present());
        assert!(!table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pml4, 0x0000000000001081);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000000001000)
        );
        assert!(table_entry.present());
        assert!(!table_entry.large_page());
    }

    #[test]
    fn test_pdpt_table_entry() {
        let table_entry = TableEntry::new(TableType::Pdpt, 0x0000000040001000);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000040001000)
        );
        assert!(!table_entry.present());
        assert!(!table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pdpt, 0x0000000040001001);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000040001000)
        );
        assert!(table_entry.present());
        assert!(!table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pdpt, 0x0000000040001080);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000040000000)
        );
        assert!(!table_entry.present());
        assert!(table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pdpt, 0x0000000040001081);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000040000000)
        );
        assert!(table_entry.present());
        assert!(table_entry.large_page());
    }

    #[test]
    fn test_pd_table_entry() {
        let table_entry = TableEntry::new(TableType::Pd, 0x0000000000201000);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000000201000)
        );
        assert!(!table_entry.present());
        assert!(!table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pd, 0x0000000000201001);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000000201000)
        );
        assert!(table_entry.present());
        assert!(!table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pd, 0x0000000000201080);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000000200000)
        );
        assert!(!table_entry.present());
        assert!(table_entry.large_page());

        let table_entry = TableEntry::new(TableType::Pd, 0x0000000000201081);
        assert_eq!(
            table_entry.address(),
            PhysicalAddress::new(0x0000000000200000)
        );
        assert!(table_entry.present());
        assert!(table_entry.large_page());
    }
}
