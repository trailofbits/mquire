//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::core::error::Result;

/// "Present" flag.
const FLAG_PRESENT: u64 = 0x01;

/// "Page Size" flag.
const FLAG_PAGE_SIZE: u64 = 0x80;

/// Mask for the page table entry target.
const MASK_PAGE_TABLE_ENTRY_TARGET: u64 = 0x000FFFFFFFFFF000;

/// Mask for the 1GB page physical address.
const MASK_1GB_PAGE_PHYSICAL_ADDRESS: u64 = 0x000FFFFFC0000000;

/// Mask for the 2MB page physical address.
const MASK_2MB_PAGE_PHYSICAL_ADDRESS: u64 = 0x000FFFFFFFE00000;

/// Mask for the 4KB page physical address.
const MASK_4KB_PAGE_PHYSICAL_ADDRESS: u64 = 0x000FFFFFFFFFF000;

/// 1GB page size.
const SIZE_1GB_PAGE: u64 = 1024 * 1024 * 1024;

/// 2MB page size.
const SIZE_2MB_PAGE: u64 = 2 * 1024 * 1024;

/// 4KB page size.
const SIZE_4KB_PAGE: u64 = 4 * 1024;

/// PML4 index shift.
const SHIFT_PML4_INDEX: u64 = 39;

/// PDPT index shift.
const SHIFT_PDPT_INDEX: u64 = 30;

/// PD index shift.
const SHIFT_PD_INDEX: u64 = 21;

/// PT index shift.
const SHIFT_PT_INDEX: u64 = 12;

/// Mask for the page table index.
const MASK_PAGE_TABLE_INDEX: u64 = 0x1FF;

/// Mask for the PDPT page offset.
const MASK_PDPT_PAGE_OFFSET: u64 = 0x000000003FFFFFFF;

/// Mask for the PD page offset.
const MASK_PD_PAGE_OFFSET: u64 = 0x00000000001FFFFF;

/// Mask for the PT page offset.
const MASK_PT_PAGE_OFFSET: u64 = 0x0000000000000FFF;

/// The page table level.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PageTableLevel {
    /// Page Map Level 4.
    Pml4,

    /// Page Directory Pointer Table.
    Pdpt,

    /// Page Directory.
    Pd,

    /// Page Table.
    Pt,
}

/// A section of a page.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PageSection {
    /// The page offset within the section.
    pub offset: u64,

    /// The size of the section.
    pub size: u64,
}

/// A virtual address component.
#[derive(Clone, Copy, Debug)]
pub struct VirtualAddressComponent {
    /// The page table index.
    pub page_table_index: usize,

    /// The page section, if applicable
    pub page_section: Option<PageSection>,
}

/// A decomposed virtual address.
#[derive(Clone, Copy, Debug)]
pub struct DecomposedVirtualAddress {
    /// The PML4 component of the virtual address.
    pub pml4: VirtualAddressComponent,

    /// The PDPT component of the virtual address.
    pub pdpt: VirtualAddressComponent,

    /// The PD component of the virtual address.
    pub pd: VirtualAddressComponent,

    /// The PT component of the virtual address.
    pub pt: VirtualAddressComponent,
}

/// A memory page.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Page {
    /// The physical address of the page.
    pub physical_address: u64,

    /// True if the page is present in memory.
    pub present: bool,

    /// The size of the page.
    pub size: u64,
}

/// A page directory.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PageDirectory {
    /// The physical address of the page.
    pub physical_address: u64,

    /// True if the page is present in memory.
    pub present: bool,
}

/// A page table entry
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PageTableEntry {
    /// A memory page.
    Page(Page),

    /// The physical address of the next page directory.
    PageDirectory(PageDirectory),
}

impl PageTableEntry {
    /// Creates a new page table entry from the given integer value.
    pub fn new(page_table_level: PageTableLevel, page_table_entry: u64) -> Result<Self> {
        let present_flag = (page_table_entry & FLAG_PRESENT) != 0;
        let page_size_flag = (page_table_entry & FLAG_PAGE_SIZE) != 0;

        let obj = match (page_table_level, page_size_flag) {
            (PageTableLevel::Pml4, _) => Self::PageDirectory(PageDirectory {
                physical_address: page_table_entry & MASK_PAGE_TABLE_ENTRY_TARGET,
                present: present_flag,
            }),

            (PageTableLevel::Pdpt, true) => Self::Page(Page {
                physical_address: page_table_entry & MASK_1GB_PAGE_PHYSICAL_ADDRESS,
                size: SIZE_1GB_PAGE,
                present: present_flag,
            }),

            (PageTableLevel::Pdpt, false) => Self::PageDirectory(PageDirectory {
                physical_address: page_table_entry & MASK_PAGE_TABLE_ENTRY_TARGET,
                present: present_flag,
            }),

            (PageTableLevel::Pd, true) => Self::Page(Page {
                physical_address: page_table_entry & MASK_2MB_PAGE_PHYSICAL_ADDRESS,
                size: SIZE_2MB_PAGE,
                present: present_flag,
            }),

            (PageTableLevel::Pd, false) => Self::PageDirectory(PageDirectory {
                physical_address: page_table_entry & MASK_PAGE_TABLE_ENTRY_TARGET,
                present: present_flag,
            }),

            (PageTableLevel::Pt, _) => Self::Page(Page {
                physical_address: page_table_entry & MASK_4KB_PAGE_PHYSICAL_ADDRESS,
                size: SIZE_4KB_PAGE,
                present: present_flag,
            }),
        };

        Ok(obj)
    }

    /// Returns true if the page or page directory is present in memory.
    pub fn present(&self) -> bool {
        match self {
            PageTableEntry::Page(page) => page.present,
            PageTableEntry::PageDirectory(directory) => directory.present,
        }
    }

    /// Decomposes the given virtual address into its components.
    pub fn decompose_virtual_address(virtual_address: u64) -> DecomposedVirtualAddress {
        DecomposedVirtualAddress {
            pml4: VirtualAddressComponent {
                page_table_index: ((virtual_address >> SHIFT_PML4_INDEX) & MASK_PAGE_TABLE_INDEX)
                    as usize,
                page_section: None,
            },
            pdpt: VirtualAddressComponent {
                page_table_index: ((virtual_address >> SHIFT_PDPT_INDEX) & MASK_PAGE_TABLE_INDEX)
                    as usize,
                page_section: Some(PageSection {
                    offset: virtual_address & MASK_PDPT_PAGE_OFFSET,
                    size: SIZE_1GB_PAGE - (virtual_address & MASK_PDPT_PAGE_OFFSET),
                }),
            },
            pd: VirtualAddressComponent {
                page_table_index: ((virtual_address >> SHIFT_PD_INDEX) & MASK_PAGE_TABLE_INDEX)
                    as usize,
                page_section: Some(PageSection {
                    offset: virtual_address & MASK_PD_PAGE_OFFSET,
                    size: SIZE_2MB_PAGE - (virtual_address & MASK_PD_PAGE_OFFSET),
                }),
            },
            pt: VirtualAddressComponent {
                page_table_index: ((virtual_address >> SHIFT_PT_INDEX) & MASK_PAGE_TABLE_INDEX)
                    as usize,
                page_section: Some(PageSection {
                    offset: virtual_address & MASK_PT_PAGE_OFFSET,
                    size: SIZE_4KB_PAGE - (virtual_address & MASK_PT_PAGE_OFFSET),
                }),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_range_loop, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_decompose_virtual_address() {
        let decomposed_vaddr = PageTableEntry::decompose_virtual_address(0xAAAAAAAAAAAAAAAA);

        assert_eq!(decomposed_vaddr.pml4.page_table_index, 0x0000000000000155);
        assert_eq!(decomposed_vaddr.pml4.page_section, None);

        assert_eq!(decomposed_vaddr.pdpt.page_table_index, 0x00000000000000AA);
        assert_eq!(
            decomposed_vaddr.pdpt.page_section,
            Some(PageSection {
                offset: 0x000000002AAAAAAA,
                size: 0x0000000015555556,
            })
        );

        assert_eq!(decomposed_vaddr.pd.page_table_index, 0x0000000000000155);
        assert_eq!(
            decomposed_vaddr.pd.page_section,
            Some(PageSection {
                offset: 0x00000000000AAAAA,
                size: 0x0000000000155556,
            })
        );

        assert_eq!(decomposed_vaddr.pt.page_table_index, 0x00000000000000AA);
        assert_eq!(
            decomposed_vaddr.pt.page_section,
            Some(PageSection {
                offset: 0x0000000000000AAA,
                size: 0x0000000000000556,
            })
        );
    }

    const BASE_PAGE_TABLE_ENTRY_VALUE: u64 = 0x0005555555555000;

    #[test]
    fn test_new_pml4_page_table_entry() {
        for present_flag in [false, true] {
            let mut raw_table_entry = BASE_PAGE_TABLE_ENTRY_VALUE;
            if present_flag {
                raw_table_entry |= FLAG_PRESENT;
            }

            assert_eq!(
                PageTableEntry::new(PageTableLevel::Pml4, raw_table_entry).unwrap(),
                PageTableEntry::PageDirectory(PageDirectory {
                    physical_address: BASE_PAGE_TABLE_ENTRY_VALUE,
                    present: present_flag,
                }),
            );
        }
    }

    #[test]
    fn test_new_pdpt_page_table_entry() {
        for present_flag in [false, true] {
            let mut raw_table_entry = BASE_PAGE_TABLE_ENTRY_VALUE;
            if present_flag {
                raw_table_entry |= FLAG_PRESENT;
            }

            assert_eq!(
                PageTableEntry::new(PageTableLevel::Pdpt, raw_table_entry | FLAG_PAGE_SIZE)
                    .unwrap(),
                PageTableEntry::Page(Page {
                    physical_address: 0x0005555540000000,
                    size: SIZE_1GB_PAGE,
                    present: present_flag,
                })
            );

            assert_eq!(
                PageTableEntry::new(PageTableLevel::Pdpt, raw_table_entry).unwrap(),
                PageTableEntry::PageDirectory(PageDirectory {
                    physical_address: BASE_PAGE_TABLE_ENTRY_VALUE,
                    present: present_flag,
                })
            );
        }
    }

    #[test]
    fn test_new_pd_page_table_entry() {
        for present_flag in [false, true] {
            let mut raw_table_entry = BASE_PAGE_TABLE_ENTRY_VALUE;
            if present_flag {
                raw_table_entry |= FLAG_PRESENT;
            }

            assert_eq!(
                PageTableEntry::new(PageTableLevel::Pd, raw_table_entry | FLAG_PAGE_SIZE).unwrap(),
                PageTableEntry::Page(Page {
                    physical_address: 0x0005555555400000,
                    size: SIZE_2MB_PAGE,
                    present: present_flag,
                })
            );

            assert_eq!(
                PageTableEntry::new(PageTableLevel::Pdpt, raw_table_entry).unwrap(),
                PageTableEntry::PageDirectory(PageDirectory {
                    physical_address: BASE_PAGE_TABLE_ENTRY_VALUE,
                    present: present_flag,
                })
            );
        }
    }

    #[test]
    fn test_new_pt_page_table_entry() {
        for present_flag in [false, true] {
            for enable_bit_7 in [false, true] {
                let mut raw_table_entry = BASE_PAGE_TABLE_ENTRY_VALUE;
                if present_flag {
                    raw_table_entry |= FLAG_PRESENT;
                }

                // When it comes to PT entries, bit 7 is no longer considered
                // as the page size flag
                if enable_bit_7 {
                    raw_table_entry |= FLAG_PAGE_SIZE;
                }

                assert_eq!(
                    PageTableEntry::new(PageTableLevel::Pt, raw_table_entry).unwrap(),
                    PageTableEntry::Page(Page {
                        physical_address: 0x0005555555555000,
                        size: SIZE_4KB_PAGE,
                        present: present_flag,
                    })
                );
            }
        }
    }
}
