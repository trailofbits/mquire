//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::architecture::intel::{TableEntry, TableType};
use crate::memory::{PhysicalAddress, RawVirtualAddress, Readable, VirtualAddress};
use crate::sys::{
    Architecture, Bitness, Error as SystemError, ErrorKind as SystemErrorKind,
    PhysicalAddressRange, Result as SystemResult,
};
use crate::utils::Reader;

/// The size of a page used to host a PML4 table
const PML4_TABLE_SIZE: u64 = 4096;

/// The mask used to extract the PML4 index from a virtual address
const PML4_INDEX_MASK: u64 = 0x0000FF8000000000;

/// The shift used to extract the PML4 index from a virtual address
const PML4_INDEX_SHIFT: u64 = 39;

/// The mask used to extract the PDPT index from a virtual address
const PDPT_INDEX_MASK: u64 = 0x0000007FC0000000;

/// The shift used to extract the PDPT index from a virtual address
const PDPT_INDEX_SHIFT: u64 = 30;

/// The mask used to extract the PD index from a virtual address
const PD_INDEX_MASK: u64 = 0x000000003FE00000;

/// The shift used to extract the PD index from a virtual address
const PD_INDEX_SHIFT: u64 = 21;

/// The mask used to extract the PT index from a virtual address
const PT_INDEX_MASK: u64 = 0x00000000001FF000;

/// The shift used to extract the PT index from a virtual address
const PT_INDEX_SHIFT: u64 = 12;

/// The mask used to extract the offset from a virtual address for a normal page size
const NORMAL_PAGE_OFFSET_VADDR_MASK: u64 = 0x00000FFF;

/// The mask used to extract the offset from a virtual address for a 2MB huge pages
const HUGE_PAGE_2MB_OFFSET_VADDR_MASK: u64 = 0x001FFFFF;

/// The mask used to extract the offset from a virtual address for a 1GB huge pages
const HUGE_PAGE_1GB_OFFSET_VADDR_MASK: u64 = 0x3FFFFFFF;

/// 4k page size (all page table entries had the PageSize bit set to 0)
const NORMAL_PAGE_SIZE: u64 = 4096;

/// 2M page size (the PD table entry had the PageSize bit set to 1)
const HUGE_PAGE_2MB_SIZE: u64 = 2 * 1024 * 1024;

/// 1G page size (the PDPT entry had the PageSize bit set to 1)
const HUGE_PAGE_1GB_SIZE: u64 = 1024 * 1024 * 1024;

/// Page table level type, used when extracting the page offset from a virtual address
enum PageTableLevel {
    /// Third level page table (PML4)
    Pdpt,

    /// Second level page table (PD)
    Pd,

    /// First level page table (PT)
    Pt,
}

/// Implements the Intel x86_64 architecture features for the Architecture trait
pub struct IntelArchitecture {
    bitness: Bitness,
}

impl IntelArchitecture {
    /// Creates a new IntelArchitecture instance
    pub fn new(bitness: Bitness) -> Self {
        Self { bitness }
    }

    /// Returns the PML4 index for a given virtual address
    fn pml4_index(raw_virtual_address: u64) -> u64 {
        (raw_virtual_address & PML4_INDEX_MASK) >> PML4_INDEX_SHIFT
    }

    /// Returns the PDPT index for a given virtual address
    fn pdpt_index(raw_virtual_address: u64) -> u64 {
        (raw_virtual_address & PDPT_INDEX_MASK) >> PDPT_INDEX_SHIFT
    }

    /// Returns the PD index for a given virtual address
    fn pd_index(raw_virtual_address: u64) -> u64 {
        (raw_virtual_address & PD_INDEX_MASK) >> PD_INDEX_SHIFT
    }

    /// Returns the PT index for a given virtual address
    fn pt_index(raw_virtual_address: u64) -> u64 {
        (raw_virtual_address & PT_INDEX_MASK) >> PT_INDEX_SHIFT
    }

    /// Returns the offset for a given virtual address
    fn page_offset(
        raw_virtual_address: u64,
        page_table_level: PageTableLevel,
        large_page: bool,
    ) -> (u64, u64) {
        if !large_page {
            let page_offset = raw_virtual_address & NORMAL_PAGE_OFFSET_VADDR_MASK;
            let remaining_bytes = NORMAL_PAGE_SIZE - page_offset;

            return (page_offset, remaining_bytes);
        }

        match page_table_level {
            PageTableLevel::Pdpt => {
                let page_offset = raw_virtual_address & HUGE_PAGE_1GB_OFFSET_VADDR_MASK;
                let remaining_bytes = HUGE_PAGE_1GB_SIZE - page_offset;

                (page_offset, remaining_bytes)
            }

            PageTableLevel::Pd => {
                let page_offset = raw_virtual_address & HUGE_PAGE_2MB_OFFSET_VADDR_MASK;
                let remaining_bytes = HUGE_PAGE_2MB_SIZE - page_offset;

                (page_offset, remaining_bytes)
            }

            PageTableLevel::Pt => {
                unreachable!("Invalid page table level for large pages");
            }
        }
    }

    /// Returns the table entries for a given table offset
    fn get_table_entries(
        readable: &dyn Readable,
        table_offset: PhysicalAddress,
        table_type: TableType,
    ) -> SystemResult<Vec<TableEntry>> {
        let mut table_buffer: [u8; 4096] = [0; 4096];
        readable.read(&mut table_buffer, table_offset)?;

        let mut qword_list: [u64; 512] = [0; 512];
        for (i, chunk) in table_buffer.chunks_exact(8).enumerate() {
            qword_list[i] = u64::from_le_bytes(chunk.try_into().expect("Invalid chunk size"));
        }

        let mut output = Vec::new();
        for qword in qword_list {
            output.push(TableEntry::new(table_type, qword));
        }

        Ok(output)
    }

    /// Returns a list of page table candidates for a given valid PML4 index
    fn search_for_page_table_candidates(
        readable: &dyn Readable,
        valid_pml4_index: u64,
    ) -> SystemResult<Vec<PhysicalAddress>> {
        let table_count = readable.len().unwrap() / PML4_TABLE_SIZE;
        let mut table_offset_candidate_list = Vec::new();

        for table_index in 0..table_count {
            let page_table_offset = PhysicalAddress::new(table_index * PML4_TABLE_SIZE);
            let pml4_entry_list =
                Self::get_table_entries(readable, page_table_offset, TableType::Pml4)?;
            if !pml4_entry_list[valid_pml4_index as usize].present() {
                continue;
            }

            let mut user_mode_count = 0;
            for (pml4_index, pml4_entry) in pml4_entry_list.iter().enumerate() {
                if !pml4_entry.present() {
                    continue;
                }

                if pml4_index <= 0xFF {
                    user_mode_count += 1;
                }
            }

            if user_mode_count != 0 {
                continue;
            }

            table_offset_candidate_list.push(page_table_offset);
        }

        Ok(table_offset_candidate_list)
    }

    /// Returns the physical address range for a given virtual address
    fn virtual_address_to_physical_address(
        readable: &dyn Readable,
        virtual_address: VirtualAddress,
    ) -> SystemResult<PhysicalAddressRange> {
        let raw_virtual_address = match virtual_address.get() {
            RawVirtualAddress::U32(_) => {
                return Err(SystemError::new(
                    SystemErrorKind::NotSupported,
                    "32-bit virtual addresses are not supported",
                ));
            }

            RawVirtualAddress::U64(raw_virtual_address) => raw_virtual_address,
        };

        // There are 4 levels of page tables:
        // - PML4
        // - PDPT
        // - PD
        // - PT
        //
        // The standard page size is 4k, but the PageSize bit in the table entries
        // can change it:
        // - PS=1 in a PDPT entry: 1G page size
        // - PS=1 in a PD entry: 2M page size
        //
        // In case this bit is set, the next page tables are skipped and the extra
        // unused bits are used as an offset in the page.

        let reader = Reader::new(readable, true);
        let raw_table_entry = reader
            .read_u64(virtual_address.page_table() + Self::pml4_index(raw_virtual_address) * 8)?;

        let pml4_table_entry = TableEntry::new(TableType::Pml4, raw_table_entry);
        if !pml4_table_entry.present() {
            return Err(SystemError::new(
                SystemErrorKind::MemoryNotMapped,
                "The PML4 page entry is not marked as present",
            ));
        }

        if pml4_table_entry.large_page() {
            return Err(SystemError::new(
                SystemErrorKind::InvalidData,
                "Invalid PML4 table entry",
            ));
        }

        let raw_table_entry = reader
            .read_u64(pml4_table_entry.address() + Self::pdpt_index(raw_virtual_address) * 8)?;

        let pdpt_table_entry = TableEntry::new(TableType::Pdpt, raw_table_entry);
        if !pdpt_table_entry.present() {
            return Err(SystemError::new(
                SystemErrorKind::MemoryNotMapped,
                "The PDPT page entry is not marked as present",
            ));
        }

        if pdpt_table_entry.large_page() {
            let (page_offset, remaining_bytes) =
                Self::page_offset(raw_virtual_address, PageTableLevel::Pdpt, true);

            return Ok(PhysicalAddressRange::new(
                pdpt_table_entry.address() + page_offset,
                remaining_bytes,
            ));
        }

        let raw_table_entry = reader
            .read_u64(pdpt_table_entry.address() + Self::pd_index(raw_virtual_address) * 8)?;

        let pd_table_entry = TableEntry::new(TableType::Pd, raw_table_entry);
        if !pd_table_entry.present() {
            return Err(SystemError::new(
                SystemErrorKind::MemoryNotMapped,
                "The PD page entry is not marked as present",
            ));
        }

        if pd_table_entry.large_page() {
            let (page_offset, remaining_bytes) =
                Self::page_offset(raw_virtual_address, PageTableLevel::Pd, true);

            return Ok(PhysicalAddressRange::new(
                pd_table_entry.address() + page_offset,
                remaining_bytes,
            ));
        }

        let raw_table_entry =
            reader.read_u64(pd_table_entry.address() + Self::pt_index(raw_virtual_address) * 8)?;

        let pt_table_entry = TableEntry::new(TableType::Pt, raw_table_entry);
        if !pt_table_entry.present() {
            return Err(SystemError::new(
                SystemErrorKind::MemoryNotMapped,
                "The PT page entry is not marked as present",
            ));
        }

        if pt_table_entry.large_page() {
            return Err(SystemError::new(
                SystemErrorKind::InvalidData,
                "The PT page entry is not valid",
            ));
        }

        let (page_offset, remaining_bytes) =
            Self::page_offset(raw_virtual_address, PageTableLevel::Pt, false);

        Ok(PhysicalAddressRange::new(
            pt_table_entry.address() + page_offset,
            remaining_bytes,
        ))
    }
}

impl Architecture for IntelArchitecture {
    /// Returns the endianness of the architecture
    fn endianness(&self) -> crate::sys::Endianness {
        crate::sys::Endianness::Little
    }

    /// Returns the bitness of the architecture
    fn bitness(&self) -> Bitness {
        self.bitness
    }

    /// Searches the memory for a page table that can correctly translate `physical_address` to `raw_virtual_address``
    fn locate_page_table_for_virtual_address(
        &self,
        readable: &dyn Readable,
        physical_address: PhysicalAddress,
        raw_virtual_address: RawVirtualAddress,
    ) -> SystemResult<PhysicalAddress> {
        let u64_virtual_address = match raw_virtual_address {
            RawVirtualAddress::U32(_) => {
                return Err(SystemError::new(
                    SystemErrorKind::NotSupported,
                    "32-bit hosts are not supported",
                ));
            }

            RawVirtualAddress::U64(raw_virtual_address) => raw_virtual_address,
        };

        let valid_pml4_index = Self::pml4_index(u64_virtual_address);
        let page_table_candidate_list =
            Self::search_for_page_table_candidates(readable, valid_pml4_index)?;

        for pml4_candidate in page_table_candidate_list {
            let virtual_address = VirtualAddress::new(pml4_candidate, raw_virtual_address);

            let generated_physical_address =
                match Self::virtual_address_to_physical_address(readable, virtual_address) {
                    Ok(physical_address) => physical_address,
                    Err(_) => continue,
                };

            if generated_physical_address.address().get() == physical_address.get() {
                return Ok(pml4_candidate);
            }
        }

        Ok(PhysicalAddress::new(0))
    }

    /// Translates a virtual address to a physical address range
    fn translate_virtual_address(
        &self,
        readable: &dyn Readable,
        virtual_address: VirtualAddress,
    ) -> SystemResult<PhysicalAddressRange> {
        Self::virtual_address_to_physical_address(readable, virtual_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::Result as MemoryResult;

    #[derive(Clone, Copy, Debug)]
    enum PageSize {
        Normal,
        Huge2Mb,
        Huge1Gb,
    }

    struct MockedPageTable {
        page_size: PageSize,
        cause_page_fault: bool,
    }

    impl MockedPageTable {
        pub fn new(page_size: PageSize, cause_page_fault: bool) -> Self {
            Self {
                page_size,
                cause_page_fault,
            }
        }
    }

    impl Readable for MockedPageTable {
        fn read(&self, buffer: &mut [u8], offset: PhysicalAddress) -> MemoryResult<()> {
            match self.page_size {
                PageSize::Normal => {
                    assert!(
                        offset.get() == 0x1008
                            || offset.get() == 0x2008
                            || offset.get() == 0x3008
                            || offset.get() == 0x4008
                    );

                    if offset.get() == 0x1008 {
                        buffer.copy_from_slice(&[0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.get() == 0x2008 {
                        buffer.copy_from_slice(&[0x01, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.get() == 0x3008 {
                        buffer.copy_from_slice(&[0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.get() == 0x4008 {
                        if self.cause_page_fault {
                            buffer
                                .copy_from_slice(&[0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        } else {
                            buffer
                                .copy_from_slice(&[0x01, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        }
                    }

                    Ok(())
                }

                PageSize::Huge2Mb => {
                    assert!(
                        offset.get() == 0x1008 || offset.get() == 0x2008 || offset.get() == 0x3008
                    );

                    if offset.get() == 0x1008 {
                        buffer.copy_from_slice(&[0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.get() == 0x2008 {
                        buffer.copy_from_slice(&[0x01, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.get() == 0x3008 {
                        if self.cause_page_fault {
                            buffer
                                .copy_from_slice(&[0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        } else {
                            buffer
                                .copy_from_slice(&[0x81, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        }
                    }

                    Ok(())
                }

                PageSize::Huge1Gb => {
                    assert!(offset.get() == 0x1008 || offset.get() == 0x2008);

                    if offset.get() == 0x1008 {
                        buffer.copy_from_slice(&[0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.get() == 0x2008 {
                        if self.cause_page_fault {
                            buffer
                                .copy_from_slice(&[0x80, 0x30, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00]);
                        } else {
                            buffer
                                .copy_from_slice(&[0x81, 0x30, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00]);
                        }
                    }

                    Ok(())
                }
            }
        }

        fn len(&self) -> MemoryResult<u64> {
            Ok(0xFFFFFFFF)
        }

        fn is_empty(&self) -> MemoryResult<bool> {
            Ok(false)
        }
    }

    #[test]
    fn test_normal_page_size_vaddr_translation() {
        let mocked_page_table = MockedPageTable::new(PageSize::Normal, false);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::U64(0x0000008040201000),
        );

        let physical_address_range = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        )
        .unwrap();

        assert_eq!(
            physical_address_range.address(),
            PhysicalAddress::new(0x5000)
        );

        assert_eq!(physical_address_range.len(), 0x1000);
    }

    #[test]
    fn test_huge_2mb_page_size_vaddr_translation() {
        let mocked_page_table = MockedPageTable::new(PageSize::Huge2Mb, false);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::U64(0x0000008040201000),
        );

        let physical_address_range = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        )
        .unwrap();

        assert_eq!(
            physical_address_range.address(),
            PhysicalAddress::new(0x201000)
        );

        assert_eq!(physical_address_range.len(), 0x1FF000);
    }

    #[test]
    fn test_huge_1gb_page_size_vaddr_translation() {
        let mocked_page_table = MockedPageTable::new(PageSize::Huge1Gb, false);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::U64(0x0000008040201000),
        );

        let physical_address_range = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        )
        .unwrap();

        assert_eq!(
            physical_address_range.address(),
            PhysicalAddress::new(0xAA00201000)
        );

        assert_eq!(physical_address_range.len(), 0x3FDFF000);
    }

    #[test]
    fn test_normal_page_size_vaddr_translation_with_page_fault() {
        let mocked_page_table = MockedPageTable::new(PageSize::Normal, true);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::U64(0x0000008040201000),
        );

        let physical_address_range_res = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        );

        assert!(physical_address_range_res.is_err());
        assert_eq!(
            *physical_address_range_res.unwrap_err().kind(),
            SystemErrorKind::MemoryNotMapped
        );
    }

    #[test]
    fn test_huge_2mb_page_size_vaddr_translation_with_page_fault() {
        let mocked_page_table = MockedPageTable::new(PageSize::Huge2Mb, true);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::U64(0x0000008040201000),
        );

        let physical_address_range_res = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        );

        assert!(physical_address_range_res.is_err());
        assert_eq!(
            *physical_address_range_res.unwrap_err().kind(),
            SystemErrorKind::MemoryNotMapped
        );
    }

    #[test]
    fn test_huge_1gb_page_size_vaddr_translation_with_page_fault() {
        let mocked_page_table = MockedPageTable::new(PageSize::Huge1Gb, true);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::U64(0x0000008040201000),
        );

        let physical_address_range_res = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        );

        assert!(physical_address_range_res.is_err());
        assert_eq!(
            *physical_address_range_res.unwrap_err().kind(),
            SystemErrorKind::MemoryNotMapped
        );
    }
}
