//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    architecture::intel::page_table_entry::{
        PageTableEntry, PageTableLevel, SHIFT_PDPT_INDEX, SHIFT_PD_INDEX, SHIFT_PML4_INDEX,
        SHIFT_PT_INDEX,
    },
    core::{
        architecture::{Architecture, Bitness, Endianness, PhysicalAddressRange, Region},
        error::{Error, ErrorKind, Result},
    },
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    utils::reader::Reader,
};

use std::sync::Arc;

/// The size, in bytes, of a page directory
const PAGE_DIRECTORY_SIZE: u64 = 4096;

/// Implements the Intel x86_64 architecture features for the Architecture trait
#[derive(Default)]
pub struct IntelArchitecture {}

impl IntelArchitecture {
    /// Creates a new IntelArchitecture instance
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }

    /// Returns the table entries for a given table offset
    fn get_table_entries(
        readable: &dyn Readable,
        mut table_offset: PhysicalAddress,
        table_level: PageTableLevel,
    ) -> Result<Vec<PageTableEntry>> {
        let reader = Reader::new(readable, true);
        let mut page_table = Vec::with_capacity(512);

        for _ in 0..512 {
            let qword = reader.read_u64(table_offset)?;
            page_table.push(PageTableEntry::new(table_level, qword)?);

            table_offset = table_offset + 8usize;
        }

        Ok(page_table)
    }

    /// Returns the physical address range for a given virtual address
    fn virtual_address_to_physical_address(
        readable: &dyn Readable,
        virtual_address: VirtualAddress,
    ) -> Result<PhysicalAddressRange> {
        let raw_virtual_addr = virtual_address.value();
        let decomposed_vaddr = PageTableEntry::decompose_virtual_address(raw_virtual_addr.value());

        let reader = Reader::new(readable, true);
        let raw_table_entry = reader.read_u64(
            virtual_address.root_page_table() + decomposed_vaddr.pml4.page_table_index * 8,
        )?;

        let page_directory = if let PageTableEntry::PageDirectory(page_directory) =
            PageTableEntry::new(PageTableLevel::Pml4, raw_table_entry)?
        {
            page_directory
        } else {
            return Err(Error::new(
                ErrorKind::InvalidPageTableEntry,
                "The PML4 table entry does not point to a page directory",
            ));
        };

        if !page_directory.present {
            return Err(Error::new(
                ErrorKind::MemoryNotMapped,
                "The page directory pointed to by the PML4 table is not mapped",
            ));
        }

        let directory_address: PhysicalAddress = page_directory.physical_address.into();
        let raw_table_entry =
            reader.read_u64(directory_address + decomposed_vaddr.pdpt.page_table_index * 8)?;

        let page_table_entry = PageTableEntry::new(PageTableLevel::Pdpt, raw_table_entry)?;
        if !page_table_entry.present() {
            return Err(Error::new(
                ErrorKind::MemoryNotMapped,
                "The page or page directory pointed to by the PDPT table is not mapped",
            ));
        }

        let raw_table_entry = match page_table_entry {
            PageTableEntry::Page(page) => {
                let page_section = decomposed_vaddr.pdpt.page_section.ok_or(Error::new(
                    ErrorKind::MemoryNotMapped,
                    "Missing page section data in the decomposed PDPT entry",
                ))?;

                let page_address: PhysicalAddress = page.physical_address.into();

                return Ok(PhysicalAddressRange::new(
                    page_address + page_section.offset,
                    page_section.size,
                ));
            }

            PageTableEntry::PageDirectory(directory) => {
                let directory_address: PhysicalAddress = directory.physical_address.into();
                reader.read_u64(directory_address + decomposed_vaddr.pd.page_table_index * 8)?
            }
        };

        let page_table_entry = PageTableEntry::new(PageTableLevel::Pd, raw_table_entry)?;
        if !page_table_entry.present() {
            return Err(Error::new(
                ErrorKind::MemoryNotMapped,
                "The page or page directory pointed to by the PD table is not mapped",
            ));
        }

        let raw_table_entry = match page_table_entry {
            PageTableEntry::Page(page) => {
                let page_section = decomposed_vaddr.pd.page_section.ok_or(Error::new(
                    ErrorKind::MemoryNotMapped,
                    "Missing page section data in the decomposed PD entry",
                ))?;

                let page_address: PhysicalAddress = page.physical_address.into();

                return Ok(PhysicalAddressRange::new(
                    page_address + page_section.offset,
                    page_section.size,
                ));
            }

            PageTableEntry::PageDirectory(directory) => {
                let directory_address: PhysicalAddress = directory.physical_address.into();
                reader.read_u64(directory_address + decomposed_vaddr.pt.page_table_index * 8)?
            }
        };

        let page_table_entry = PageTableEntry::new(PageTableLevel::Pt, raw_table_entry)?;
        if !page_table_entry.present() {
            return Err(Error::new(
                ErrorKind::MemoryNotMapped,
                "The page pointed to by the PT table is not mapped",
            ));
        }

        match page_table_entry {
            PageTableEntry::PageDirectory(_) => Err(Error::new(
                ErrorKind::InvalidPageTableEntry,
                "Unexpected page directory entry found in PT table",
            )),

            PageTableEntry::Page(page) => {
                let page_section = decomposed_vaddr.pt.page_section.ok_or(Error::new(
                    ErrorKind::MemoryNotMapped,
                    "Missing page section data in the decomposed PT entry",
                ))?;

                let page_address: PhysicalAddress = page.physical_address.into();

                Ok(PhysicalAddressRange::new(
                    page_address + page_section.offset,
                    page_section.size,
                ))
            }
        }
    }
}

impl Architecture for IntelArchitecture {
    fn endianness(&self) -> Endianness {
        Endianness::Little
    }

    fn bitness(&self) -> Bitness {
        Bitness::Bit64
    }

    fn locate_page_table_for_virtual_address(
        &self,
        readable: &dyn Readable,
        physical_address: PhysicalAddress,
        raw_virtual_address: RawVirtualAddress,
    ) -> Result<PhysicalAddress> {
        let decomposed_vaddr =
            PageTableEntry::decompose_virtual_address(raw_virtual_address.value());

        for region in readable.regions()? {
            for page_table_offset in region
                .start
                .aligned_to(PAGE_DIRECTORY_SIZE)
                .range_step(region.end, PAGE_DIRECTORY_SIZE)
            {
                let pml4_page_table =
                    Self::get_table_entries(readable, page_table_offset, PageTableLevel::Pml4)?;

                let page_directory = if let Some(PageTableEntry::PageDirectory(page_directory)) =
                    pml4_page_table.get(decomposed_vaddr.pml4.page_table_index)
                {
                    page_directory
                } else {
                    continue;
                };

                if !page_directory.present {
                    continue;
                }

                let mut user_mode_count = 0;
                for (pml4_index, pml4_entry) in pml4_page_table.iter().enumerate() {
                    let present = match pml4_entry {
                        PageTableEntry::Page(page) => page.present,
                        PageTableEntry::PageDirectory(directory) => directory.present,
                    };

                    if !present {
                        continue;
                    }

                    if pml4_index <= 0xFF {
                        user_mode_count += 1;
                    }
                }

                if user_mode_count != 0 {
                    continue;
                }

                let virtual_address = VirtualAddress::new(page_table_offset, raw_virtual_address);
                let physical_address_range =
                    match Self::virtual_address_to_physical_address(readable, virtual_address) {
                        Ok(physical_address) => physical_address,
                        Err(_) => continue,
                    };

                if physical_address_range.address().value() == physical_address.value() {
                    return Ok(page_table_offset);
                }
            }
        }

        Err(Error::new(
            ErrorKind::NoRootPageDirectoryFound,
            &format!(
                "No PML4 table found to translate {raw_virtual_address} => {physical_address} ",
            ),
        ))
    }

    fn translate_virtual_address(
        &self,
        readable: &dyn Readable,
        virtual_address: VirtualAddress,
    ) -> Result<PhysicalAddressRange> {
        Self::virtual_address_to_physical_address(readable, virtual_address)
    }

    fn enumerate_page_table_regions(
        &self,
        readable: &dyn Readable,
        root_page_table: PhysicalAddress,
    ) -> Result<Vec<Region>> {
        let mut region_list = Vec::new();

        // Read the entire PML4 table (4096 bytes = 512 entries)
        let mut pml4_buffer = [0u8; 4096];
        readable.read_exact(&mut pml4_buffer, root_page_table)?;

        for (pml4_index, chunk) in pml4_buffer.chunks_exact(8).enumerate() {
            let pml4_index = pml4_index as u64;
            let Ok(bytes) = <[u8; 8]>::try_from(chunk) else {
                continue;
            };
            let raw_table_entry = u64::from_le_bytes(bytes);

            let pml4_page_directory =
                match PageTableEntry::new(PageTableLevel::Pml4, raw_table_entry) {
                    Ok(PageTableEntry::PageDirectory(page_directory)) => {
                        if !page_directory.present {
                            continue;
                        }

                        page_directory
                    }

                    _ => continue,
                };

            // Read the entire PDPT table
            let mut pdpt_buffer = [0u8; 4096];
            if readable
                .read_exact(
                    &mut pdpt_buffer,
                    PhysicalAddress::new(pml4_page_directory.physical_address),
                )
                .is_err()
            {
                continue;
            }

            for (pdpt_index, chunk) in pdpt_buffer.chunks_exact(8).enumerate() {
                let pdpt_index = pdpt_index as u64;
                let Ok(bytes) = <[u8; 8]>::try_from(chunk) else {
                    continue;
                };
                let raw_table_entry = u64::from_le_bytes(bytes);

                let pdpt_page_directory =
                    match PageTableEntry::new(PageTableLevel::Pdpt, raw_table_entry) {
                        Ok(PageTableEntry::PageDirectory(page_directory)) => {
                            if !page_directory.present {
                                continue;
                            }

                            page_directory
                        }

                        Ok(PageTableEntry::Page(page)) => {
                            if page.present {
                                let raw_virtual_address = RawVirtualAddress::new(
                                    (pml4_index << SHIFT_PML4_INDEX)
                                        | (pdpt_index << SHIFT_PDPT_INDEX),
                                );

                                region_list.push(Region {
                                    virtual_address: VirtualAddress::new(
                                        root_page_table,
                                        raw_virtual_address,
                                    )
                                    .canonicalized(),
                                    physical_address: PhysicalAddress::new(page.physical_address),
                                    size: page.size,
                                });
                            }

                            continue;
                        }

                        _ => continue,
                    };

                // Read the entire PD table
                let mut pd_buffer = [0u8; 4096];
                if readable
                    .read_exact(
                        &mut pd_buffer,
                        PhysicalAddress::new(pdpt_page_directory.physical_address),
                    )
                    .is_err()
                {
                    continue;
                }

                for (pd_index, chunk) in pd_buffer.chunks_exact(8).enumerate() {
                    let pd_index = pd_index as u64;
                    let Ok(bytes) = <[u8; 8]>::try_from(chunk) else {
                        continue;
                    };
                    let raw_table_entry = u64::from_le_bytes(bytes);

                    let pd_page_directory =
                        match PageTableEntry::new(PageTableLevel::Pd, raw_table_entry) {
                            Ok(PageTableEntry::PageDirectory(page_directory)) => {
                                if !page_directory.present {
                                    continue;
                                }

                                page_directory
                            }

                            Ok(PageTableEntry::Page(page)) => {
                                if page.present {
                                    let raw_virtual_address = RawVirtualAddress::new(
                                        (pml4_index << SHIFT_PML4_INDEX)
                                            | (pdpt_index << SHIFT_PDPT_INDEX)
                                            | (pd_index << SHIFT_PD_INDEX),
                                    );

                                    region_list.push(Region {
                                        virtual_address: VirtualAddress::new(
                                            root_page_table,
                                            raw_virtual_address,
                                        )
                                        .canonicalized(),
                                        physical_address: PhysicalAddress::new(
                                            page.physical_address,
                                        ),
                                        size: page.size,
                                    });
                                }

                                continue;
                            }

                            _ => continue,
                        };

                    // Read the entire PT table
                    let mut pt_buffer = [0u8; 4096];
                    if readable
                        .read_exact(
                            &mut pt_buffer,
                            PhysicalAddress::new(pd_page_directory.physical_address),
                        )
                        .is_err()
                    {
                        continue;
                    }

                    for (pt_index, chunk) in pt_buffer.chunks_exact(8).enumerate() {
                        let pt_index = pt_index as u64;
                        let Ok(bytes) = <[u8; 8]>::try_from(chunk) else {
                            continue;
                        };
                        let raw_table_entry = u64::from_le_bytes(bytes);

                        if let Ok(PageTableEntry::Page(page)) =
                            PageTableEntry::new(PageTableLevel::Pt, raw_table_entry)
                        {
                            if page.present {
                                let raw_virtual_address = RawVirtualAddress::new(
                                    (pml4_index << SHIFT_PML4_INDEX)
                                        | (pdpt_index << SHIFT_PDPT_INDEX)
                                        | (pd_index << SHIFT_PD_INDEX)
                                        | (pt_index << SHIFT_PT_INDEX),
                                );

                                region_list.push(Region {
                                    virtual_address: VirtualAddress::new(
                                        root_page_table,
                                        raw_virtual_address,
                                    )
                                    .canonicalized(),
                                    physical_address: PhysicalAddress::new(page.physical_address),
                                    size: page.size,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(region_list)
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::error::Result as MemoryResult;

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum PageSize {
        Normal,
        Large2Mb,
        Large1Gb,
    }

    struct MockedPageTable {
        page_size: PageSize,
        unmapped: bool,
    }

    impl MockedPageTable {
        pub fn new(page_size: PageSize, unmapped: bool) -> Self {
            Self {
                page_size,
                unmapped,
            }
        }
    }

    impl Readable for MockedPageTable {
        fn read(&self, buffer: &mut [u8], offset: PhysicalAddress) -> MemoryResult<usize> {
            match self.page_size {
                PageSize::Normal => {
                    assert!(
                        offset.value() == 0x1008
                            || offset.value() == 0x2008
                            || offset.value() == 0x3008
                            || offset.value() == 0x4008
                    );

                    if offset.value() == 0x1008 {
                        buffer.copy_from_slice(&[0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.value() == 0x2008 {
                        buffer.copy_from_slice(&[0x01, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.value() == 0x3008 {
                        buffer.copy_from_slice(&[0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.value() == 0x4008 {
                        if self.unmapped {
                            buffer
                                .copy_from_slice(&[0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        } else {
                            buffer
                                .copy_from_slice(&[0x01, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        }
                    }

                    Ok(buffer.len())
                }

                PageSize::Large2Mb => {
                    assert!(
                        offset.value() == 0x1008
                            || offset.value() == 0x2008
                            || offset.value() == 0x3008
                    );

                    if offset.value() == 0x1008 {
                        buffer.copy_from_slice(&[0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.value() == 0x2008 {
                        buffer.copy_from_slice(&[0x01, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.value() == 0x3008 {
                        if self.unmapped {
                            buffer
                                .copy_from_slice(&[0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        } else {
                            buffer
                                .copy_from_slice(&[0x81, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        }
                    }

                    Ok(buffer.len())
                }

                PageSize::Large1Gb => {
                    assert!(offset.value() == 0x1008 || offset.value() == 0x2008);

                    if offset.value() == 0x1008 {
                        buffer.copy_from_slice(&[0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else if offset.value() == 0x2008 {
                        if self.unmapped {
                            buffer
                                .copy_from_slice(&[0x80, 0x30, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00]);
                        } else {
                            buffer
                                .copy_from_slice(&[0x81, 0x30, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00]);
                        }
                    }

                    Ok(buffer.len())
                }
            }
        }

        fn len(&self) -> MemoryResult<u64> {
            Ok(0xFFFFFFFF)
        }
    }

    #[test]
    fn test_normal_page_size_vaddr_translation() {
        let mocked_page_table = MockedPageTable::new(PageSize::Normal, false);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::new(0x0000008040201000),
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
        let mocked_page_table = MockedPageTable::new(PageSize::Large2Mb, false);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::new(0x0000008040201000),
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
        let mocked_page_table = MockedPageTable::new(PageSize::Large1Gb, false);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::new(0x0000008040201000),
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
            RawVirtualAddress::new(0x0000008040201000),
        );

        let physical_address_range_res = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        );

        assert!(physical_address_range_res.is_err());
        assert_eq!(
            physical_address_range_res.unwrap_err().kind(),
            ErrorKind::MemoryNotMapped
        );
    }

    #[test]
    fn test_huge_2mb_page_size_vaddr_translation_with_page_fault() {
        let mocked_page_table = MockedPageTable::new(PageSize::Large2Mb, true);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::new(0x0000008040201000),
        );

        let physical_address_range_res = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        );

        assert!(physical_address_range_res.is_err());
        assert_eq!(
            physical_address_range_res.unwrap_err().kind(),
            ErrorKind::MemoryNotMapped
        );
    }

    #[test]
    fn test_huge_1gb_page_size_vaddr_translation_with_page_fault() {
        let mocked_page_table = MockedPageTable::new(PageSize::Large1Gb, true);
        let virtual_address = VirtualAddress::new(
            PhysicalAddress::new(0x1000),
            RawVirtualAddress::new(0x0000008040201000),
        );

        let physical_address_range_res = IntelArchitecture::virtual_address_to_physical_address(
            &mocked_page_table,
            virtual_address,
        );

        assert!(physical_address_range_res.is_err());
        assert_eq!(
            physical_address_range_res.unwrap_err().kind(),
            ErrorKind::MemoryNotMapped
        );
    }
}
