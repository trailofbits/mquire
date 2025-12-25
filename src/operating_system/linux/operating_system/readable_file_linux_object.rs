//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        architecture::Architecture,
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{
        error::{Error as MemoryError, ErrorKind as MemoryErrorKind, Result as MemoryResult},
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    operating_system::linux::{kallsyms::Kallsyms, virtual_struct::VirtualStruct, xarray::XArray},
};

use {btfparse::TypeInformation, log::debug};

use std::{collections::BTreeMap, ops::Range, sync::Arc};

/// Standard page size
const PAGE_SIZE: u64 = 4096;

/// Max amount of pages per folio structure
const MAX_FOLIO_PAGES: u64 = 512;

/// Implements reading from a Linux file object in memory
pub(super) struct ReadableLinuxFileObject {
    /// Underlying memory dump
    memory_dump: Arc<dyn Readable>,

    /// Base virtual address of the vmemmap
    vmemmap_base: VirtualAddress,

    /// Size of struct page
    page_struct_size: u64,

    /// Size of the file
    file_size: u64,

    /// Page map
    cached_page_map: BTreeMap<u64, VirtualAddress>,
}

impl ReadableLinuxFileObject {
    /// Creates a new reader for the `struct file` object at the given vaddr
    pub(super) fn from_file_vaddr(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        type_information: &TypeInformation,
        kallsyms: &Kallsyms,
        file_vaddr: VirtualAddress,
    ) -> Result<Arc<dyn Readable>> {
        let vmemmap_base_ptr = kallsyms.get("vmemmap_base").ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to find vmemmap_base symbol in kallsyms",
            )
        })?;

        let vmem_reader = VirtualMemoryReader::new(memory_dump.as_ref(), architecture.as_ref());
        let vmemmap_base = match vmem_reader.read_vaddr(vmemmap_base_ptr) {
            Ok(value) => value,
            Err(err) => {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    &format!("Failed to read vmemmap_base: {:?}", err),
                ));
            }
        };

        let page_tid = type_information.id_of("page").ok_or(Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            "Failed to find 'page' struct in BTF",
        ))?;

        let page_struct_size = type_information.size_of(page_tid)? as u64;
        let file = VirtualStruct::from_name(&vmem_reader, type_information, "file", &file_vaddr)?;

        let inode = file.traverse("f_inode")?.dereference()?;
        let file_size = inode.traverse("i_size")?.read_u64()?;
        let i_pages_vaddr = inode
            .traverse("i_mapping")?
            .dereference()?
            .traverse("i_pages")?
            .virtual_address();

        let xarray = XArray::new(
            memory_dump.as_ref(),
            architecture.as_ref(),
            type_information,
            i_pages_vaddr,
        )?;

        let page_vaddrs = xarray.entries();
        let mut cached_page_map = BTreeMap::new();

        for &page_vaddr in page_vaddrs {
            if let Ok(folio) =
                VirtualStruct::from_name(&vmem_reader, type_information, "folio", &page_vaddr)
            {
                let page_index = folio.traverse("index")?.read_u64()?;
                let nr_pages = folio
                    .traverse("_folio_nr_pages")
                    .and_then(|field| field.read_u32())
                    .unwrap_or(1) as u64;

                if nr_pages > MAX_FOLIO_PAGES {
                    log::error!(
                        "  Folio has suspicious page count: {} (max: {}), treating as single page",
                        nr_pages,
                        MAX_FOLIO_PAGES
                    );

                    cached_page_map.insert(page_index, page_vaddr);
                } else {
                    for i in 0..nr_pages {
                        cached_page_map.insert(page_index + i, page_vaddr);
                    }
                }
            } else if let Ok(page) =
                VirtualStruct::from_name(&vmem_reader, type_information, "page", &page_vaddr)
            {
                let page_index = page.traverse("index")?.read_u64()?;
                cached_page_map.insert(page_index, page_vaddr);
            } else {
                debug!("Failed to parse page/folio at vaddr {:?}", page_vaddr);
                continue;
            }
        }

        Ok(Arc::new(Self {
            memory_dump,
            vmemmap_base,
            page_struct_size,
            file_size,
            cached_page_map,
        }))
    }

    /// Converts a `struct page` virtual address to a physical address.
    fn page_to_phys(&self, page_vaddr: RawVirtualAddress) -> PhysicalAddress {
        let raw_vmemmap_base_vaddr = self.vmemmap_base.value();
        let offset_from_vmemmap = page_vaddr.value() - raw_vmemmap_base_vaddr.value();
        let pfn = offset_from_vmemmap / self.page_struct_size;

        PhysicalAddress::new(pfn * PAGE_SIZE)
    }
}

impl Readable for ReadableLinuxFileObject {
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> MemoryResult<usize> {
        let mut total_bytes_read = 0;
        let mut current_offset = physical_address;
        let mut buffer_offset = 0;

        while buffer_offset < buffer.len() {
            let page_index = current_offset.value() / PAGE_SIZE;
            let offset_in_page = (current_offset.value() % PAGE_SIZE) as usize;

            let page_vaddr = self.cached_page_map.get(&page_index).ok_or_else(|| {
                MemoryError::new(
                    MemoryErrorKind::IOError,
                    &format!("Page {} not in cache", page_index),
                )
            })?;

            let phys_addr = self.page_to_phys(page_vaddr.value());
            let read_phys_addr = PhysicalAddress::new(phys_addr.value() + offset_in_page as u64);

            let remaining_in_buffer = buffer.len() - buffer_offset;
            let remaining_in_page = PAGE_SIZE as usize - offset_in_page;
            let bytes_to_read = remaining_in_buffer.min(remaining_in_page);

            let bytes_read = self.memory_dump.read(
                &mut buffer[buffer_offset..buffer_offset + bytes_to_read],
                read_phys_addr,
            )?;

            if bytes_read == 0 {
                break;
            }

            total_bytes_read += bytes_read;
            buffer_offset += bytes_read;
            current_offset = PhysicalAddress::new(current_offset.value() + bytes_read as u64);

            if bytes_read < bytes_to_read {
                break;
            }
        }

        Ok(total_bytes_read)
    }

    fn len(&self) -> MemoryResult<u64> {
        Ok(self.file_size)
    }

    fn regions(&self) -> MemoryResult<Vec<Range<PhysicalAddress>>> {
        let page_index_list = {
            let mut key_list = self.cached_page_map.keys().cloned().collect::<Vec<u64>>();
            key_list.sort();

            key_list
        };

        let range_list: Vec<Range<PhysicalAddress>> = page_index_list
            .iter()
            .map(|page_index| {
                let page_offset = PhysicalAddress::new(page_index.wrapping_mul(PAGE_SIZE));

                Range {
                    start: page_offset,
                    end: page_offset + PAGE_SIZE,
                }
            })
            .collect();

        let mut region_list: Vec<Range<PhysicalAddress>> = Vec::new();

        for range in range_list {
            if let Some(last) = region_list.last_mut() {
                if last.end >= range.start {
                    last.end = last.end.max(range.end);
                } else {
                    region_list.push(range);
                }
            } else {
                region_list.push(range);
            }
        }

        Ok(region_list)
    }
}
