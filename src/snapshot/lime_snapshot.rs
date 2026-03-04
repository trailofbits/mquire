//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

//! LiME (Linux Memory Extractor) snapshot format.
//!
//! LiME snapshots use headers to define non-contiguous physical memory ranges.
//! Regions where the original memory was empty may be optimized away by LiME
//! (detected via consecutive headers with no data in between); reads to these
//! zero-filled regions return zeroes.
//!
//! [`Readable::regions`] returns all declared ranges, both data-present and
//! zero-filled. Reads to addresses outside the declared ranges fail at the
//! binary search. Reads to data-present ranges whose file offsets fall beyond
//! the memory map are treated as snapshot file corruption.

use crate::{
    memory::{
        error::{Error, ErrorKind, Result},
        primitives::PhysicalAddress,
        readable::Readable,
    },
    utils::{readable_file::ReadableFile, reader::Reader},
};

use memmap2::Mmap;

use std::{cmp::Ordering, fs::File, ops::Range, path::Path, sync::Arc};

/// The magic value for LiME snapshot files
const LIME_HEADER_MAGIC: u32 = 0x4C694D45;

/// The expected version field for LiME snapshot files
const LIME_HEADER_VERSION: u32 = 0x00000001;

/// Size of the memory range header
const LIME_MEMORY_RANGE_HEADER_SIZE: usize = 32;

/// The memory range header
struct MemoryRange {
    /// File offset of the memory range data
    file_offset: u64,

    /// Starting address of the memory range
    s_addr: u64,

    /// Ending address of the memory range
    e_addr: u64,

    /// Whether data is present in the file (false for zero-filled regions)
    data_present: bool,
}

impl MemoryRange {
    /// Creates a new Header object from a file
    fn from_file(file: &mut File, address: PhysicalAddress) -> Result<MemoryRange> {
        let readable = ReadableFile::new(file);
        let reader = Reader::new(&readable, true);

        let mut current_address = address;

        let magic = reader.read_u32(current_address)?;
        current_address = current_address + std::mem::size_of_val(&magic);

        if magic != LIME_HEADER_MAGIC {
            return Err(Error::new(
                ErrorKind::InvalidSnapshotFormat,
                &format!("Invalid magic value (0x{magic:08X}) found at offset {address}",),
            ));
        }

        let version = reader.read_u32(current_address)?;
        current_address = current_address + std::mem::size_of_val(&version);

        if version != LIME_HEADER_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidSnapshotFormat,
                &format!("Invalid version value (0x{version:08X}) found at offset {address}",),
            ));
        }

        let s_addr = reader.read_u64(current_address)?;
        current_address = current_address + std::mem::size_of_val(&s_addr);

        let e_addr = reader.read_u64(current_address)?;
        if s_addr >= e_addr {
            Err(Error::new(
                ErrorKind::InvalidSnapshotFormat,
                &format!(
                    "Found an invalid memory range header (s_addr >= e_addr) at offset {address}",
                ),
            ))
        } else {
            Ok(Self {
                file_offset: address.value() + LIME_MEMORY_RANGE_HEADER_SIZE as u64,
                s_addr,
                e_addr,
                data_present: true,
            })
        }
    }

    fn len(&self) -> u64 {
        1 + self.e_addr - self.s_addr
    }
}

/// Represents a lime snapshot of the memory
pub struct LimeSnapshot {
    /// Memory-mapped view of the snapshot file
    mmap: Mmap,

    /// Memory ranges in the file
    memory_range_list: Vec<MemoryRange>,

    /// Total size of the mapped memory
    size: u64,
}

impl LimeSnapshot {
    /// Creates a new lime snapshot from the given path
    pub fn new(file_path: &Path) -> Result<Arc<Self>> {
        let mut file = File::open(file_path)?;
        let file_size = file.metadata()?.len();

        let mut address = PhysicalAddress::default();
        let mut memory_range_list: Vec<MemoryRange> = Vec::new();

        let mut size = 0;

        loop {
            let current_memory_range = MemoryRange::from_file(&mut file, address)?;

            let next_header_position = address + LIME_MEMORY_RANGE_HEADER_SIZE;

            // Check if there's another header immediately following this one
            let has_consecutive_header =
                if next_header_position.value() + LIME_MEMORY_RANGE_HEADER_SIZE as u64 <= file_size
                {
                    let readable = ReadableFile::new(&mut file);
                    let reader = Reader::new(&readable, true);
                    reader.read_u32(next_header_position).ok() == Some(LIME_HEADER_MAGIC)
                } else {
                    false
                };

            let (memory_range, next_address) = if has_consecutive_header {
                // Zero-filled region: data was omitted from the file
                let range = MemoryRange {
                    file_offset: 0, // Not used for zero-filled regions
                    s_addr: current_memory_range.s_addr,
                    e_addr: current_memory_range.e_addr,
                    data_present: false,
                };
                (range, next_header_position)
            } else {
                // Data follows the header
                size += current_memory_range.len();
                let next_addr = next_header_position + current_memory_range.len();
                (current_memory_range, next_addr)
            };

            if memory_range_list.iter().any(|range| {
                memory_range.s_addr < range.e_addr && range.s_addr < memory_range.e_addr
            }) {
                return Err(Error::new(
                    ErrorKind::InvalidSnapshotFormat,
                    &format!("Found an overlapping memory range at offset {address}"),
                ));
            }

            let pos = memory_range_list
                .binary_search_by(|range| range.s_addr.cmp(&memory_range.s_addr))
                .unwrap_or_else(|e| e);

            memory_range_list.insert(pos, memory_range);

            address = next_address;

            if address.value() >= file_size {
                break;
            }
        }

        Ok(Arc::new(LimeSnapshot {
            mmap: unsafe { Mmap::map(&file)? },
            memory_range_list,
            size,
        }))
    }
}

impl Readable for LimeSnapshot {
    /// Reads the specified number of bytes from the given physical address
    fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let memory_range_index = self
            .memory_range_list
            .binary_search_by(|memory_range| {
                if physical_address.value() < memory_range.s_addr {
                    Ordering::Greater
                } else if physical_address.value() >= memory_range.e_addr {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .map_err(|_insert_pos| {
                Error::new(
                    ErrorKind::IOError,
                    &format!("Address {physical_address} is not mapped by the snapshot file",),
                )
            })?;

        let memory_range = self
            .memory_range_list
            .get(memory_range_index)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::IOError,
                    &format!("Address {physical_address} is not mapped by the snapshot file",),
                )
            })?;

        let range_offset = physical_address.value() - memory_range.s_addr;

        let readable_bytes = std::cmp::min(buffer.len() as u64, memory_range.len()) as usize;
        let read_buffer = buffer.get_mut(..readable_bytes).ok_or_else(|| {
            Error::new(
                ErrorKind::IOError,
                &format!("Failed to get mutable slice of buffer for {readable_bytes} bytes",),
            )
        })?;

        // Fill with zeroes if this region was optimized away, otherwise
        // read from the memory mapping
        if !memory_range.data_present {
            read_buffer.fill(0);
            Ok(readable_bytes)
        } else {
            let file_offset = memory_range.file_offset + range_offset;

            let start = file_offset as usize;
            if start >= self.mmap.len() {
                return Err(Error::new(
                    ErrorKind::IOError,
                    &format!(
                        "File offset 0x{start:X} exceeds snapshot file size for address {physical_address}",
                    ),
                ));
            }

            let end = (start + readable_bytes).min(self.mmap.len());

            let bytes_to_read = end - start;
            if bytes_to_read > 0 {
                read_buffer[..bytes_to_read].copy_from_slice(&self.mmap[start..end]);
            }

            Ok(bytes_to_read)
        }
    }

    /// Returns the size of the snapshot
    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }

    /// Returns the list of mapped regions
    fn regions(&self) -> Result<Vec<Range<PhysicalAddress>>> {
        Ok(self
            .memory_range_list
            .iter()
            .map(|memory_range| Range {
                start: memory_range.s_addr.into(),
                end: memory_range.e_addr.into(),
            })
            .collect())
    }
}
