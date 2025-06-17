//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    memory::{
        error::{Error, ErrorKind, Result},
        primitives::PhysicalAddress,
        readable::Readable,
    },
    utils::{readable_file::ReadableFile, reader::Reader},
};

use std::{cmp::Ordering, fs::File, ops::Range, os::unix::fs::FileExt, path::Path, rc::Rc};

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
            })
        }
    }

    fn len(&self) -> u64 {
        1 + self.e_addr - self.s_addr
    }
}

/// Represents a lime snapshot of the memory
pub struct LimeSnapshot {
    /// The file containing the lime snapshot
    file: File,

    /// Memory ranges in the file
    memory_range_list: Vec<MemoryRange>,

    /// Total size of the mapped memory
    size: u64,
}

impl LimeSnapshot {
    /// Creates a new lime snapshot from the given path
    pub fn new(file_path: &Path) -> Result<Rc<Self>> {
        let mut file = File::open(file_path)?;
        let file_size = file.metadata()?.len();

        let mut address = PhysicalAddress::default();
        let mut memory_range_list: Vec<MemoryRange> = Vec::new();

        let mut size = 0;

        loop {
            let current_memory_range = MemoryRange::from_file(&mut file, address)?;

            address = address + LIME_MEMORY_RANGE_HEADER_SIZE + current_memory_range.len();

            if memory_range_list.iter().any(|memory_range| {
                current_memory_range.s_addr < memory_range.e_addr
                    && memory_range.s_addr < current_memory_range.e_addr
            }) {
                return Err(Error::new(
                    ErrorKind::InvalidSnapshotFormat,
                    &format!("Found an overlapping memory range at offset {address}"),
                ));
            }

            let pos = memory_range_list
                .binary_search_by(|range| range.s_addr.cmp(&current_memory_range.s_addr))
                .unwrap_or_else(|e| e);

            size += current_memory_range.len();
            memory_range_list.insert(pos, current_memory_range);

            if address.value() >= file_size {
                break;
            }
        }

        Ok(Rc::new(LimeSnapshot {
            file,
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
        let file_offset = memory_range.file_offset + range_offset;

        let readable_bytes = std::cmp::min(buffer.len() as u64, memory_range.len()) as usize;
        let read_buffer = buffer.get_mut(..readable_bytes).ok_or_else(|| {
            Error::new(
                ErrorKind::IOError,
                &format!("Failed to get mutable slice of buffer for {readable_bytes} bytes",),
            )
        })?;

        Ok(self.file.read_at(read_buffer, file_offset)?)
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
