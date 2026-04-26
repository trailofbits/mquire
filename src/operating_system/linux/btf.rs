//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::architecture::Endianness,
    generate_address_ranges,
    memory::{error::Error as MemoryError, primitives::PhysicalAddress, readable::Readable},
};

use btfparse::{
    Error as BTFParseError, ErrorKind as BTFParseErrorKind, Readable as BTFParseReadable,
    Result as BTFParseResult, TypeInformation,
};

use {
    log::debug,
    rayon::prelude::*,
    std::ops::{Range, RangeInclusive},
};

/// BTF signature for little endian machines
const BTF_LITTLE_ENDIAN_SIGNATURE: [u8; 3] = [
    0x9F, 0xEB, // Magic number
    0x01, // Version
];

/// BTF signature for big endian machines
const BTF_BIG_ENDIAN_SIGNATURE: [u8; 3] = [
    0xEB, 0x9F, // Magic number
    0x01, // Version
];

/// BTF signature length (same for both endiannesses)
const BTF_SIGNATURE_LEN: usize = 3;

/// The per-CPU data section name, which is only used by the vmlinux BTF data.
const KERNEL_PERCPU_DATASEC: &str = ".data..percpu";

/// Size of the BTF header
const BTF_HEADER_SIZE: usize = 24;

/// The amount of bytes we'd expect to find in a vmlinux BTF data blob
const KERNEL_BTF_PAYLOAD_RANGE: RangeInclusive<u64> = (1024 * 1024)..=(64 * 1024 * 1024);

/// Buffer size used for chunk-based scanning (4 MB)
const SCAN_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Number of 4MB chunks to scan per batch.
/// 64 chunks * 4MB = 256MB scanned per `next()` call.
const RANGE_COUNT_PER_BATCH: usize = 64;

/// Parsed fields from a 24-byte BTF header.
struct BtfHeader {
    /// BTF flags
    flags: u8,

    /// Header length in bytes (expected to equal `BTF_HEADER_SIZE`)
    hdr_len: u32,

    /// Length of the type section in bytes
    type_len: u32,

    /// Length of the string section in bytes
    str_len: u32,
}

impl BtfHeader {
    /// Reads and parses a BTF header at the given offset. Returns `None`
    /// if the read fails or the magic/version signature is not recognised.
    fn new(readable: &dyn Readable, offset: PhysicalAddress) -> Option<Self> {
        let mut buffer = [0u8; BTF_HEADER_SIZE];
        if readable.read(&mut buffer, offset).ok()? != BTF_HEADER_SIZE {
            return None;
        }

        let signature: [u8; BTF_SIGNATURE_LEN] = buffer[..BTF_SIGNATURE_LEN].try_into().ok()?;
        let u32_from_bytes = match signature {
            BTF_LITTLE_ENDIAN_SIGNATURE => u32::from_le_bytes,
            BTF_BIG_ENDIAN_SIGNATURE => u32::from_be_bytes,

            _ => return None,
        };

        Some(Self {
            flags: buffer[3],
            hdr_len: u32_from_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
            type_len: u32_from_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            str_len: u32_from_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]),
        })
    }
}

/// Makes the Snapshot object compatible with the btfparse library.
pub struct BtfparseReadableAdapter<'a> {
    /// The underlying memory snapshot, as a raw file
    readable: &'a dyn Readable,

    /// Where to start parsing BTF data from
    base_offset: u64,
}

impl<'a> BtfparseReadableAdapter<'a> {
    /// Creates a new BtfparseReadableAdapter object
    pub fn new(readable: &'a dyn Readable, base_offset: u64) -> Self {
        BtfparseReadableAdapter {
            readable,
            base_offset,
        }
    }
}

impl From<MemoryError> for BTFParseError {
    /// Converts a MemoryError into a BTFParseError
    fn from(error: MemoryError) -> Self {
        BTFParseError::new(BTFParseErrorKind::IOError, &format!("{error:?}"))
    }
}

impl<'a> BTFParseReadable for BtfparseReadableAdapter<'a> {
    /// Reads from the snapshot
    fn read(&self, offset: u64, buffer: &mut [u8]) -> BTFParseResult<()> {
        let physical_address = PhysicalAddress::new(self.base_offset + offset);

        let bytes_read = self.readable.read(buffer, physical_address)?;
        if bytes_read != buffer.len() {
            Err(BTFParseError::new(
                BTFParseErrorKind::IOError,
                &format!(
                    "Only {} bytes were available out of the requested {}",
                    bytes_read,
                    buffer.len()
                ),
            ))
        } else {
            Ok(())
        }
    }
}

/// A lazy, batched iterator that scans physical memory for valid BTF
/// sections that pass the size + `task_struct` check.
///
/// The kernel image is loaded by the bootloader as a single physically
/// contiguous block. The `.BTF` ELF section within the kernel's rodata
/// contains all kernel type information, so a linear scan over physical
/// memory will find complete, parseable BTF blobs without fragmentation.
///
/// Each call to `next()` scans one batch of ranges in parallel using
/// rayon, returning all valid BTF candidates found in that batch sorted
/// by physical address.
pub struct BtfBatchScanner<'a> {
    /// Reference to the memory backing store
    readable: &'a dyn Readable,

    /// BTF magic + version signature to scan for (endianness-dependent)
    signature: &'static [u8; 3],

    /// Flat list of all ranges across all regions, in physical address order
    range_list: Vec<Range<PhysicalAddress>>,

    /// Index of the next batch to scan (batch = `RANGE_COUNT_PER_BATCH` consecutive ranges)
    current_batch_index: usize,
}

impl<'a> BtfBatchScanner<'a> {
    /// Creates a new `BtfBatchScanner` that will scan all regions
    /// of the given `Readable` for BTF candidates.
    pub fn new(
        readable: &'a dyn Readable,
        endianness: Endianness,
    ) -> crate::core::error::Result<Self> {
        let signature = match endianness {
            Endianness::Little => &BTF_LITTLE_ENDIAN_SIGNATURE,
            Endianness::Big => &BTF_BIG_ENDIAN_SIGNATURE,
        };

        let regions = readable.regions()?;
        let mut range_list = Vec::new();

        for region in &regions {
            range_list.extend(generate_address_ranges!(
                region.start,
                region.end,
                SCAN_BUFFER_SIZE,
                BTF_SIGNATURE_LEN
            ));
        }

        Ok(Self {
            readable,
            signature,
            range_list,
            current_batch_index: 0,
        })
    }
}

impl<'a> Iterator for BtfBatchScanner<'a> {
    type Item = Vec<TypeInformation>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let batch_start = self.current_batch_index * RANGE_COUNT_PER_BATCH;
            if batch_start >= self.range_list.len() {
                return None;
            }

            let batch_end = (batch_start + RANGE_COUNT_PER_BATCH).min(self.range_list.len());
            let batch = &self.range_list[batch_start..batch_end];
            self.current_batch_index += 1;

            let readable = self.readable;
            let signature = self.signature;
            let mut results: Vec<(PhysicalAddress, TypeInformation)> = batch
                .par_iter()
                .flat_map_iter(|range| scan_range_for_btf(readable, range, signature))
                .collect();

            if results.is_empty() {
                continue;
            }

            results.sort_by_key(|(addr, _)| *addr);
            return Some(results.into_iter().map(|(_, ti)| ti).collect());
        }
    }
}

/// Scans a single range for BTF signature matches, parses each match,
/// and returns all valid `TypeInformation` objects found in that range.
fn scan_range_for_btf(
    readable: &dyn Readable,
    range: &Range<PhysicalAddress>,
    signature: &[u8; 3],
) -> Vec<(PhysicalAddress, TypeInformation)> {
    let mut read_buffer = vec![0u8; SCAN_BUFFER_SIZE];
    let bytes_read = match readable.read(&mut read_buffer, range.start) {
        Ok(n) => n,
        Err(_) => {
            debug!("Failed to read buffer during BTF scan at {:?}", range.start);
            return vec![];
        }
    };

    let mut results = Vec::new();
    for offset in read_buffer[..bytes_read]
        .windows(signature.len())
        .enumerate()
        .filter_map(|(offset, window)| {
            if window == signature {
                Some(offset)
            } else {
                None
            }
        })
    {
        let btf_offset = range.start + (offset as u64);
        let btf_header = match BtfHeader::new(readable, btf_offset) {
            Some(obj) => obj,
            None => continue,
        };

        if btf_header.flags != 0 || btf_header.hdr_len as usize != BTF_HEADER_SIZE {
            continue;
        }

        let payload = btf_header.type_len as u64 + btf_header.str_len as u64;
        if !KERNEL_BTF_PAYLOAD_RANGE.contains(&payload) {
            continue;
        }

        let readable_adapter = BtfparseReadableAdapter::new(readable, btf_offset.value());

        let type_information = match TypeInformation::new(&readable_adapter) {
            Ok(type_information) => type_information,
            Err(_) => {
                debug!("Failed to parse BTF data at offset {}", btf_offset);
                continue;
            }
        };

        if type_information.id_of(KERNEL_PERCPU_DATASEC).is_some()
            && type_information.id_of("task_struct").is_some()
        {
            debug!("BTF data found at offset {btf_offset}");
            results.push((btf_offset, type_information));
        }
    }

    results
}
