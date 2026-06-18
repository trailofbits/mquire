//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

/*
  This is a reference taken from `write_src` in scripts/kallsyms.c
  for kernel 6.17.7. The layout has not been stable across different
  kernel versions, so we need to be able to locate the different
  sections independently. Luckily the most important sections did
  not change in order, but we may have or may have not gaps between
  them.

  These changes have been introduced in version 6.4, see commit:
  404bad70fcf7 "scripts/kallsyms: change the output order

  We currently don't support earlier versions, but the code is structured
  in a way that would allow adding support for them in the future.

  ```
    .section kallsyms_num_syms

      symbol count, as a 4 bytes value

    .section kallsyms_names

      <kallsyms_num_syms> entries, each entry is:
        - 1 or 2 bytes of length information
        - a stream of compressed token data

      In case the name length is less than 0x80, it is stored as a single
      byte, otherwise it is stored as two bytes, with the high bit of the
      first byte set to indicate the "big" length format.

    .section kallsyms_markers

      entry count: (<kallsyms_num_syms> + 255) / 256

      Each entry is a 4-bytes value containing an offset into the
      <kallsyms_names> data, pointing to the beginning of the
      names for that group of 256 symbols.

    .section kallsyms_token_table

      The full list of 256 tokens that have been used to compress the
      symbol names.

      Note that a token is arbitrarily sized.

    .section kallsyms_token_index

      A list of 2-bytes values representing the offsets of each token
      inside the <kallsyms_token_table> data.

    .section kallsyms_offsets

      <kallsyms_num_syms> entries, each entry is a 4 bytes value
      representing the offset of that symbol inside based on the
      relative base (the address of the lowest symbol).

    .section kallsyms_relative_base

      The base address used for relative offsets.

    .section kallsyms_seqs_of_names

      <kallsyms_num_syms> entries, each entry is a byte triplet
      representing the symbol index inside the token table.
  ```

  Kernel v6.8.0


  ```
    .section kallsyms_num_syms
    .section kallsyms_names
    .section kallsyms_markers
    .section kallsyms_token_table
    .section kallsyms_token_index

    if !base_relative {
        .section kallsyms_addresses
    } else {
        .section kallsyms_offsets
        .section kallsyms_relative_base
    }

    .section kallsyms_seqs_of_names
  ```

  Kernel v7.0.0

  ```
    .section kallsyms_num_syms
    .section kallsyms_names
    .section kallsyms_markers
    .section kallsyms_token_table
    .section kallsyms_token_index
    .section kallsyms_offsets
    .section kallsyms_seqs_of_names
  ```

  - `kallsyms_relative_base` was removed entirely. The `relative_base`
    variable and `record_relative_base()` were dropped from
    scripts/kallsyms.c.

  - `kallsyms_offsets` is now PC-relative by default (controlled by
    the new `--pc-relative` flag). Offsets are relative to `_text`,
    not to a separate base address. Symbol address reconstruction:
    `addr = offset_entry_value + offset_entry_position + _text`.

  - `kallsyms_addresses` (full 64-bit addresses) was also removed.
    The only mode is now `kallsyms_offsets`.

  - Alignment changed from 8-byte (`.balign 8`) to 4-byte (`.balign 4`).
    `kallsyms_num_syms` is emitted as `.long` (4 bytes) with no padding
    after it.
*/

use crate::{
    core::{
        architecture::{Architecture, Bitness},
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    operating_system::linux::kernel_version::KernelVersion,
    utils::memory_scanner::MemoryScanner,
};

use rayon::prelude::*;

use std::{collections::BTreeMap, ops::Range, vec};

/// The base of the kernel virtual address space
const KERNEL_VIRTUAL_ADDRESS_BASE: u64 = 0xFFFF800000000000;

/// Represents a single entry in the kallsyms_names data
type KallsymsNamesEntry = Vec<u16>;

/// Represents a list of kallsyms_names entries
type KallsymsNamesEntryList = Vec<KallsymsNamesEntry>;

/// Data for a single symbol entry
#[derive(Clone, Debug)]
pub struct SymbolData {
    /// The virtual address of the symbol
    pub address: RawVirtualAddress,

    /// The symbol type character
    pub symbol_type: char,
}

/// Represents an ongoing scan session for kallsyms data structures
#[derive(Clone)]
struct ScanSession {
    /// The root page table physical address
    root_page_table: PhysicalAddress,

    /// The kernel version
    kernel_version: KernelVersion,

    /// The kallsyms_token_table virtual address range
    kallsyms_token_table_range: Range<RawVirtualAddress>,

    /// The token table
    kallsyms_token_table: Vec<String>,

    /// The kallsyms_token_index virtual address range
    kallsyms_token_index_range: Option<Range<RawVirtualAddress>>,

    /// The token index table
    kallsyms_token_index: Vec<u16>,

    /// The kallsyms_markers virtual address range
    kallsyms_markers_range: Option<Range<RawVirtualAddress>>,

    /// The markers table
    kallsyms_markers: Vec<usize>,

    /// The kallsyms_num_syms virtual address range
    kallsyms_num_syms_range: Option<Range<RawVirtualAddress>>,

    /// The number of symbols
    kallsyms_num_syms: usize,

    /// The kallsyms_addresses virtual address range (CONFIG_KALLSYMS_BASE_RELATIVE=n only)
    kallsyms_addresses_range: Option<Range<RawVirtualAddress>>,

    /// The addresses table - full 64-bit addresses (CONFIG_KALLSYMS_BASE_RELATIVE=n only)
    kallsyms_addresses: Vec<usize>,

    /// The kallsyms_offsets virtual address range (CONFIG_KALLSYMS_BASE_RELATIVE=y only)
    kallsyms_offsets_range: Option<Range<RawVirtualAddress>>,

    /// The offsets table - 32-bit signed offsets (CONFIG_KALLSYMS_BASE_RELATIVE=y only)
    kallsyms_offsets: Vec<i32>,

    /// The kallsyms_relative_base virtual address range (CONFIG_KALLSYMS_BASE_RELATIVE=y only)
    kallsyms_relative_base_range: Option<Range<RawVirtualAddress>>,

    /// The relative base address (CONFIG_KALLSYMS_BASE_RELATIVE=y only)
    kallsyms_relative_base: Option<RawVirtualAddress>,

    /// The kallsyms_names virtual address range
    kallsyms_names_range: Option<Range<RawVirtualAddress>>,

    /// The names table
    kallsyms_names: KallsymsNamesEntryList,
}

impl ScanSession {
    /// Creates a new scan session
    fn new(
        root_page_table: PhysicalAddress,
        kernel_version: KernelVersion,
        kallsyms_token_table_range: Range<RawVirtualAddress>,
        kallsyms_token_table: Vec<String>,
    ) -> Self {
        Self {
            root_page_table,
            kernel_version,
            kallsyms_token_table_range,
            kallsyms_token_table,
            kallsyms_token_index_range: None,
            kallsyms_token_index: Vec::new(),
            kallsyms_markers_range: None,
            kallsyms_markers: Vec::new(),
            kallsyms_num_syms_range: None,
            kallsyms_num_syms: 0,
            kallsyms_addresses_range: None,
            kallsyms_addresses: Vec::new(),
            kallsyms_offsets_range: None,
            kallsyms_offsets: Vec::new(),
            kallsyms_relative_base_range: None,
            kallsyms_relative_base: None,
            kallsyms_names_range: None,
            kallsyms_names: KallsymsNamesEntryList::new(),
        }
    }
}

/// Represents a list of ongoing kallsyms scan sessions
type ScanSessionList = Vec<ScanSession>;

/// Represents the Linux kernel's kallsyms data structures
pub struct Kallsyms {
    /// The scan session used to locate and decompress the kallsyms data
    scan_session: ScanSession,

    /// A map of symbol names to their data
    symbol_map: BTreeMap<String, SymbolData>,
}

impl Kallsyms {
    /// Attempts to locate the kallsyms data structures in the provided memory dump
    pub fn new(
        memory_dump: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        kernel_version: &Option<KernelVersion>,
    ) -> Result<Self> {
        let kernel_version: &KernelVersion = kernel_version.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "A valid kernel version string is required to locate kallsyms data structures",
            )
        })?;

        let memory_range_list: Vec<Range<u64>> = architecture
            .enumerate_page_table_regions(memory_dump, root_page_table)?
            .into_iter()
            .map(|region| {
                let raw_start_vaddr = region.virtual_address.value();
                let int_start_vaddr = raw_start_vaddr.value();

                Range {
                    start: int_start_vaddr,
                    end: int_start_vaddr + region.size,
                }
            })
            .collect();

        let scan_session_list = Self::scan_for_kallsyms_token_table(
            memory_dump,
            architecture,
            root_page_table,
            &memory_range_list,
            kernel_version,
        )?;

        if scan_session_list.is_empty() {
            return Err(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate any kallsyms_token_table candidate",
            ));
        }

        let scan_session_list = Self::scan_for_kallsyms_token_index(
            memory_dump,
            architecture,
            root_page_table,
            scan_session_list,
            kernel_version,
        )?;

        if scan_session_list.is_empty() {
            return Err(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate any kallsyms_token_index candidate",
            ));
        }

        let scan_session_list = Self::scan_for_kallsyms_markers(
            memory_dump,
            architecture,
            root_page_table,
            scan_session_list,
            kernel_version,
        )?;

        if scan_session_list.is_empty() {
            return Err(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate any kallsyms_markers candidate",
            ));
        }

        let scan_session_list = Self::scan_for_kallsyms_num_syms(
            memory_dump,
            architecture,
            root_page_table,
            scan_session_list,
            kernel_version,
        )?;

        if scan_session_list.is_empty() {
            return Err(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate any kallsyms_num_syms candidate",
            ));
        }

        let mut scan_session_list = if kernel_version < &KernelVersion::new(7, 0, 0) {
            Self::scan_for_v6_kallsyms_offsets_or_addresses(
                memory_dump,
                architecture,
                root_page_table,
                scan_session_list,
                kernel_version,
            )?
        } else {
            Self::scan_for_v7_kallsyms_offsets(
                memory_dump,
                architecture,
                root_page_table,
                scan_session_list,
                kernel_version,
            )?
        };

        if scan_session_list.is_empty() {
            return Err(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate any kallsyms_offsets candidate",
            ));
        }

        // The kallsyms_relative_base field is no longer available/used in kernels >= 7.0.0
        if kernel_version < &KernelVersion::new(7, 0, 0) {
            scan_session_list = Self::scan_for_kallsyms_relative_base(
                memory_dump,
                architecture,
                root_page_table,
                scan_session_list,
                kernel_version,
            )?;

            if scan_session_list.is_empty() {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "Failed to locate any kallsyms_relative_base candidate",
                ));
            }
        }

        let scan_session_list = Self::scan_for_kallsyms_names(
            memory_dump,
            architecture,
            root_page_table,
            scan_session_list,
            kernel_version,
        )?;

        if scan_session_list.is_empty() {
            return Err(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate any kallsyms_names candidate",
            ));
        }

        for scan_session in scan_session_list {
            if let Ok(kallsyms) = Self::decompress_kallsyms(scan_session) {
                return Ok(kallsyms);
            }
        }

        Err(Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            "Failed to decompress the kallsyms data structures",
        ))
    }

    /// Gets the virtual address of a symbol by its name
    pub fn get(&self, symbol_name: &str) -> Option<VirtualAddress> {
        self.symbol_map.get(symbol_name).map(|symbol_data| {
            VirtualAddress::new(self.scan_session.root_page_table, symbol_data.address)
        })
    }

    /// Returns an iterator over all symbols with their names and data
    pub fn symbols(&self) -> impl Iterator<Item = (&str, &SymbolData)> + '_ {
        self.symbol_map
            .iter()
            .map(|(name, data)| (name.as_str(), data))
    }

    /// Decompresses kallsyms symbol names and builds a map of symbol names to symbol data
    fn decompress_kallsyms(scan_session: ScanSession) -> Result<Self> {
        let mut symbol_map = BTreeMap::new();

        for (index, name_entry) in scan_session.kallsyms_names.iter().enumerate() {
            if index >= scan_session.kallsyms_offsets.len() {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "The kallsyms_names index exceeds offsets table length",
                ));
            }

            let (symbol_name, symbol_type) = Self::decompress_symbol_name_with_type(
                name_entry,
                &scan_session.kallsyms_token_table,
            )?;

            let raw_vaddr = if scan_session.kernel_version >= KernelVersion::new(7, 0, 0) {
                // Kernels >= 7.0.0 no longer supports relative bases or absolute addresses.
                // Instead, we always use the entry-relative offset: &kallsyms_offsets[idx] +
                //                                                    kallsyms_offsets[idx]

                let entry_raw_vaddr = scan_session
                  .kallsyms_offsets_range
                  .as_ref()
                  .map(|range| range.start + (index * 4))
                  .ok_or_else(|| {
                    Error::new(
                        ErrorKind::OperatingSystemInitializationFailed,
                        "kallsyms_offsets/kallsyms_offsets_range is expected on >= 7.0.0 kernels",
                    )
                  })?;

                let relative_offset = scan_session
                                        .kallsyms_offsets
                                        .get(index)
                                        .map(|&offset| {
                                            // Sign extend, then cast to u64. The two's-complement
                                            // will allow us to just use wrapping_add
                                            offset as i64 as u64
                                        })
                                        .ok_or_else(|| {
                    Error::new(
                        ErrorKind::OperatingSystemInitializationFailed,
                        "kallsyms_offsets/kallsyms_offsets_range is expected on >= 7.0.0 kernels",
                    )
                })?;

                entry_raw_vaddr + relative_offset
            } else if scan_session.kallsyms_addresses_range.is_some() {
                RawVirtualAddress::new(scan_session.kallsyms_addresses[index] as u64)
            } else if let Some(kallsyms_relative_base) = &scan_session.kallsyms_relative_base {
                let offset = scan_session.kallsyms_offsets[index];

                //
                // From kernel/kallsyms.c kallsyms_sym_address():
                // - CONFIG_KALLSYMS_ABSOLUTE_PERCPU was removed in kernel 6.15
                //   (commit 01157ddc58dc "kallsyms: Remove KALLSYMS_ABSOLUTE_PERCPU")
                //
                // - Kernels >= 6.15 always use: kallsyms_relative_base + (u32)kallsyms_offsets[idx]
                // - Kernels < 6.15 with CONFIG_KALLSYMS_ABSOLUTE_PERCPU (default on x86_64 && SMP):
                //   - If offset >= 0: return kallsyms_offsets[idx] (absolute address, sign-extend)
                //   - If offset < 0: return kallsyms_relative_base - 1 - kallsyms_offsets[idx]
                //

                if scan_session.kernel_version >= KernelVersion::new(6, 15, 0) {
                    RawVirtualAddress::new(kallsyms_relative_base.value() + offset as u32 as u64)
                } else if offset >= 0 {
                    RawVirtualAddress::new(offset as i64 as u64)
                } else {
                    let base_minus_1 = kallsyms_relative_base.value() - 1;
                    let result = (base_minus_1 as i64 - offset as i64) as u64;
                    RawVirtualAddress::new(result)
                }
            } else {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "kallsyms_relative_base is required but missing",
                ));
            };

            symbol_map.insert(
                symbol_name,
                SymbolData {
                    address: raw_vaddr,
                    symbol_type,
                },
            );
        }

        Ok(Self {
            scan_session,
            symbol_map,
        })
    }

    /// Decompresses a symbol name from a list of token indices, returning the name and type
    fn decompress_symbol_name_with_type(
        token_indices: &[u16],
        token_table: &[String],
    ) -> Result<(String, char)> {
        let mut decompressed_name = String::new();

        for &token_index in token_indices {
            if token_index >= token_table.len() as u16 {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    &format!("Invalid token index {} in symbol name", token_index),
                ));
            }

            decompressed_name.push_str(&token_table[token_index as usize]);
        }

        let symbol_type = match decompressed_name.chars().next() {
            Some(c) => c,
            None => {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "Decompressed symbol name is empty",
                ));
            }
        };

        decompressed_name.remove(0);

        Ok((decompressed_name, symbol_type))
    }

    /// Scans the virtual memory for the kallsyms_token_table data
    fn scan_for_kallsyms_token_table(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        memory_range_list: &[Range<u64>],
        kernel_version: &KernelVersion,
    ) -> Result<ScanSessionList> {
        if kernel_version < &KernelVersion::new(6, 4, 0) {
            return Err(Error::new(
                ErrorKind::NotSupported,
                "scan_for_kallsyms_token_table is not yet implemented for kernel versions prior to 6.4",
            ));
        }

        // Locate the digits sequence, then search for the uppercase and lowercase patterns
        // within a small window after it.
        //
        // To find the start of the token table, scan backwards until encountering data
        // that cannot be part of the token table. Then, scan forward to locate the end,
        // ensuring exactly 256 tokens are present.
        const TOKEN_SEQUENCE_SCAN_SIZE: usize = 1024;
        const MAX_TOKEN_TABLE_SIZE: usize = 8192;

        const DIGITS_TOKEN_SEQUENCE: [u8; 20] = [
            b'0', 0x00, b'1', 0x00, b'2', 0x00, b'3', 0x00, b'4', 0x00, b'5', 0x00, b'6', 0x00,
            b'7', 0x00, b'8', 0x00, b'9', 0x00,
        ];

        // Scan backwards to find candidate start positions for the token table.
        //
        // Two consecutive null bytes means we encountered section padding (.balign 8)
        // from kernels < 7.x. In this case, we just return a single candidate past both
        // padding nulls. This is the easiest scenario.
        //
        // In all other cases, we scan backward until we end up inside the kallsyms_markers
        // section by looking for non-printable characters. From there we start scanning
        // forward again, generating a candidate for each potential token table entry (a null
        // byte followed by a printable character).
        fn find_token_table_start(buffer: &[u8], start_position: usize) -> Vec<usize> {
            let mut current_index = start_position;
            let mut prev_was_null = false;

            while current_index > 0 {
                let current_byte = buffer[current_index];

                if current_byte == 0 {
                    if prev_was_null {
                        return vec![current_index + 2];
                    }

                    prev_was_null = true;
                } else if current_byte <= 0x20 || current_byte >= 0x7F {
                    // We are now inside the kallsyms_markers section. Generate all
                    // the possible candidates now.
                    let boundary = current_index + 1;
                    let mut candidates = vec![boundary];

                    for pos in (boundary + 1)..=start_position {
                        if buffer[pos - 1] == 0 && buffer[pos] > 0x20 && buffer[pos] < 0x7F {
                            candidates.push(pos);
                        }
                    }

                    return candidates;
                } else {
                    prev_was_null = false;
                }

                current_index -= 1;
            }

            vec![]
        }

        // Scans forward to find the end of the token table.
        // A valid table must have exactly 256 tokens, each terminated by a single null byte.
        // The table ends after the 256th token's null terminator.
        fn find_token_table_end(buffer: &[u8]) -> Option<usize> {
            let mut current_token_count = 0;

            let mut current_index = 0;
            let mut prev_was_null = false;

            while current_index < buffer.len() {
                let current_byte = buffer[current_index];

                if current_byte == 0 {
                    if prev_was_null {
                        // Two consecutive null bytes means it's not a token, so this
                        // is an invalid candidate
                        return None;
                    }

                    prev_was_null = true;
                    current_token_count += 1;

                    // Check if we've exceeded 256 tokens
                    if current_token_count > 256 {
                        return None;
                    }

                    // Check if we've reached exactly 256 tokens
                    if current_token_count == 256 {
                        return Some(current_index + 1);
                    }
                } else {
                    // Check if this byte is a valid token character
                    if current_byte <= 0x20 || current_byte >= 0x7F {
                        return None;
                    }

                    prev_was_null = false;
                }

                current_index += 1;
            }

            // Skip if invalid or doesn't have exactly 256 tokens
            None
        }

        let active_scan_session_list: ScanSessionList = memory_range_list
            .par_iter()
            .filter(|range| range.start >= KERNEL_VIRTUAL_ADDRESS_BASE)
            .flat_map(|region| {
                let vmem_reader = VirtualMemoryReader::new(readable, architecture);
                let mut backward_scan_buffer = [0u8; TOKEN_SEQUENCE_SCAN_SIZE];
                let mut forward_scan_buffer = vec![0u8; MAX_TOKEN_TABLE_SIZE];
                let mut results = Vec::new();

                let start_vaddr = VirtualAddress::new(root_page_table, region.start.into());
                let end_vaddr = VirtualAddress::new(root_page_table, region.end.into());

                let digits_vaddr_iter = match MemoryScanner::new(
                    &vmem_reader,
                    start_vaddr,
                    end_vaddr,
                    &DIGITS_TOKEN_SEQUENCE,
                ) {
                    Ok(scanner) => scanner.filter_map(|r| r.ok()),
                    Err(_) => return results,
                };

                for digits_vaddr in digits_vaddr_iter {
                    if vmem_reader
                        .read_exact(
                            &mut backward_scan_buffer,
                            digits_vaddr - TOKEN_SEQUENCE_SCAN_SIZE,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    let scan_positions = find_token_table_start(
                        &backward_scan_buffer,
                        backward_scan_buffer.len() - 1,
                    );

                    for scan_position in scan_positions {
                        let token_table_start_vaddr =
                            digits_vaddr - TOKEN_SEQUENCE_SCAN_SIZE + scan_position;

                        // Scan forward to locate the end of the token table: a valid table must have exactly
                        // 256 tokens, each terminated by a single null byte. After the null byte of the last
                        // token, the table ends.
                        if vmem_reader
                            .read_exact(&mut forward_scan_buffer, token_table_start_vaddr)
                            .is_err()
                        {
                            continue;
                        }

                        let token_table_end_pos = match find_token_table_end(&forward_scan_buffer) {
                            Some(pos) => pos,
                            None => continue,
                        };

                        let kallsyms_token_table_range = Range {
                            start: token_table_start_vaddr.value(),
                            end: token_table_start_vaddr.value() + token_table_end_pos as u64,
                        };

                        let mut read_buffer = vec![0u8; token_table_end_pos];
                        if vmem_reader
                            .read_exact(&mut read_buffer, token_table_start_vaddr)
                            .is_err()
                        {
                            continue;
                        }

                        let kallsyms_token_table = read_buffer
                            .split(|&byte| byte == 0)
                            .take(256)
                            .map(|token| String::from_utf8_lossy(token).to_string())
                            .collect();

                        results.push(ScanSession::new(
                            root_page_table,
                            kernel_version.clone(),
                            kallsyms_token_table_range,
                            kallsyms_token_table,
                        ));
                    }
                }

                results
            })
            .collect();

        Ok(active_scan_session_list)
    }

    /// Scans the virtual memory for the kallsyms_token_index data, starting
    /// from a list of possible kallsyms_token_table locations
    fn scan_for_kallsyms_token_index(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        scan_session_list: ScanSessionList,
        kernel_version: &KernelVersion,
    ) -> Result<ScanSessionList> {
        if kernel_version < &KernelVersion::new(6, 4, 0) {
            return Err(Error::new(
                ErrorKind::NotSupported,
                "scan_for_kallsyms_token_index is not yet implemented for kernel versions prior to 6.4",
            ));
        }

        const SCAN_WINDOW_SIZE: u64 = 10 * 1024 * 1024;

        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let mut active_scan_session_list = ScanSessionList::new();

        for scan_session in scan_session_list {
            let token_table_candidate = &scan_session.kallsyms_token_table_range;
            let token_table_vaddr =
                VirtualAddress::new(root_page_table, token_table_candidate.start);

            let token_table_size =
                (token_table_candidate.end - token_table_candidate.start) as usize;

            let mut token_table = vec![0u8; token_table_size];
            if vmem_reader
                .read_exact(&mut token_table, token_table_vaddr)
                .is_err()
            {
                continue;
            }

            let expected_token_index_table: Vec<u8> = vec![0u8, 0u8]
                .into_iter()
                .chain(
                    token_table
                        .iter()
                        .enumerate()
                        .filter_map(|(index, &byte)| {
                            if byte != 0 || index + 1 >= token_table.len() {
                                return None;
                            }

                            Some((index as u16 + 1).to_le_bytes())
                        })
                        .flatten(),
                )
                .collect();

            let scan_window_base = token_table_vaddr - (SCAN_WINDOW_SIZE / 2);
            let scan_window_end = token_table_vaddr + token_table_size + (SCAN_WINDOW_SIZE / 2);

            let token_table_vaddr_it = MemoryScanner::new(
                &vmem_reader,
                scan_window_base,
                scan_window_end,
                &expected_token_index_table,
            )?
            .filter_map(|r| r.ok());

            let new_scan_session_list: ScanSessionList = token_table_vaddr_it
                .map(|vaddr| {
                    let mut new_scan_session = scan_session.clone();
                    new_scan_session.kallsyms_token_index_range = Some(Range {
                        start: vaddr.value(),
                        end: vaddr.value() + expected_token_index_table.len() as u64,
                    });

                    new_scan_session.kallsyms_token_index = expected_token_index_table
                        .chunks(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();

                    new_scan_session
                })
                .collect();

            active_scan_session_list.extend(new_scan_session_list);
        }

        Ok(active_scan_session_list)
    }

    /// Scans the virtual memory for the kallsyms_markers data, starting
    /// from a list of possible kallsyms_token_table locations
    fn scan_for_kallsyms_markers(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        scan_session_list: ScanSessionList,
        kernel_version: &KernelVersion,
    ) -> Result<ScanSessionList> {
        if kernel_version < &KernelVersion::new(6, 4, 0) {
            return Err(Error::new(
                ErrorKind::NotSupported,
                "scan_for_kallsyms_markers is not yet implemented for kernel versions prior to 6.4",
            ));
        }

        // The markers data contains a list of 4-byte offsets pointing to the beginning
        // of each 256-symbol group in the kallsyms_names data.
        // The first entry is always 0, which can be used as a landmark to locate the data.
        const FIRST_TOKEN_MARKERS_ENTRY: [u8; 4] = 0u32.to_le_bytes();
        const SCAN_WINDOW_SIZE: u64 = 10 * 1024 * 1024;

        let mut active_scan_session_list = ScanSessionList::new();

        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let mut read_buffer = vec![0u8; SCAN_WINDOW_SIZE as usize];

        for scan_session in scan_session_list {
            let token_table_candidate = &scan_session.kallsyms_token_table_range;
            let scan_window_vaddr =
                VirtualAddress::new(root_page_table, token_table_candidate.start)
                    - SCAN_WINDOW_SIZE;

            if vmem_reader
                .read_exact(&mut read_buffer, scan_window_vaddr)
                .is_err()
            {
                continue;
            }

            let mut current_scan_start_pos = read_buffer.len() - 1;

            // The kallsyms symbol data layout may include extra sections between the token table
            // and the markers table.
            // To account for this, we repeat the scan multiple times and filter out invalid
            // candidates afterward.
            for _ in 0..5 {
                // Skip any empty entry at the end of the markers table: find the last
                // non-null byte, and then align it to the next entry boundary.
                let unaligned_markers_table_end = read_buffer[..current_scan_start_pos]
                    .iter()
                    .rposition(|&byte| byte != 0)
                    .unwrap_or(read_buffer.len() - 1);

                let markers_table_end = unaligned_markers_table_end
                    .div_ceil(FIRST_TOKEN_MARKERS_ENTRY.len())
                    * FIRST_TOKEN_MARKERS_ENTRY.len();

                let markers_table_start = match read_buffer[..markers_table_end]
                    .windows(FIRST_TOKEN_MARKERS_ENTRY.len())
                    .enumerate()
                    .rev()
                    .filter(|(index, _)| index % FIRST_TOKEN_MARKERS_ENTRY.len() == 0)
                    .find_map(|(index, window)| {
                        if *window == FIRST_TOKEN_MARKERS_ENTRY {
                            Some(index)
                        } else {
                            None
                        }
                    }) {
                    Some(pos) => pos,
                    None => break,
                };

                current_scan_start_pos = markers_table_start;

                let markers_table: Vec<usize> = read_buffer[markers_table_start..markers_table_end]
                    .chunks_exact(FIRST_TOKEN_MARKERS_ENTRY.len())
                    .map(|chunk| {
                        if chunk.len() == 4 {
                            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize
                        } else if chunk.len() == 8 {
                            u64::from_le_bytes([
                                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5],
                                chunk[6], chunk[7],
                            ]) as usize
                        } else {
                            unreachable!()
                        }
                    })
                    .collect();

                // The smallest entry we can have inside the kallsyms_names data is 2 bytes:
                //  - 1 byte for the length
                //  - 1 byte containing a token index
                //
                // The largest entry we can have is 32769 bytes:
                //  - 2 bytes for the length: 32767 (represented as 0x80, 0x7F - you need to mask
                //      out the high bit of the first byte)
                //  - 32767 bytes containing token indexes
                //
                // Since the markers point to the beginning of each 256-symbol group, we can
                // compute the minimum and maximum possible increment between two consecutive
                // entries:
                //
                // Min: 256 * 2 = 0x00000200
                // Max: 256 * 32769 = 0x00800100
                //
                // We can use this information to filter out invalid candidates.
                const MIN_MARKER_INCREMENT: usize = 0x00000200;
                const MAX_MARKER_INCREMENT: usize = 0x00800100;

                let invalid_progression_found = markers_table.windows(2).any(|entry_pair| {
                    entry_pair[1] - entry_pair[0] < MIN_MARKER_INCREMENT
                        || entry_pair[1] - entry_pair[0] > MAX_MARKER_INCREMENT
                });

                if !invalid_progression_found {
                    let mut new_scan_session = scan_session.clone();
                    new_scan_session.kallsyms_markers_range = Some(Range {
                        start: scan_window_vaddr.value() + markers_table_start as u64,
                        end: scan_window_vaddr.value() + markers_table_end as u64,
                    });

                    new_scan_session.kallsyms_markers = markers_table;

                    active_scan_session_list.push(new_scan_session);
                }
            }
        }

        Ok(active_scan_session_list)
    }

    /// Scans the virtual memory for the kallsyms_num_syms data
    fn scan_for_kallsyms_num_syms(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        scan_session_list: ScanSessionList,
        kernel_version: &KernelVersion,
    ) -> Result<ScanSessionList> {
        if kernel_version < &KernelVersion::new(6, 4, 0) {
            return Err(Error::new(
                ErrorKind::NotSupported,
                "scan_for_kallsyms_num_syms is not yet implemented for kernel versions prior to 6.4",
            ));
        }

        // Locate kallsyms_num_syms by searching for linux_banner
        //
        // In kernel v6.4+ (commit 404bad70fcf7), kallsyms data structure order was
        // reorganized to place kallsyms_num_syms first, making it reliably locatable
        // via the linux_banner string that precedes it.
        //
        // Prior to v6.4 (kernels 5.x through 6.3), kallsyms_offsets came first,
        // making this heuristic invalid for older kernels.
        //
        // Memory layout (v6.4+):
        //   1. linux_banner      - "Linux version X.Y.Z ..." null-terminated string
        //   2. [padding]         - 0-7 bytes to align to 8-byte boundary
        //   3. kallsyms_num_syms - 4-byte unsigned int (little-endian)
        //   ... (remaining kallsyms structures)
        //
        //  The kernel build process (scripts/link-vmlinux.sh) links object files
        //  in a specific order:
        //    ld \
        //      ... \
        //      vmlinux.a \
        //      init/version-timestamp.o \
        //      ${kallsymso} \
        //      ...
        //
        //  The linker script (include/asm-generic/vmlinux.lds.h) merges all .rodata
        //  sections using the wildcard pattern "*(.rodata)", which concatenates
        //  sections in command-line order:
        //    [.rodata from vmlinux.a]
        //    [version-timestamp.o]
        //    [kallsymso]
        //
        //  Since both linux_banner (in version-timestamp.o) and kallsyms data
        //  (in kallsymso) reside in .rodata, and kallsyms_num_syms is now first
        //  in the kallsyms structure (v6.4+), it appears immediately yet
        //  linux_banner with only alignment padding between them.
        //
        // References:
        //   - scripts/link-vmlinux.sh (link order)
        //   - scripts/kallsyms.c:write_src() (structure generation)
        //   - init/version-timestamp.c (linux_banner definition)
        //   - include/asm-generic/vmlinux.lds.h (RO_DATA macro)
        //   - commit 404bad70fcf7 "scripts/kallsyms: change the output order" (v6.4)

        const SCAN_WINDOW_SIZE: u64 = 10 * 1024 * 1024;
        const KALLSYMS_NUM_SYS_SIZE: u64 = 4;

        let expected_linux_banner_prefix = format!(
            "Linux version {}.{}.{}",
            kernel_version.major, kernel_version.minor, kernel_version.patch
        )
        .into_bytes();

        let mut active_scan_session_list = ScanSessionList::new();

        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let mut read_buffer = vec![0u8; SCAN_WINDOW_SIZE as usize];

        for scan_session in scan_session_list {
            let kallsyms_markers_range = match &scan_session.kallsyms_markers_range {
                Some(range) => range,
                None => continue,
            };

            let scan_window_end =
                VirtualAddress::new(root_page_table, kallsyms_markers_range.start);

            let scan_window_start = scan_window_end - SCAN_WINDOW_SIZE;

            if vmem_reader
                .read_exact(&mut read_buffer, scan_window_start)
                .is_err()
            {
                continue;
            }

            let linux_banner_start = match read_buffer
                .windows(expected_linux_banner_prefix.len())
                .enumerate()
                .rev()
                .find_map(|(index, window)| {
                    if window == expected_linux_banner_prefix.as_slice() {
                        Some(index)
                    } else {
                        None
                    }
                }) {
                Some(pos) => pos,
                None => continue,
            };

            let linux_banner_end = match read_buffer[linux_banner_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|pos| linux_banner_start + pos)
            {
                Some(pos) => pos,
                None => continue,
            };

            let aligned_kallsyms_num_syms_offset = ((linux_banner_end + 1 + 3) & !3) as u64;

            let kallsyms_num_syms_start = scan_window_start + aligned_kallsyms_num_syms_offset;
            let kallsyms_num_syms_end = kallsyms_num_syms_start + KALLSYMS_NUM_SYS_SIZE;

            let kallsyms_num_syms = match vmem_reader.read_u32(kallsyms_num_syms_start) {
                Ok(value) => value as usize,
                Err(_) => continue,
            };

            // We know that we have one marker entry every 256 symbols, but we don't
            // know how many we have in the last group.
            let marker_count = scan_session.kallsyms_markers.len();

            let min_expected_marker_count = (marker_count - 1) * 256 + 1;
            let max_expected_marker_count = marker_count * 256;

            if kallsyms_num_syms < min_expected_marker_count
                || kallsyms_num_syms > max_expected_marker_count
            {
                continue;
            }

            let mut new_scan_session = scan_session.clone();
            new_scan_session.kallsyms_num_syms_range = Some(Range {
                start: kallsyms_num_syms_start.value(),
                end: kallsyms_num_syms_end.value(),
            });

            new_scan_session.kallsyms_num_syms = kallsyms_num_syms;

            active_scan_session_list.push(new_scan_session);
        }

        Ok(active_scan_session_list)
    }

    /// Scans the virtual memory for the kallsyms_offsets or kallsyms_addresses data
    fn scan_for_v7_kallsyms_offsets(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        scan_session_list: ScanSessionList,
        kernel_version: &KernelVersion,
    ) -> Result<ScanSessionList> {
        if kernel_version < &KernelVersion::new(7, 0, 0) {
            return Err(Error::new(
                ErrorKind::NotSupported,
                "scan_for_v7_kallsyms_offsets is only implemented for kernel versions equal to or greater than 7.0.0",
            ));
        }

        const KALLSYMS_OFFSET_ENTRY_SIZE: usize = 4;

        let mut active_scan_session_list = ScanSessionList::new();
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);

        for scan_session in &scan_session_list {
            let kallsyms_num_syms = match scan_session.kallsyms_num_syms_range {
                Some(_) => scan_session.kallsyms_num_syms,
                None => continue,
            };

            let kallsyms_token_index_range = match &scan_session.kallsyms_token_index_range {
                Some(range) => range,
                None => continue,
            };

            let unaligned_offset = kallsyms_token_index_range.end.value();
            let aligned_offset = unaligned_offset.div_ceil(KALLSYMS_OFFSET_ENTRY_SIZE as u64)
                * KALLSYMS_OFFSET_ENTRY_SIZE as u64;

            let start = RawVirtualAddress::new(aligned_offset);

            let array_size = kallsyms_num_syms * 4;
            let end = start + array_size;

            let mut read_buffer = vec![0u8; array_size];
            if vmem_reader
                .read_exact(
                    &mut read_buffer,
                    VirtualAddress::new(root_page_table, start),
                )
                .is_err()
            {
                continue;
            }

            let mut new_scan_session = scan_session.clone();
            new_scan_session.kallsyms_offsets_range = Some(Range { start, end });

            new_scan_session.kallsyms_offsets = read_buffer
                .chunks_exact(KALLSYMS_OFFSET_ENTRY_SIZE)
                .map(|chunk| i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect();

            active_scan_session_list.push(new_scan_session);
        }

        Ok(active_scan_session_list)
    }

    /// Scans the virtual memory for the kallsyms_offsets or kallsyms_addresses data
    /// Limited to Linux kernels < 7.0.0
    fn scan_for_v6_kallsyms_offsets_or_addresses(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        scan_session_list: ScanSessionList,
        kernel_version: &KernelVersion,
    ) -> Result<ScanSessionList> {
        if kernel_version >= &KernelVersion::new(7, 0, 0) {
            return Err(Error::new(
                ErrorKind::NotSupported,
                "scan_for_v6_kallsyms_offsets_or_addresses is only implemented for kernel versions prior to 7.0.0",
            ));
        }

        const KALLSYMS_OFFSET_ENTRY_SIZE: usize = 4;
        const KALLSYMS_ADDRESS_ENTRY_SIZE: usize = 8;

        let mut active_scan_session_list = ScanSessionList::new();
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);

        for scan_session in &scan_session_list {
            let kallsyms_num_syms = match scan_session.kallsyms_num_syms_range {
                Some(_) => scan_session.kallsyms_num_syms,
                None => continue,
            };

            let kallsyms_token_index_range = match &scan_session.kallsyms_token_index_range {
                Some(range) => range,
                None => continue,
            };

            let unaligned_offset = kallsyms_token_index_range.end.value();
            let aligned_offset = unaligned_offset.div_ceil(KALLSYMS_OFFSET_ENTRY_SIZE as u64)
                * KALLSYMS_OFFSET_ENTRY_SIZE as u64;

            let start = RawVirtualAddress::new(aligned_offset);

            // At this point, depending on the kernel version and kernel build options, we
            // could either have a `kallsyms_offsets` as a list of `kallsyms_num_syms` 4-byte
            // values, or a `kallsyms_addresses` as a list of `kallsyms_num_syms` 8-byte values.
            let first_entry =
                match vmem_reader.read_u64(VirtualAddress::new(root_page_table, start)) {
                    Ok(val) => val,
                    Err(_) => continue,
                };

            let (entry_size, config_kallsyms_base_relative) =
                if first_entry >= KERNEL_VIRTUAL_ADDRESS_BASE {
                    (KALLSYMS_ADDRESS_ENTRY_SIZE, false)
                } else {
                    (KALLSYMS_OFFSET_ENTRY_SIZE, true)
                };

            let array_size = kallsyms_num_syms * entry_size;
            let end = start + array_size;

            let mut read_buffer = vec![0u8; array_size];
            if vmem_reader
                .read_exact(
                    &mut read_buffer,
                    VirtualAddress::new(root_page_table, start),
                )
                .is_err()
            {
                continue;
            }

            let mut new_scan_session = scan_session.clone();
            if config_kallsyms_base_relative {
                new_scan_session.kallsyms_offsets_range = Some(Range { start, end });

                new_scan_session.kallsyms_offsets = read_buffer
                    .chunks_exact(KALLSYMS_OFFSET_ENTRY_SIZE)
                    .map(|chunk| i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect();
            } else {
                new_scan_session.kallsyms_addresses_range = Some(Range { start, end });

                new_scan_session.kallsyms_addresses = read_buffer
                    .chunks_exact(KALLSYMS_ADDRESS_ENTRY_SIZE)
                    .map(|chunk| {
                        u64::from_le_bytes([
                            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                            chunk[7],
                        ]) as usize
                    })
                    .collect();
            }

            active_scan_session_list.push(new_scan_session);
        }

        Ok(active_scan_session_list)
    }

    /// Scans the virtual memory for the kallsyms_relative_base data
    fn scan_for_kallsyms_relative_base(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        scan_session_list: ScanSessionList,
        kernel_version: &KernelVersion,
    ) -> Result<ScanSessionList> {
        if kernel_version < &KernelVersion::new(6, 4, 0) {
            return Err(Error::new(
                ErrorKind::NotSupported,
                "scan_for_kallsyms_relative_base is not yet implemented for kernel versions prior to 6.4",
            ));
        }

        let kallsyms_relative_base_size: usize = match architecture.bitness() {
            Bitness::Bit64 => 8,
        };

        let mut active_scan_session_list = ScanSessionList::new();
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);

        for scan_session in &scan_session_list {
            if scan_session.kallsyms_addresses_range.is_some() {
                active_scan_session_list.push(scan_session.clone());
                continue;
            }

            let kallsyms_token_index_range = match &scan_session.kallsyms_offsets_range {
                Some(range) => range,
                None => continue,
            };

            let unaligned_offset = kallsyms_token_index_range.end.value();
            let aligned_offset = unaligned_offset.div_ceil(kallsyms_relative_base_size as u64)
                * kallsyms_relative_base_size as u64;

            let start = RawVirtualAddress::new(aligned_offset);
            let end = start + kallsyms_relative_base_size;

            let kallsyms_relative_base_start = VirtualAddress::new(root_page_table, start);

            let kallsyms_relative_base = match architecture.bitness() {
                Bitness::Bit64 => match vmem_reader
                    .read_u64(kallsyms_relative_base_start)
                    .map(RawVirtualAddress::new)
                {
                    Ok(addr) => addr,
                    Err(_) => {
                        continue;
                    }
                },
            };

            if kallsyms_relative_base.value() < KERNEL_VIRTUAL_ADDRESS_BASE {
                continue;
            }

            let mut new_scan_session = scan_session.clone();
            new_scan_session.kallsyms_relative_base_range = Some(Range { start, end });
            new_scan_session.kallsyms_relative_base = Some(kallsyms_relative_base.canonicalized());

            active_scan_session_list.push(new_scan_session);
        }

        Ok(active_scan_session_list)
    }

    /// Scans the virtual memory for the kallsyms_names data
    fn scan_for_kallsyms_names(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        root_page_table: PhysicalAddress,
        scan_session_list: ScanSessionList,
        kernel_version: &KernelVersion,
    ) -> Result<ScanSessionList> {
        if kernel_version < &KernelVersion::new(6, 4, 0) {
            return Err(Error::new(
                ErrorKind::NotSupported,
                "scan_for_kallsyms_names is not yet implemented for kernel versions prior to 6.4",
            ));
        }

        const SCAN_WINDOW_SIZE: u64 = 10 * 1024 * 1024;

        let mut active_scan_session_list = ScanSessionList::new();
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);

        for scan_session in &scan_session_list {
            let kallsyms_num_syms_range = match &scan_session.kallsyms_num_syms_range {
                Some(range) => range,
                None => continue,
            };

            let unaligned_offset = kallsyms_num_syms_range.end.value();
            let aligned_offset = unaligned_offset.div_ceil(8_u64) * 8_u64;

            let start = RawVirtualAddress::new(aligned_offset);

            let mut read_buffer = vec![0u8; SCAN_WINDOW_SIZE as usize];
            if vmem_reader
                .read_exact(
                    &mut read_buffer,
                    VirtualAddress::new(root_page_table, start),
                )
                .is_err()
            {
                continue;
            }

            let mut entry_list = KallsymsNamesEntryList::new();
            let mut current_index = 0;

            while entry_list.len() < scan_session.kallsyms_num_syms {
                if current_index >= read_buffer.len() {
                    break;
                }

                let first_length_byte = read_buffer[current_index];
                current_index += 1;

                let mut name_length = (first_length_byte & 0x7F) as usize;
                if (first_length_byte & 0x80) != 0 {
                    if current_index >= read_buffer.len() {
                        break;
                    }

                    let second_length_byte = read_buffer[current_index];
                    current_index += 1;

                    name_length |= (second_length_byte as usize) << 7;
                }

                if current_index + name_length > read_buffer.len() {
                    break;
                }

                let token_index_list: KallsymsNamesEntry = read_buffer
                    [current_index..current_index + name_length]
                    .iter()
                    .map(|&b| b as u16)
                    .collect();

                current_index += name_length;
                entry_list.push(token_index_list);
            }

            let end = RawVirtualAddress::new(aligned_offset + current_index as u64);

            let mut new_scan_session = scan_session.clone();
            new_scan_session.kallsyms_names = entry_list;
            new_scan_session.kallsyms_names_range = Some(Range { start, end });

            active_scan_session_list.push(new_scan_session);
        }

        Ok(active_scan_session_list)
    }
}
