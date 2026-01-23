//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::virtual_memory_reader::VirtualMemoryReader,
    generate_address_ranges,
    memory::{
        error::{Error, ErrorKind, Result},
        virtual_address::VirtualAddress,
    },
};

use std::ops::Range;

/// Trait for pattern matching algorithms used by MemoryScannerBase.
///
/// Implementations provide the core pattern matching logic while the scanner
/// handles buffer management, I/O, and address range tracking.
pub trait ScanAlgorithm: Sized {
    /// Creates a new algorithm instance for the given pattern.
    ///
    /// Returns an error if the pattern is invalid (e.g., empty).
    fn new(pattern: &[u8]) -> Result<Self>;

    /// Returns the pattern being searched for.
    fn pattern(&self) -> &[u8];

    /// Finds the next match in the buffer starting from `start_offset`.
    ///
    /// Returns `Some(offset)` if a match is found, where `offset` is the
    /// position in the buffer where the pattern starts. Returns `None` if
    /// no match exists between `start_offset` and the end of searchable area
    /// (i.e., `bytes_available - pattern.len()`).
    fn find_next_match(
        &self,
        buffer: &[u8],
        start_offset: usize,
        bytes_available: usize,
    ) -> Option<usize>;
}

/// Boyer-Moore-Horspool pattern matching algorithm (u8 variant).
///
/// Uses a bad character skip table for efficient searching. Average case
/// complexity is O(n/m) where n is text length and m is pattern length.
pub struct BMHScanAlgorithm {
    pattern: Vec<u8>,
    /// Bad character skip table - skip_table[byte] gives the skip distance
    /// when `byte` is found at the end of a non-matching window.
    skip_table: [usize; 256],
}

impl ScanAlgorithm for BMHScanAlgorithm {
    fn new(pattern: &[u8]) -> Result<Self> {
        if pattern.is_empty() {
            return Err(Error::new(ErrorKind::IOError, "Pattern cannot be empty"));
        }

        let pattern_len = pattern.len();

        // Build Boyer-Moore-Horspool bad character skip table
        let mut skip_table = [pattern_len; 256];
        for (i, &byte) in pattern[..pattern_len - 1].iter().enumerate() {
            skip_table[byte as usize] = pattern_len - 1 - i;
        }

        Ok(Self {
            pattern: pattern.to_vec(),
            skip_table,
        })
    }

    fn pattern(&self) -> &[u8] {
        &self.pattern
    }

    fn find_next_match(
        &self,
        buffer: &[u8],
        start_offset: usize,
        bytes_available: usize,
    ) -> Option<usize> {
        let pattern_len = self.pattern.len();
        let mut offset = start_offset;

        while offset + pattern_len <= bytes_available {
            let window = &buffer[offset..offset + pattern_len];

            if window == self.pattern.as_slice() {
                return Some(offset);
            }

            // Skip based on the last byte in the window
            let last_byte = window[pattern_len - 1];
            offset += self.skip_table[last_byte as usize];
        }

        None
    }
}

/// Boyer-Moore-Horspool pattern matching algorithm (u16 variant).
///
/// Uses a u16 bigram skip table with a bloom filter for fast rejection.
/// Instead of a 65536-entry array, uses a sorted list of (bigram, skip)
/// pairs with a 64-bit bloom filter mask to quickly reject bigrams not
/// in the pattern.
///
/// Optimized for longer patterns (10+ bytes) where the bigram table
/// provides better skip distances than single-byte lookups.
pub struct BMH16ScanAlgorithm {
    pattern: Vec<u8>,
    /// Bloom filter mask - bit at position hash(bigram) is set if bigram might be in table
    mask: u64,
    /// Sorted list of (bigram, skip_distance) pairs for bigrams in the pattern
    skip_table: Vec<(u16, usize)>,
    /// First byte of pattern, used for edge case when bigram not in table
    first_byte: u8,
}

impl BMH16ScanAlgorithm {
    /// Hash a u16 value to a 6-bit index (0-63) using multiply-shift.
    /// Uses a golden ratio derived constant for good bit mixing.
    #[inline]
    fn hash_u16(value: u16) -> u32 {
        (value as u32).wrapping_mul(0x9E3779B9) >> 26
    }

    /// Look up the skip distance for a bigram.
    #[inline]
    fn get_skip(&self, bigram: u16) -> usize {
        let bit = 1u64 << Self::hash_u16(bigram);

        if (self.mask & bit) == 0 {
            // Definitely not in table - check edge case
            return self.default_skip(bigram);
        }

        // Might be in table, binary search
        match self.skip_table.binary_search_by_key(&bigram, |&(v, _)| v) {
            Ok(idx) => self.skip_table[idx].1,
            Err(_) => self.default_skip(bigram),
        }
    }

    /// Calculate default skip when bigram is not in the table.
    /// If the bigram's second byte equals pattern[0], a match could exist
    /// at offset + pattern_len - 1, so we can only skip pattern_len - 1.
    /// Otherwise, we can safely skip the full pattern length.
    #[inline]
    fn default_skip(&self, bigram: u16) -> usize {
        let second_byte = (bigram >> 8) as u8;
        if second_byte == self.first_byte {
            self.pattern.len() - 1
        } else {
            self.pattern.len()
        }
    }
}

impl ScanAlgorithm for BMH16ScanAlgorithm {
    fn new(pattern: &[u8]) -> Result<Self> {
        if pattern.len() < 2 {
            return Err(Error::new(
                ErrorKind::IOError,
                "Pattern must be at least 2 bytes for BMH16",
            ));
        }

        let pattern_len = pattern.len();
        let first_byte = pattern[0];
        let mut mask = 0u64;

        // Build skip table directly without HashMap allocation.
        // Iterate in reverse order so rightmost occurrences (smallest skips) come first.
        // After stable sort and dedup, we keep the smallest skip for each bigram.
        let mut skip_table: Vec<(u16, usize)> = Vec::with_capacity(pattern_len.saturating_sub(2));

        for i in (0..pattern_len.saturating_sub(2)).rev() {
            let bigram = u16::from_le_bytes([pattern[i], pattern[i + 1]]);
            let skip = pattern_len - 2 - i;

            // Set bloom filter bit
            mask |= 1u64 << Self::hash_u16(bigram);

            skip_table.push((bigram, skip));
        }

        // Sort by bigram (stable sort preserves order among equal keys)
        skip_table.sort_by_key(|&(k, _)| k);

        // Deduplicate by bigram, keeping first (which has smallest skip due to reverse iteration)
        skip_table.dedup_by(|a, b| a.0 == b.0);

        Ok(Self {
            pattern: pattern.to_vec(),
            mask,
            skip_table,
            first_byte,
        })
    }

    fn pattern(&self) -> &[u8] {
        &self.pattern
    }

    fn find_next_match(
        &self,
        buffer: &[u8],
        start_offset: usize,
        bytes_available: usize,
    ) -> Option<usize> {
        let pattern_len = self.pattern.len();
        let mut offset = start_offset;

        while offset + pattern_len <= bytes_available {
            let window = &buffer[offset..offset + pattern_len];

            if window == self.pattern.as_slice() {
                return Some(offset);
            }

            // Get the last bigram of the window (little-endian)
            let last_bigram = u16::from_le_bytes([
                buffer[offset + pattern_len - 2],
                buffer[offset + pattern_len - 1],
            ]);

            offset += self.get_skip(last_bigram);
        }

        None
    }
}

/// Boyer-Moore-Horspool pattern matching algorithm (u32 variant).
///
/// Uses a u32 quadgram skip table with a bloom filter for fast rejection.
/// Instead of a 4 billion-entry array, uses a sorted list of (quadgram, skip)
/// pairs with a 4096-bit bloom filter to quickly reject quadgrams not
/// in the pattern.
///
/// Optimized for longer patterns (10+ bytes) where the quadgram table
/// provides better skip distances and dramatically fewer false positives
/// compared to the u16 variant.
pub struct BMH32ScanAlgorithm {
    pattern: Vec<u8>,
    /// Bloom filter - 4096 bits (64 x u64) indexed by 12-bit hash
    bloom: [u64; 64],
    /// Sorted list of (quadgram, skip_distance) pairs for quadgrams in the pattern
    skip_table: Vec<(u32, usize)>,
    /// First 3 bytes of pattern, used for edge case overlap checks
    prefix: [u8; 3],
}

impl BMH32ScanAlgorithm {
    /// Hash a u32 value to a 12-bit index (0-4095) using MurmurHash3 finalmix.
    /// Provides excellent bit mixing to ensure all 32 input bits influence the output.
    #[inline]
    fn hash_u32(value: u32) -> u32 {
        let mut h = value;
        h ^= h >> 16;
        h = h.wrapping_mul(0x85ebca6b);
        h ^= h >> 13;
        h = h.wrapping_mul(0xc2b2ae35);
        h ^= h >> 16;
        h >> 20 // 12-bit hash (0-4095)
    }

    /// Check if a bit is set in the bloom filter.
    #[inline]
    fn bloom_check(&self, hash: u32) -> bool {
        let word_idx = (hash >> 6) as usize; // Upper 6 bits select the u64
        let bit_idx = hash & 63; // Lower 6 bits select the bit
        (self.bloom[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Set a bit in the bloom filter.
    #[inline]
    fn bloom_set(bloom: &mut [u64; 64], hash: u32) {
        let word_idx = (hash >> 6) as usize;
        let bit_idx = hash & 63;
        bloom[word_idx] |= 1u64 << bit_idx;
    }

    /// Look up the skip distance for a quadgram.
    #[inline]
    fn get_skip(&self, quadgram: u32) -> usize {
        let hash = Self::hash_u32(quadgram);

        if !self.bloom_check(hash) {
            // Definitely not in table - check edge cases
            return self.default_skip(quadgram);
        }

        // Might be in table, binary search
        match self.skip_table.binary_search_by_key(&quadgram, |&(v, _)| v) {
            Ok(idx) => self.skip_table[idx].1,
            Err(_) => self.default_skip(quadgram),
        }
    }

    /// Calculate default skip when quadgram is not in the table.
    /// Checks for potential overlaps between the quadgram's suffix and the pattern's prefix.
    #[inline]
    fn default_skip(&self, quadgram: u32) -> usize {
        let bytes = quadgram.to_le_bytes();

        // Check 3-byte overlap: bytes[1..4] == pattern[0..3]
        if bytes[1] == self.prefix[0] && bytes[2] == self.prefix[1] && bytes[3] == self.prefix[2] {
            return self.pattern.len() - 3;
        }

        // Check 2-byte overlap: bytes[2..4] == pattern[0..2]
        if bytes[2] == self.prefix[0] && bytes[3] == self.prefix[1] {
            return self.pattern.len() - 2;
        }

        // Check 1-byte overlap: bytes[3] == pattern[0]
        if bytes[3] == self.prefix[0] {
            return self.pattern.len() - 1;
        }

        // No overlap possible, skip full pattern
        self.pattern.len()
    }
}

impl ScanAlgorithm for BMH32ScanAlgorithm {
    fn new(pattern: &[u8]) -> Result<Self> {
        if pattern.len() < 4 {
            return Err(Error::new(
                ErrorKind::IOError,
                "Pattern must be at least 4 bytes for BMH32",
            ));
        }

        let pattern_len = pattern.len();
        let prefix = [pattern[0], pattern[1], pattern[2]];
        let mut bloom = [0u64; 64];

        // Build skip table.
        // Iterate in reverse order so rightmost occurrences (smallest skips) come first.
        // After stable sort and dedup, we keep the smallest skip for each quadgram.
        let mut skip_table: Vec<(u32, usize)> = Vec::with_capacity(pattern_len.saturating_sub(4));

        for i in (0..pattern_len.saturating_sub(4)).rev() {
            let quadgram =
                u32::from_le_bytes([pattern[i], pattern[i + 1], pattern[i + 2], pattern[i + 3]]);
            let skip = pattern_len - 4 - i;

            // Set bloom filter bit
            Self::bloom_set(&mut bloom, Self::hash_u32(quadgram));

            skip_table.push((quadgram, skip));
        }

        // Sort by quadgram (stable sort preserves order among equal keys)
        skip_table.sort_by_key(|&(k, _)| k);

        // Deduplicate by quadgram, keeping first (which has smallest skip due to reverse iteration)
        skip_table.dedup_by(|a, b| a.0 == b.0);

        Ok(Self {
            pattern: pattern.to_vec(),
            bloom,
            skip_table,
            prefix,
        })
    }

    fn pattern(&self) -> &[u8] {
        &self.pattern
    }

    fn find_next_match(
        &self,
        buffer: &[u8],
        start_offset: usize,
        bytes_available: usize,
    ) -> Option<usize> {
        let pattern_len = self.pattern.len();
        let mut offset = start_offset;

        while offset + pattern_len <= bytes_available {
            let window = &buffer[offset..offset + pattern_len];

            if window == self.pattern.as_slice() {
                return Some(offset);
            }

            // Get the last quadgram of the window (little-endian)
            let last_quadgram = u32::from_le_bytes([
                buffer[offset + pattern_len - 4],
                buffer[offset + pattern_len - 3],
                buffer[offset + pattern_len - 2],
                buffer[offset + pattern_len - 1],
            ]);

            offset += self.get_skip(last_quadgram);
        }

        None
    }
}

/// Scans virtual memory for a byte pattern using a configurable search algorithm.
///
/// The scanner handles buffer management, I/O operations, and address range
/// tracking, while delegating the actual pattern matching to the algorithm.
pub struct MemoryScannerBase<'a, T: ScanAlgorithm> {
    vmem_reader: &'a VirtualMemoryReader<'a>,
    start: VirtualAddress,
    end: VirtualAddress,
    range_list: Vec<Range<VirtualAddress>>,
    current_range_index: usize,
    read_buffer: Vec<u8>,
    bytes_read: usize,
    current_read_buffer_offset: usize,
    current_range_start: VirtualAddress,
    algorithm: T,
    /// Overlap between consecutive buffer ranges (for boundary-spanning patterns)
    overlap: usize,
}

/// Type alias for the default memory scanner - uses BMH32 (u32 quadgram) algorithm.
/// Requires patterns of at least 4 bytes.
pub type MemoryScanner<'a> = MemoryScannerBase<'a, BMH32ScanAlgorithm>;

/// Type alias for the u16-based BMH scanner (for 2-3 byte patterns).
pub type MemoryScannerU16<'a> = MemoryScannerBase<'a, BMH16ScanAlgorithm>;

/// Type alias for the u8-based BMH scanner (for single-byte patterns or compatibility).
pub type MemoryScannerU8<'a> = MemoryScannerBase<'a, BMHScanAlgorithm>;

impl<'a, T: ScanAlgorithm> MemoryScannerBase<'a, T> {
    /// Creates a new scanner for the given pattern in the virtual address range.
    pub fn new(
        vmem_reader: &'a VirtualMemoryReader<'a>,
        start: VirtualAddress,
        end: VirtualAddress,
        pattern: &[u8],
    ) -> Result<Self> {
        let algorithm = T::new(pattern)?;

        // Use 16MB buffer or the size of the region to scan, whichever is smaller.
        // Buffer must be at least pattern length for valid searching.
        const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024; // 16MB
        let region_size = end.value().value().saturating_sub(start.value().value()) as usize;
        let buffer_size = region_size.min(MAX_BUFFER_SIZE).max(pattern.len());
        let pattern_len = pattern.len();

        // Overlap must be less than buffer_size to ensure forward progress in range generation.
        // When buffer_size == pattern_len, we use overlap of pattern_len - 1.
        let overlap = pattern_len.min(buffer_size.saturating_sub(1));

        let mut range_list = Vec::new();
        for range in generate_address_ranges!(start, end, buffer_size, overlap) {
            range_list.push(range);
        }

        Ok(Self {
            vmem_reader,
            start,
            end,
            range_list,
            current_range_index: 0,
            read_buffer: vec![0u8; buffer_size],
            bytes_read: 0,
            current_read_buffer_offset: 0,
            current_range_start: start,
            algorithm,
            overlap,
        })
    }

    /// Returns the pattern being searched for.
    pub fn pattern(&self) -> &[u8] {
        self.algorithm.pattern()
    }

    /// Returns the number of bytes scanned so far (i.e., the current scan position).
    pub fn bytes_scanned(&self) -> u64 {
        let raw_start_vaddr = self.start.value().value();
        let current_pos =
            self.current_range_start.value().value() + self.current_read_buffer_offset as u64;

        current_pos - raw_start_vaddr
    }
}

impl<'a, T: ScanAlgorithm> Iterator for MemoryScannerBase<'a, T> {
    type Item = Result<VirtualAddress>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to find a match in the current buffer
            if let Some(match_offset) = self.algorithm.find_next_match(
                &self.read_buffer,
                self.current_read_buffer_offset,
                self.bytes_read,
            ) {
                // Match found - advance by 1 to find overlapping matches
                self.current_read_buffer_offset = match_offset + 1;
                return Some(Ok(self.current_range_start + match_offset as u64));
            }

            // No more matches in current buffer, try to load next range
            if let Some(range) = self.range_list.get(self.current_range_index) {
                //
                // Current buffer is exhausted, load the next range.
                //

                self.current_range_index += 1;
                self.current_range_start = range.start;

                // Calculate how many bytes we should expect to read.
                // This is clamped by the user's requested end boundary.
                let range_start_raw = range.start.value().value();
                let end_raw = self.end.value().value();
                let bytes_until_end = end_raw.saturating_sub(range_start_raw) as usize;
                let expected_bytes = self.read_buffer.len().min(bytes_until_end);

                // Track if this is a continuation range (not the first)
                let is_continuation = self.current_range_index > 1;

                match self.vmem_reader.read(&mut self.read_buffer, range.start) {
                    Ok(bytes_read) => {
                        // Any partial read within user boundaries is an error (memory hole).
                        // We only allow short reads when we've reached the user's end address.
                        if bytes_read < expected_bytes {
                            return Some(Err(Error::new(
                                ErrorKind::IOError,
                                "Memory hole detected: partial read within user boundaries",
                            )));
                        }

                        self.bytes_read = bytes_read;

                        // For continuation ranges, skip the overlap region that was already
                        // searched in the previous buffer.
                        self.current_read_buffer_offset =
                            if is_continuation { self.overlap } else { 0 };
                    }

                    Err(_) => {
                        return Some(Err(Error::new(ErrorKind::IOError, "Failed to read memory")));
                    }
                }
            } else {
                // No more ranges to process
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        core::{
            architecture::{Architecture, Bitness, Endianness, PhysicalAddressRange, Region},
            error::Result as CoreResult,
        },
        memory::{
            error::Result,
            primitives::{PhysicalAddress, RawVirtualAddress},
            readable::Readable,
        },
    };

    /// Mock readable memory for testing - provides contiguous data
    struct MockMemory {
        data: Vec<u8>,
    }

    impl MockMemory {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl Readable for MockMemory {
        fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
            let offset = physical_address.value() as usize;
            if offset >= self.data.len() {
                return Err(Error::new(
                    ErrorKind::IOError,
                    "Read beyond end of mock memory",
                ));
            }

            let available = self.data.len() - offset;
            let to_read = buffer.len().min(available);
            buffer[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);

            Ok(to_read)
        }

        fn len(&self) -> Result<u64> {
            Ok(self.data.len() as u64)
        }
    }

    /// Mock memory with a hole - simulates memory corruption/unmapped region
    struct MockMemoryWithHole {
        data: Vec<u8>,
        hole_start: usize,
        hole_end: usize,
    }

    impl MockMemoryWithHole {
        fn new(data: Vec<u8>, hole_start: usize, hole_end: usize) -> Self {
            Self {
                data,
                hole_start,
                hole_end,
            }
        }
    }

    impl Readable for MockMemoryWithHole {
        fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
            let offset = physical_address.value() as usize;

            // If read starts in the hole, error immediately
            if offset >= self.hole_start && offset < self.hole_end {
                return Err(Error::new(ErrorKind::IOError, "Read in memory hole"));
            }

            if offset >= self.data.len() {
                return Err(Error::new(
                    ErrorKind::IOError,
                    "Read beyond end of mock memory",
                ));
            }

            // Calculate how much we can read before hitting the hole or end
            let available = if offset < self.hole_start {
                // Before hole: can read up to hole_start
                (self.hole_start - offset).min(self.data.len() - offset)
            } else {
                // After hole: read normally
                self.data.len() - offset
            };

            let to_read = buffer.len().min(available);
            buffer[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);

            Ok(to_read)
        }

        fn len(&self) -> Result<u64> {
            Ok(self.data.len() as u64)
        }
    }

    /// Mock architecture for testing
    #[derive(Clone, Copy, Default)]
    struct MockArchitecture;

    impl Architecture for MockArchitecture {
        fn translate_virtual_address(
            &self,
            _readable: &dyn Readable,
            virtual_address: VirtualAddress,
        ) -> CoreResult<PhysicalAddressRange> {
            let phys_addr = PhysicalAddress::from(virtual_address.value().value());

            Ok(PhysicalAddressRange::new(
                phys_addr,
                u64::MAX - virtual_address.value().value(),
            ))
        }

        fn endianness(&self) -> Endianness {
            Endianness::Little
        }

        fn bitness(&self) -> Bitness {
            Bitness::Bit64
        }

        fn locate_page_table_for_virtual_address(
            &self,
            _readable: &dyn Readable,
            _physical_address: PhysicalAddress,
            _raw_virtual_address: RawVirtualAddress,
        ) -> CoreResult<PhysicalAddress> {
            unimplemented!("Not needed for tests")
        }

        fn enumerate_page_table_regions(
            &self,
            _readable: &dyn Readable,
            _root_page_table: PhysicalAddress,
        ) -> CoreResult<Vec<Region>> {
            unimplemented!("Not needed for tests")
        }
    }

    #[test]
    fn test_single_match() {
        let data = vec![0x00, 0x11, 0xAA, 0xBB, 0xCC, 0xDD, 0x00];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(7));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let results: Vec<_> = scanner.collect();

        // All results should be Ok
        assert!(results.iter().all(|r| r.is_ok()));

        let matches: Vec<_> = results.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value().value(), 2);
    }

    #[test]
    fn test_multiple_matches() {
        // Use 4-byte pattern for BMH32
        let data = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0xAA, 0xBB,
            0xCC, 0xDD,
        ];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(16));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let results: Vec<_> = scanner.collect();

        assert!(results.iter().all(|r| r.is_ok()));

        let matches: Vec<_> = results.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].value().value(), 0);
        assert_eq!(matches[1].value().value(), 6);
        assert_eq!(matches[2].value().value(), 12);
    }

    #[test]
    fn test_overlapping_matches() {
        // Use MemoryScannerU16 for 2-byte patterns
        let data = vec![0xAA, 0xAA, 0xAA, 0x00];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(4));

        let scanner = MemoryScannerU16::new(&reader, start, end, &[0xAA, 0xAA]).unwrap();
        let matches: Vec<_> = scanner.filter_map(|r| r.ok()).collect();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].value().value(), 0);
        assert_eq!(matches[1].value().value(), 1);
    }

    #[test]
    fn test_no_matches() {
        let data = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(8));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        let results: Vec<_> = scanner.collect();

        assert!(results.iter().all(|r| r.is_ok()));
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_pattern_at_boundaries() {
        let data = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(12));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let matches: Vec<_> = scanner.filter_map(|r| r.ok()).collect();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].value().value(), 0);
        assert_eq!(matches[1].value().value(), 8);
    }

    #[test]
    fn test_empty_pattern_returns_error() {
        let memory = MockMemory::new(vec![0; 10]);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(10));

        // BMH32 requires minimum 4 bytes
        let result = MemoryScanner::new(&reader, start, end, &[]);
        assert!(result.is_err());

        let result = MemoryScanner::new(&reader, start, end, &[0x42]);
        assert!(result.is_err());

        let result = MemoryScanner::new(&reader, start, end, &[0x42, 0x43]);
        assert!(result.is_err());

        let result = MemoryScanner::new(&reader, start, end, &[0x42, 0x43, 0x44]);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.kind(), ErrorKind::IOError);
            assert!(err.message().contains("at least 4 bytes"));
        }
    }

    #[test]
    fn test_single_byte_pattern_works_with_u8_scanner() {
        // Use the U8 scanner for single-byte patterns
        let data = vec![0xFF, 0x00, 0xFF, 0x00, 0xFF];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(5));

        let scanner = MemoryScannerU8::new(&reader, start, end, &[0xFF]).unwrap();
        let matches: Vec<_> = scanner.filter_map(|r| r.ok()).collect();

        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].value().value(), 0);
        assert_eq!(matches[1].value().value(), 2);
        assert_eq!(matches[2].value().value(), 4);
    }

    #[test]
    fn test_memory_hole_detected_via_short_read() {
        // Data has 100 bytes, but we'll simulate a hole by returning short reads.
        // The buffer size will be 100 bytes (min of region size and MAX_BUFFER_SIZE),
        // so we try to read all 100 bytes at once. The mock returns only 50 bytes
        // (up to the hole), triggering an immediate error before any searching.
        let data = vec![0xAA; 100];
        let memory = MockMemoryWithHole::new(data, 50, 60); // Hole from 50 to 60

        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        // Scan the entire range including the hole
        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(100));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xAA, 0xAA, 0xAA]).unwrap();

        // The first read returns a short read (50 bytes instead of 100),
        // which is detected as a memory hole and returns an error immediately.
        let results: Vec<_> = scanner.collect();

        // Should have exactly one error (the memory hole detection)
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());

        if let Err(err) = &results[0] {
            assert!(err.message().contains("Memory hole"));
        }
    }

    #[test]
    fn test_memory_hole_detected_via_read_error() {
        // Memory that explicitly fails to read in a certain range
        let data = vec![0xAA; 100];
        let memory = MockMemoryWithHole::new(data, 50, 60);

        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(100));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xAA, 0xAA, 0xAA]).unwrap();

        let results: Vec<_> = scanner.collect();

        // Should have at least one error
        assert!(results.iter().any(|r| r.is_err()));
    }

    #[test]
    fn test_short_read_at_end_boundary_is_ok() {
        // 50 bytes of data, but we request scanning only 50 bytes
        // Pattern is 4 bytes for BMH32
        // This ensures buffer_size > requested range
        let data = vec![0xAA; 50];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(50));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xAA, 0xAA, 0xAA]).unwrap();
        let results: Vec<_> = scanner.collect();

        // Should find many matches without error
        assert!(results.iter().all(|r| r.is_ok()));
        assert!(!results.is_empty());
    }

    #[test]
    fn test_request_beyond_available_data_triggers_error() {
        // 30 bytes available, but we request 100 bytes
        let data = vec![0xAA; 30];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(100));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xAA, 0xAA, 0xAA]).unwrap();

        // Consume all results
        let results: Vec<_> = scanner.collect();

        // Should detect error when trying to read beyond available data
        assert!(results.iter().any(|r| r.is_err()));
    }

    #[test]
    fn test_large_pattern_with_exact_boundary() {
        // Large pattern to test buffer sizing
        let pattern = vec![0xBB; 50];
        let mut data = vec![0xAA; 200];
        data[100..150].copy_from_slice(&pattern);

        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(200));

        let scanner = MemoryScanner::new(&reader, start, end, &pattern).unwrap();
        let results: Vec<_> = scanner.collect();

        assert!(results.iter().all(|r| r.is_ok()));
        let matches: Vec<_> = results.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value().value(), 100);
    }

    #[test]
    fn test_bytes_scanned_tracking() {
        let data = vec![0xAA; 100];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(100));

        let mut scanner =
            MemoryScanner::new(&reader, start, end, &[0xAA, 0xAA, 0xAA, 0xAA]).unwrap();

        assert_eq!(scanner.bytes_scanned(), 0);

        // Scan a few matches
        let _result = scanner.next();
        assert!(scanner.bytes_scanned() > 0);

        let bytes_before = scanner.bytes_scanned();
        let _result = scanner.next();
        assert!(scanner.bytes_scanned() > bytes_before);
    }

    #[test]
    fn test_pattern_getter() {
        let memory = MockMemory::new(vec![0; 10]);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(10));

        let pattern = &[0xDE, 0xAD, 0xBE, 0xEF];
        let scanner = MemoryScanner::new(&reader, start, end, pattern).unwrap();

        assert_eq!(scanner.pattern(), pattern);
    }

    /// Brute-force reference implementation for differential testing.
    fn brute_force_search(data: &[u8], pattern: &[u8]) -> Vec<usize> {
        if pattern.is_empty() || pattern.len() > data.len() {
            return Vec::new();
        }
        (0..=data.len() - pattern.len())
            .filter(|&i| data[i..i + pattern.len()] == *pattern)
            .collect()
    }

    /// Helper to run MemoryScanner and collect match offsets.
    fn scanner_search(data: &[u8], pattern: &[u8]) -> Vec<usize> {
        let memory = MockMemory::new(data.to_vec());
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(
            PhysicalAddress::from(0),
            RawVirtualAddress::new(data.len() as u64),
        );

        let scanner = MemoryScanner::new(&reader, start, end, pattern).unwrap();
        scanner
            .filter_map(|r| r.ok())
            .map(|addr| addr.value().value() as usize)
            .collect()
    }

    #[test]
    fn test_bmh32_matches_brute_force() {
        // Test case 1: Pattern with distinct bytes (4-byte minimum for BMH32)
        let data = vec![
            0x00, 0x11, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let pattern = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 2: Overlapping matches (repeated bytes) - 4-byte pattern
        let data = vec![0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
        let pattern = &[0xAA, 0xAA, 0xAA, 0xAA];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 3: Pattern where last bytes appear earlier
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04];
        let pattern = &[0x01, 0x02, 0x03, 0x04];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 4: Pattern at very end
        let data = vec![0x00, 0x00, 0x00, 0xAB, 0xCD, 0xEF, 0x12];
        let pattern = &[0xAB, 0xCD, 0xEF, 0x12];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 5: No matches
        let data = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let pattern = &[0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 6: Pattern same length as data
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let pattern = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 7: Larger data with multiple scattered matches
        let mut data = vec![0x00; 200];
        data[10..14].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        data[50..54].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        data[196..200].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        let pattern = &[0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );
    }

    /// Direct algorithm test helper - tests BMH16ScanAlgorithm directly without scanner wrapper
    fn bmh16_direct_search(data: &[u8], pattern: &[u8]) -> Vec<usize> {
        let algo = BMH16ScanAlgorithm::new(pattern).unwrap();
        let mut results = Vec::new();
        let mut offset = 0;
        while let Some(match_offset) = algo.find_next_match(data, offset, data.len()) {
            results.push(match_offset);
            offset = match_offset + 1;
        }
        results
    }

    #[test]
    fn test_bmh16_edge_case_second_byte_equals_first() {
        // This tests the edge case where the bigram's second byte equals pattern[0]
        // Pattern "ABC", searching in "XABC" - "XA" is not in pattern, but 'A' = pattern[0]
        let data = b"XABC";
        let pattern = b"ABC";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Another edge case: "XXABC"
        let data = b"XXABC";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Multiple X's before match
        let data = b"XXXXABC";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );
    }

    #[test]
    fn test_bmh16_two_byte_pattern() {
        // Two-byte patterns create an empty skip table (loop 0..pattern_len-2 = 0..0).
        // The bloom filter mask is 0, so all lookups fall through to default_skip().
        // This is correct behavior - the algorithm still works via the default skip logic.
        let pattern = b"AB";

        // Match at start
        let data = b"ABCD";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Match after non-matching prefix
        let data = b"XABC";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Match after prefix where second byte of window equals pattern[0]
        let data = b"XAAB";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Multiple matches
        let data = b"ABABAB";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );
    }

    #[test]
    fn test_bmh16_repeated_bigrams() {
        // Pattern with repeated bigram - should use rightmost occurrence (smallest skip)
        let pattern = b"ABAB";
        let data = b"XXABAB";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Another repeated bigram case
        let pattern = b"AAAA";
        let data = b"XAAAAX";
        assert_eq!(
            bmh16_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );
    }

    #[test]
    fn test_bmh16_long_pattern() {
        // Test with a longer pattern similar to kallsyms use case
        let pattern: Vec<u8> = (0..20).collect();
        let mut data = vec![0xFF; 100];
        data[50..70].copy_from_slice(&pattern);

        assert_eq!(
            bmh16_direct_search(&data, &pattern),
            brute_force_search(&data, &pattern)
        );
    }

    #[test]
    fn test_bmh16_ascii_null_pattern() {
        // Pattern similar to kallsyms token sequences (ASCII + null interleaved)
        let pattern = [b'A', 0x00, b'B', 0x00, b'C', 0x00];
        let mut data = vec![0xFF; 50];
        data[20..26].copy_from_slice(&pattern);

        assert_eq!(
            bmh16_direct_search(&data, &pattern),
            brute_force_search(&data, &pattern)
        );
    }

    #[test]
    fn test_bmh16_bloom_filter_hash_distribution() {
        // Verify the hash function produces reasonable distribution
        // by checking that different bigrams produce different hashes
        let hash1 = BMH16ScanAlgorithm::hash_u16(0x0000);
        let hash2 = BMH16ScanAlgorithm::hash_u16(0xFFFF);
        let hash3 = BMH16ScanAlgorithm::hash_u16(0x4141); // "AA"
        let hash4 = BMH16ScanAlgorithm::hash_u16(0x4142); // "BA"

        // Hashes should be in valid range
        assert!(hash1 < 64);
        assert!(hash2 < 64);
        assert!(hash3 < 64);
        assert!(hash4 < 64);

        // These specific values should produce different hashes
        // (testing the multiply-shift distribution)
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_bmh16_comprehensive_differential() {
        // Comprehensive differential test against brute force
        // with various data patterns and sizes

        // Random-ish patterns
        for pattern_len in 2..=10 {
            let pattern: Vec<u8> = (0..pattern_len).map(|i| (i * 17 + 3) as u8).collect();

            for data_len in [pattern_len, pattern_len + 1, 20, 50, 100] {
                let data: Vec<u8> = (0..data_len).map(|i| (i * 13 + 7) as u8).collect();

                assert_eq!(
                    bmh16_direct_search(&data, &pattern),
                    brute_force_search(&data, &pattern),
                    "Failed for pattern_len={}, data_len={}",
                    pattern_len,
                    data_len
                );
            }
        }

        // Patterns with matches
        for pattern_len in 2..=8 {
            let pattern: Vec<u8> = vec![0xAA; pattern_len];
            let mut data = vec![0x00; 50];
            data[10..10 + pattern_len].copy_from_slice(&pattern);
            data[30..30 + pattern_len].copy_from_slice(&pattern);

            assert_eq!(
                bmh16_direct_search(&data, &pattern),
                brute_force_search(&data, &pattern),
                "Failed for pattern_len={} with matches",
                pattern_len
            );
        }
    }

    // ============ BMH32 Tests ============

    /// Direct algorithm test helper - tests BMH32ScanAlgorithm directly without scanner wrapper
    fn bmh32_direct_search(data: &[u8], pattern: &[u8]) -> Vec<usize> {
        let algo = BMH32ScanAlgorithm::new(pattern).unwrap();
        let mut results = Vec::new();
        let mut offset = 0;
        while let Some(match_offset) = algo.find_next_match(data, offset, data.len()) {
            results.push(match_offset);
            offset = match_offset + 1;
        }
        results
    }

    #[test]
    fn test_bmh32_edge_case_prefix_overlaps() {
        // Test 3-byte overlap: last 3 bytes of quadgram equal pattern[0..3]
        let data = b"XABCDEFGH";
        let pattern = b"ABCDEFGH";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Test 2-byte overlap
        let data = b"XXABCDEF";
        let pattern = b"ABCDEF";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Test 1-byte overlap
        let data = b"XXXABCDE";
        let pattern = b"ABCDE";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // No overlap case
        let data = b"XXXXABCD";
        let pattern = b"ABCD";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );
    }

    #[test]
    fn test_bmh32_four_byte_pattern() {
        // Four-byte patterns have no entries in skip table, rely on default skip logic
        let pattern = b"ABCD";

        // Match at start
        let data = b"ABCDEFGH";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Match after non-matching prefix
        let data = b"XXXXABCD";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Match after prefix with 1-byte overlap potential
        let data = b"XXXAABCD";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Multiple matches
        let data = b"ABCDABCDABCD";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );
    }

    #[test]
    fn test_bmh32_repeated_quadgrams() {
        // Pattern with repeated quadgram - should use rightmost occurrence (smallest skip)
        let pattern = b"ABCDABCD";
        let data = b"XXXXABCDABCD";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );

        // Another repeated quadgram case
        let pattern = b"AAAAAAAA";
        let data = b"XAAAAAAAAX";
        assert_eq!(
            bmh32_direct_search(data, pattern),
            brute_force_search(data, pattern)
        );
    }

    #[test]
    fn test_bmh32_long_pattern() {
        // Test with a longer pattern similar to kallsyms use case
        let pattern: Vec<u8> = (0..20).collect();
        let mut data = vec![0xFF; 100];
        data[50..70].copy_from_slice(&pattern);

        assert_eq!(
            bmh32_direct_search(&data, &pattern),
            brute_force_search(&data, &pattern)
        );
    }

    #[test]
    fn test_bmh32_ascii_null_pattern() {
        // Pattern similar to kallsyms token sequences (ASCII + null interleaved)
        let pattern = [b'A', 0x00, b'B', 0x00, b'C', 0x00, b'D', 0x00];
        let mut data = vec![0xFF; 50];
        data[20..28].copy_from_slice(&pattern);

        assert_eq!(
            bmh32_direct_search(&data, &pattern),
            brute_force_search(&data, &pattern)
        );
    }

    #[test]
    fn test_bmh32_bloom_filter_hash_distribution() {
        // Verify the hash function produces reasonable distribution
        // by checking that different quadgrams produce different hashes
        let hash1 = BMH32ScanAlgorithm::hash_u32(0x00000000);
        let hash2 = BMH32ScanAlgorithm::hash_u32(0xFFFFFFFF);
        let hash3 = BMH32ScanAlgorithm::hash_u32(0x41414141); // "AAAA"
        let hash4 = BMH32ScanAlgorithm::hash_u32(0x41414142); // "BAAA"

        // Hashes should be in valid range (12 bits = 0-4095)
        assert!(hash1 < 4096);
        assert!(hash2 < 4096);
        assert!(hash3 < 4096);
        assert!(hash4 < 4096);

        // These specific values should produce different hashes
        // (testing the multiply-shift distribution)
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_bmh32_comprehensive_differential() {
        // Comprehensive differential test against brute force
        // with various data patterns and sizes

        // Random-ish patterns (4-byte minimum for BMH32)
        for pattern_len in 4..=12 {
            let pattern: Vec<u8> = (0..pattern_len).map(|i| (i * 17 + 3) as u8).collect();

            for data_len in [pattern_len, pattern_len + 1, 20, 50, 100] {
                let data: Vec<u8> = (0..data_len).map(|i| (i * 13 + 7) as u8).collect();

                assert_eq!(
                    bmh32_direct_search(&data, &pattern),
                    brute_force_search(&data, &pattern),
                    "Failed for pattern_len={}, data_len={}",
                    pattern_len,
                    data_len
                );
            }
        }

        // Patterns with matches
        for pattern_len in 4..=10 {
            let pattern: Vec<u8> = vec![0xAA; pattern_len];
            let mut data = vec![0x00; 50];
            data[10..10 + pattern_len].copy_from_slice(&pattern);
            data[30..30 + pattern_len].copy_from_slice(&pattern);

            assert_eq!(
                bmh32_direct_search(&data, &pattern),
                brute_force_search(&data, &pattern),
                "Failed for pattern_len={} with matches",
                pattern_len
            );
        }
    }

    #[test]
    fn test_bmh32_overlapping_matches() {
        // Test overlapping matches with 4-byte patterns
        let data = vec![0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
        let pattern = &[0xAA, 0xAA, 0xAA, 0xAA];

        assert_eq!(
            bmh32_direct_search(&data, pattern),
            brute_force_search(&data, pattern)
        );
        // Should find 4 overlapping matches at positions 0, 1, 2, 3
        assert_eq!(bmh32_direct_search(&data, pattern), vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_bmh32_minimum_pattern_length() {
        // Test that BMH32 requires at least 4 bytes
        let result = BMH32ScanAlgorithm::new(&[0x01]);
        assert!(result.is_err());

        let result = BMH32ScanAlgorithm::new(&[0x01, 0x02]);
        assert!(result.is_err());

        let result = BMH32ScanAlgorithm::new(&[0x01, 0x02, 0x03]);
        assert!(result.is_err());

        let result = BMH32ScanAlgorithm::new(&[0x01, 0x02, 0x03, 0x04]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bmh16_minimum_pattern_length() {
        // Test that BMH16 requires at least 2 bytes
        let result = BMH16ScanAlgorithm::new(&[]);
        assert!(result.is_err());

        let result = BMH16ScanAlgorithm::new(&[0x01]);
        assert!(result.is_err());

        let result = BMH16ScanAlgorithm::new(&[0x01, 0x02]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bmh_rejects_empty_pattern() {
        // Test that BMH (u8) requires at least 1 byte
        let result = BMHScanAlgorithm::new(&[]);
        assert!(result.is_err());

        let result = BMHScanAlgorithm::new(&[0x01]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bmh32_default_skip_all_overlap_cases() {
        // Create a pattern and test the default_skip method for various overlap scenarios
        let algo = BMH32ScanAlgorithm::new(b"ABCDEFGH").unwrap();

        // No overlap - quadgram has no suffix matching pattern prefix
        // Quadgram "XXXX" (0x58585858) should skip full pattern length (8)
        let skip = algo.default_skip(u32::from_le_bytes(*b"XXXX"));
        assert_eq!(skip, 8);

        // 1-byte overlap - quadgram's last byte equals pattern[0] ('A')
        // Quadgram "XXXA" should skip pattern_len - 1 = 7
        let skip = algo.default_skip(u32::from_le_bytes(*b"XXXA"));
        assert_eq!(skip, 7);

        // 2-byte overlap - quadgram's last 2 bytes equal pattern[0..2] ('AB')
        // Quadgram "XXAB" should skip pattern_len - 2 = 6
        let skip = algo.default_skip(u32::from_le_bytes(*b"XXAB"));
        assert_eq!(skip, 6);

        // 3-byte overlap - quadgram's last 3 bytes equal pattern[0..3] ('ABC')
        // Quadgram "XABC" should skip pattern_len - 3 = 5
        let skip = algo.default_skip(u32::from_le_bytes(*b"XABC"));
        assert_eq!(skip, 5);
    }
}
