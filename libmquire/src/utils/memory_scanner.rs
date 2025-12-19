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

/// Scans virtual memory for a byte pattern using Boyer-Moore-Horspool algorithm.
pub struct MemoryScanner<'a> {
    vmem_reader: &'a VirtualMemoryReader<'a>,
    start: VirtualAddress,
    end: VirtualAddress,
    range_list: Vec<Range<VirtualAddress>>,
    current_range_index: usize,
    read_buffer: Vec<u8>,
    bytes_read: usize,
    current_read_buffer_offset: usize,
    pattern: Vec<u8>,
    current_range_start: VirtualAddress,
    /// Boyer-Moore-Horspool bad character skip table
    skip_table: [usize; 256],
}

impl<'a> MemoryScanner<'a> {
    /// Creates a new scanner for the given pattern in the virtual address range.
    pub fn new(
        vmem_reader: &'a VirtualMemoryReader<'a>,
        start: VirtualAddress,
        end: VirtualAddress,
        pattern: &[u8],
    ) -> Result<Self> {
        if pattern.is_empty() {
            return Err(Error::new(ErrorKind::IOError, "Pattern cannot be empty"));
        }

        let buffer_size = pattern.len() * 10;
        let pattern_len = pattern.len();

        let mut range_list = Vec::new();
        for range in generate_address_ranges!(start, end, buffer_size, pattern_len) {
            range_list.push(range);
        }

        // Build Boyer-Moore-Horspool bad character skip table
        let mut skip_table = [pattern_len; 256];
        for (i, &byte) in pattern[..pattern_len - 1].iter().enumerate() {
            skip_table[byte as usize] = pattern_len - 1 - i;
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
            pattern: pattern.to_vec(),
            current_range_start: start,
            skip_table,
        })
    }

    /// Returns the pattern being searched for.
    pub fn pattern(&self) -> &[u8] {
        &self.pattern
    }

    /// Returns the total number of bytes read from the range.
    pub fn bytes_read(&self) -> u64 {
        let raw_start_vaddr = self.start.value().value();
        let current_pos =
            self.current_range_start.value().value() + self.current_read_buffer_offset as u64;

        current_pos - raw_start_vaddr
    }
}

impl<'a> Iterator for MemoryScanner<'a> {
    type Item = Result<VirtualAddress>;

    fn next(&mut self) -> Option<Self::Item> {
        let pattern_len = self.pattern.len();

        loop {
            if self.current_read_buffer_offset + pattern_len <= self.bytes_read {
                //
                // Boyer-Moore-Horspool: compare pattern and skip based on bad character
                //

                let window = &self.read_buffer[self.current_read_buffer_offset
                    ..self.current_read_buffer_offset + pattern_len];

                let current_offset = self.current_read_buffer_offset;

                if window == self.pattern.as_slice() {
                    // Match found - advance by 1 to find overlapping matches
                    self.current_read_buffer_offset += 1;
                    return Some(Ok(self.current_range_start + current_offset as u64));
                } else {
                    // No match - skip based on the last byte in the window
                    let last_byte = window[pattern_len - 1];
                    self.current_read_buffer_offset += self.skip_table[last_byte as usize];
                }
            } else if let Some(range) = self.range_list.get(self.current_range_index) {
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
                        self.current_read_buffer_offset = 0;
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
        core::architecture::{Architecture, Bitness, Endianness, PhysicalAddressRange, Region},
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
                return Err(crate::memory::error::Error::new(
                    crate::memory::error::ErrorKind::IOError,
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
                return Err(crate::memory::error::Error::new(
                    crate::memory::error::ErrorKind::IOError,
                    "Read in memory hole",
                ));
            }

            if offset >= self.data.len() {
                return Err(crate::memory::error::Error::new(
                    crate::memory::error::ErrorKind::IOError,
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
        ) -> crate::core::error::Result<PhysicalAddressRange> {
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
        ) -> crate::core::error::Result<PhysicalAddress> {
            unimplemented!("Not needed for tests")
        }

        fn enumerate_page_table_regions(
            &self,
            _readable: &dyn Readable,
            _root_page_table: PhysicalAddress,
        ) -> crate::core::error::Result<Vec<Region>> {
            unimplemented!("Not needed for tests")
        }
    }

    #[test]
    fn test_single_match() {
        let data = vec![0x00, 0x11, 0xAA, 0xBB, 0xCC, 0x00];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(6));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xBB, 0xCC]).unwrap();
        let results: Vec<_> = scanner.collect();

        // All results should be Ok
        assert!(results.iter().all(|r| r.is_ok()));

        let matches: Vec<_> = results.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value().value(), 2);
    }

    #[test]
    fn test_multiple_matches() {
        let data = vec![0xAA, 0xBB, 0x00, 0xAA, 0xBB, 0x00, 0xAA, 0xBB];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(8));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xBB]).unwrap();
        let results: Vec<_> = scanner.collect();

        assert!(results.iter().all(|r| r.is_ok()));

        let matches: Vec<_> = results.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].value().value(), 0);
        assert_eq!(matches[1].value().value(), 3);
        assert_eq!(matches[2].value().value(), 6);
    }

    #[test]
    fn test_overlapping_matches() {
        let data = vec![0xAA, 0xAA, 0xAA, 0x00];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(4));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xAA]).unwrap();
        let matches: Vec<_> = scanner.filter_map(|r| r.ok()).collect();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].value().value(), 0);
        assert_eq!(matches[1].value().value(), 1);
    }

    #[test]
    fn test_no_matches() {
        let data = vec![0x00, 0x11, 0x22, 0x33, 0x44];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(5));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xFF, 0xFF]).unwrap();
        let results: Vec<_> = scanner.collect();

        assert!(results.iter().all(|r| r.is_ok()));
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_pattern_at_boundaries() {
        let data = vec![0xAA, 0xBB, 0x00, 0x00, 0x00, 0xAA, 0xBB];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(7));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xBB]).unwrap();
        let matches: Vec<_> = scanner.filter_map(|r| r.ok()).collect();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].value().value(), 0);
        assert_eq!(matches[1].value().value(), 5);
    }

    #[test]
    fn test_empty_pattern_returns_error() {
        let memory = MockMemory::new(vec![0; 10]);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(10));

        let result = MemoryScanner::new(&reader, start, end, &[]);

        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.kind(), crate::memory::error::ErrorKind::IOError);
            assert_eq!(err.message(), "Pattern cannot be empty");
        }
    }

    #[test]
    fn test_memory_hole_detected_via_short_read() {
        // Data has 100 bytes, but we'll simulate a hole by returning short reads
        let data = vec![0xAA; 100];
        let memory = MockMemoryWithHole::new(data, 50, 60); // Hole from 50 to 60

        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        // Scan the entire range including the hole
        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(100));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA]).unwrap();

        let mut found_error = false;
        let mut successful_matches = Vec::new();

        for result in scanner {
            match result {
                Ok(addr) => {
                    if !found_error {
                        successful_matches.push(addr);
                    }
                }
                Err(_) => {
                    found_error = true;
                    break; // Stop on first error
                }
            }
        }

        // Should have found some successful matches before the hole
        assert!(!successful_matches.is_empty());

        // All successful matches should be before the hole starts at position 50
        for m in &successful_matches {
            assert!(m.value().value() < 50);
        }

        // Should have detected an error
        assert!(found_error);
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

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA]).unwrap();

        let results: Vec<_> = scanner.collect();

        // Should have at least one error
        assert!(results.iter().any(|r| r.is_err()));
    }

    #[test]
    fn test_short_read_at_end_boundary_is_ok() {
        // 50 bytes of data, but we request scanning only 50 bytes
        // Pattern is 2 bytes, buffer is 20 bytes
        // This ensures buffer_size > requested range
        let data = vec![0xAA; 50];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(50));

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA, 0xAA]).unwrap();
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

        let scanner = MemoryScanner::new(&reader, start, end, &[0xAA]).unwrap();

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
    fn test_bytes_read_tracking() {
        let data = vec![0xAA; 100];
        let memory = MockMemory::new(data);
        let arch = MockArchitecture;
        let reader = VirtualMemoryReader::new(&memory, &arch);

        let start = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(0));
        let end = VirtualAddress::new(PhysicalAddress::from(0), RawVirtualAddress::new(100));

        let mut scanner = MemoryScanner::new(&reader, start, end, &[0xAA]).unwrap();

        assert_eq!(scanner.bytes_read(), 0);

        // Read a few matches
        let _result = scanner.next();
        assert!(scanner.bytes_read() > 0);

        let bytes_before = scanner.bytes_read();
        let _result = scanner.next();
        assert!(scanner.bytes_read() > bytes_before);
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
    fn test_bmh_matches_brute_force() {
        // Test case 1: Pattern with distinct bytes
        let data = vec![
            0x00, 0x11, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let pattern = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 2: Overlapping matches (repeated bytes)
        let data = vec![0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
        let pattern = &[0xAA, 0xAA];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 3: Pattern where last byte appears earlier
        let data = vec![0x00, 0x01, 0x02, 0x01, 0x00, 0x01, 0x02, 0x03];
        let pattern = &[0x01, 0x02, 0x03];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 4: Single byte pattern
        let data = vec![0xFF, 0x00, 0xFF, 0x00, 0xFF];
        let pattern = &[0xFF];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 5: Pattern at very end
        let data = vec![0x00, 0x00, 0x00, 0xAB, 0xCD];
        let pattern = &[0xAB, 0xCD];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 6: No matches
        let data = vec![0x00, 0x11, 0x22, 0x33, 0x44];
        let pattern = &[0xFF, 0xFF];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 7: Pattern same length as data
        let data = vec![0xDE, 0xAD];
        let pattern = &[0xDE, 0xAD];
        assert_eq!(
            scanner_search(&data, pattern),
            brute_force_search(&data, pattern)
        );

        // Test case 8: Larger data with multiple scattered matches
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
}
