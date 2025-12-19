//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        error::Result, operating_system::OperatingSystem,
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::primitives::PhysicalAddress,
    operating_system::linux::{
        entities::syslog_file::{SyslogFile, SyslogFileDataSource, SyslogFileRegion},
        operating_system::LinuxOperatingSystem,
        virtual_struct::VirtualStruct,
    },
    try_chain,
};

use log::debug;

use std::collections::BTreeMap;

/// Syslog path
const SYSLOG_PATH: &str = "/var/log/syslog";

impl LinuxOperatingSystem {
    /// Returns the syslog file data from memory
    pub(super) fn get_syslog_file_regions_impl(&self) -> Result<Vec<SyslogFile>> {
        // This function attempts to read /var/log/syslog from memory using two approaches:
        // 1. Page cache from open file handles
        // 2. Memory mappings of the file
        let mut syslog_entity_list: Vec<SyslogFile> = Vec::new();

        // First, read from open files via page cache. It is possible for multiple file
        // entities to exist with the same path, for example if the `/var/log/syslog` file
        // is deleted and recreated while still being held open by a process.
        let file_list = self
            .get_task_open_file_list()?
            .into_iter()
            .filter(|file_entity| file_entity.path == SYSLOG_PATH)
            .map(|file_entity| (file_entity.virtual_address.value(), file_entity))
            .collect::<BTreeMap<_, _>>() // Use the file object vaddr to deduplicate
            .into_values()
            .collect::<Vec<_>>();

        let page_cache_syslog: Vec<SyslogFile> = file_list
            .iter()
            .filter_map(|file| {
                let reader = match self.get_file_reader(file.virtual_address) {
                    Ok(reader) => reader,

                    Err(err) => {
                        debug!(
                            "Failed to create file reader for {SYSLOG_PATH} at {:?}: {err:?}",
                            file.virtual_address
                        );

                        return None;
                    }
                };

                let file_region_list = match reader.regions() {
                    Ok(region_list) => region_list,

                    Err(err) => {
                        debug!(
                            "Failed to enumerate regions for {SYSLOG_PATH} at {:?}: {err:?}",
                            file.virtual_address
                        );
                        return None;
                    }
                };

                let syslog_region_list: Vec<SyslogFileRegion> = file_region_list
                    .iter()
                    .filter_map(|region| {
                        let region_size = region.end - region.start;
                        let mut buffer = vec![0; region_size as usize];

                        let buffer =
                            match reader.read(&mut buffer, region.start).map(|bytes_read| {
                                buffer.truncate(bytes_read);
                                buffer
                            }) {
                                Ok(buffer) => buffer,

                                Err(err) => {
                                    debug!(
                                "Failed to read region {:?} for {SYSLOG_PATH} at {:?}: {err:?}",
                                region, file.virtual_address
                            );
                                    return None;
                                }
                            };

                        let lines = extract_valid_lines(&buffer, 10);
                        if lines.is_empty() {
                            debug!(
                                "Skipping syslog region {:?} at {:?}: no valid text lines found",
                                region, file.virtual_address
                            );

                            return None;
                        }

                        Some(SyslogFileRegion {
                            offset_range: region.clone(),
                            lines,
                        })
                    })
                    .collect();

                Some(SyslogFile {
                    virtual_address: file.virtual_address,
                    task: file.task,
                    pid: file.pid,
                    data_source: SyslogFileDataSource::PageCache,
                    region_list: syslog_region_list,
                })
            })
            .collect();

        syslog_entity_list.extend(page_cache_syslog);

        let syslog_mappings: Vec<_> = self
            .get_task_memory_mappings_impl()?
            .into_iter()
            .filter(|mapping| {
                mapping
                    .file_backing
                    .as_ref()
                    .map(|file_backing| file_backing.path.to_str().unwrap_or("") == SYSLOG_PATH)
                    .unwrap_or(false)
            })
            .collect();

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        for mapping in syslog_mappings {
            let region_size = (mapping.region.end.value() - mapping.region.start.value()) as usize;
            let mut buffer = vec![0u8; region_size];

            match vmem_reader.read(&mut buffer, mapping.region.start) {
                Ok(bytes_read) => {
                    buffer.truncate(bytes_read);

                    let lines = extract_valid_lines(&buffer, 10);
                    if lines.is_empty() {
                        debug!(
                            "Skipping syslog memory mapping at {:?}: no valid text lines found",
                            mapping.region.start
                        );
                        continue;
                    }

                    let syslog_region = SyslogFileRegion {
                        offset_range: PhysicalAddress::new(0)
                            ..PhysicalAddress::new(bytes_read as u64),
                        lines,
                    };

                    let task_struct = VirtualStruct::from_name(
                        &vmem_reader,
                        &self.kernel_type_info,
                        "task_struct",
                        &mapping.task,
                    )
                    .inspect_err(|err| debug!("{err:?}"))?;

                    let pid = match try_chain!(task_struct.traverse("tgid")?.read_u32()) {
                        Ok(tgid) => tgid,
                        Err(err) => {
                            debug!(
                                "Failed to read the tgid field from task {:?}{err:?}",
                                mapping.task
                            );
                            0
                        }
                    };

                    syslog_entity_list.push(SyslogFile {
                        virtual_address: mapping.region.start,
                        task: mapping.task,
                        pid,
                        data_source: SyslogFileDataSource::MemoryMapping,
                        region_list: vec![syslog_region],
                    });
                }

                Err(err) => {
                    debug!(
                        "Failed to read memory mapping for {SYSLOG_PATH} at {:?}: {err:?}",
                        mapping.region.start
                    );
                }
            }
        }

        Ok(syslog_entity_list)
    }
}

/// Validates if a text string contains mostly printable characters
pub(crate) fn is_valid_text(text: &str, min_length: usize) -> bool {
    if text.len() < min_length {
        return false;
    }

    let printable_count = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();

    // Require at least 80% printable characters
    printable_count as f32 / text.len() as f32 >= 0.8
}

/// Extracts valid text lines from a buffer that may contain binary data
pub(super) fn extract_valid_lines(buffer: &[u8], min_line_length: usize) -> Vec<String> {
    let mut valid_lines = Vec::new();
    let mut current_line_start = 0;

    for i in 0..buffer.len() {
        if buffer[i] == b'\n' || i == buffer.len() - 1 {
            let line_end = if buffer[i] == b'\n' { i } else { i + 1 };
            let line_bytes = &buffer[current_line_start..line_end];

            if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                let line_clean = line_str.trim_end_matches('\r').trim();

                if is_valid_text(line_clean, min_line_length) {
                    valid_lines.push(line_clean.to_string());
                }
            }

            current_line_start = line_end + 1;
        }
    }

    valid_lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_valid_lines_preserves_valid_input() {
        let input = b"This is a valid line\nAnother valid line\nThird valid line\n";
        let expected = vec![
            "This is a valid line",
            "Another valid line",
            "Third valid line",
        ];

        let result = extract_valid_lines(input, 1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_valid_lines_handles_different_line_endings() {
        let input = b"Line with CRLF\r\nAnother line\r\nThird line\r\n";
        let expected = vec!["Line with CRLF", "Another line", "Third line"];

        let result = extract_valid_lines(input, 1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_valid_lines_filters_short_lines() {
        let input = b"This is long enough\nShort\nAnother long line\n";
        let expected = vec!["This is long enough", "Another long line"];

        let result = extract_valid_lines(input, 10);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_valid_lines_handles_no_final_newline() {
        let input = b"First line\nSecond line\nLast line without newline";
        let expected = vec!["First line", "Second line", "Last line without newline"];

        let result = extract_valid_lines(input, 1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_valid_lines_trims_whitespace() {
        let input = b"  Line with leading spaces\nLine with trailing spaces  \n  Both sides  \n";
        let expected = vec![
            "Line with leading spaces",
            "Line with trailing spaces",
            "Both sides",
        ];

        let result = extract_valid_lines(input, 1);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_is_valid_text_accepts_fully_printable() {
        assert!(is_valid_text("This is 100% valid ASCII text!", 1));
        assert!(is_valid_text("Line with spaces and punctuation.", 1));
        assert!(is_valid_text("Numbers 12345 are fine", 1));
    }

    #[test]
    fn test_is_valid_text_rejects_mostly_binary() {
        let binary_heavy = "abc\x00\x01\x02\x03\x04\x05";
        assert!(!is_valid_text(binary_heavy, 1));
    }

    #[test]
    fn test_is_valid_text_respects_min_length() {
        assert!(!is_valid_text("ab", 5));
        assert!(is_valid_text("abcde", 5));
        assert!(is_valid_text("abcdef", 5));
    }
}
