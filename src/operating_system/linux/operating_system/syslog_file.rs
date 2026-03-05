//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        error::{Error, Result},
        operating_system::OperatingSystem,
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        virtual_address::VirtualAddress,
    },
    operating_system::linux::{
        entities::syslog_file::{SyslogFile, SyslogFileDataSource, SyslogFileRegion},
        operating_system::{
            LinuxOperatingSystem, file::TaskOpenFilesIterator,
            memory_mapping::MemoryMappingIterator, task::TaskIterator,
        },
        virtual_struct::VirtualStruct,
    },
    try_chain,
};

use {log::debug, std::collections::BTreeSet};

/// Syslog path
const SYSLOG_PATH: &str = "/var/log/syslog";

/// Iterator over syslog file regions from memory
pub struct SyslogFileIterator<'a> {
    /// Reference to the operating system
    operating_system: &'a LinuxOperatingSystem,

    /// Current iteration stage
    iterator_stage: SyslogIteratorStage<'a>,

    /// Seen file virtual addresses for deduplication (open files stage)
    visited_file_vaddr_set: BTreeSet<RawVirtualAddress>,
}

/// Stage of the syslog iterator
enum SyslogIteratorStage<'a> {
    /// Processing open file handles
    OpenFiles {
        task_iter: TaskIterator<'a>,
        current_files_iter: Option<TaskOpenFilesIterator<'a>>,
    },

    /// Processing memory mapping entries
    MemoryMappings {
        task_iter: TaskIterator<'a>,
        current_mappings_iter: Option<MemoryMappingIterator<'a>>,
    },

    /// Done iterating
    Done,
}

/// Result of a single iteration step within a stage
enum StageStepResult {
    /// Continue to the next iteration within this stage
    Continue,

    /// Yield a successful result
    Yield(SyslogFile),

    /// Yield an error result
    Error(Error),

    /// Transition to the next stage
    NextStage,

    /// Iteration complete
    Done,
}

impl Iterator for SyslogFileIterator<'_> {
    type Item = Result<SyslogFile>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let result = match &self.iterator_stage {
                SyslogIteratorStage::OpenFiles { .. } => self.step_open_files(),
                SyslogIteratorStage::MemoryMappings { .. } => self.step_memory_mappings(),
                SyslogIteratorStage::Done => StageStepResult::Done,
            };

            match result {
                StageStepResult::Continue => continue,
                StageStepResult::Yield(syslog_file) => return Some(Ok(syslog_file)),
                StageStepResult::Error(err) => return Some(Err(err)),
                StageStepResult::NextStage => self.transition_to_next_stage(),
                StageStepResult::Done => return None,
            }
        }
    }
}

impl<'a> SyslogFileIterator<'a> {
    /// Perform one step in the open files stage
    fn step_open_files(&mut self) -> StageStepResult {
        let (task_iter, current_files_iter) = match &mut self.iterator_stage {
            SyslogIteratorStage::OpenFiles {
                task_iter,
                current_files_iter,
            } => (task_iter, current_files_iter),

            _ => return StageStepResult::Done,
        };

        // Try to get next file from current iterator
        if let Some(files_iter) = current_files_iter {
            match files_iter.next() {
                Some(Ok(file)) => {
                    if file.path != SYSLOG_PATH {
                        return StageStepResult::Continue;
                    }

                    if !self
                        .visited_file_vaddr_set
                        .insert(file.virtual_address.value())
                    {
                        return StageStepResult::Continue;
                    }

                    match self.process_open_file(file.virtual_address, file.task, file.tgid) {
                        Some(syslog_file) => return StageStepResult::Yield(syslog_file),
                        None => return StageStepResult::Continue,
                    }
                }

                Some(Err(err)) => {
                    debug!("Error iterating open files: {err:?}");
                    return StageStepResult::Continue;
                }

                None => {
                    *current_files_iter = None;
                }
            }
        }

        // Get next task and its files iterator
        loop {
            match task_iter.next() {
                Some(Ok(task)) => {
                    match self
                        .operating_system
                        .iter_task_open_files_impl(task.virtual_address)
                    {
                        Ok(files_iter) => {
                            *current_files_iter = Some(files_iter);
                            return StageStepResult::Continue;
                        }

                        Err(err) => {
                            debug!(
                                "Failed to get open files for task {:?}: {err:?}",
                                task.virtual_address
                            );

                            continue;
                        }
                    }
                }

                Some(Err(err)) => {
                    debug!("Error iterating tasks: {err:?}");
                    continue;
                }

                None => return StageStepResult::NextStage,
            }
        }
    }

    /// Perform one step in the memory mappings stage
    fn step_memory_mappings(&mut self) -> StageStepResult {
        let (task_iter, current_mappings_iter) = match &mut self.iterator_stage {
            SyslogIteratorStage::MemoryMappings {
                task_iter,
                current_mappings_iter,
            } => (task_iter, current_mappings_iter),

            _ => return StageStepResult::Done,
        };

        if let Some(mappings_iter) = current_mappings_iter {
            match mappings_iter.next() {
                Some(Ok(mapping)) => {
                    let is_syslog = mapping
                        .file_backing
                        .as_ref()
                        .is_some_and(|fb| fb.path.to_str().unwrap_or("") == SYSLOG_PATH);

                    if !is_syslog {
                        return StageStepResult::Continue;
                    }

                    return Self::process_memory_mapping(
                        self.operating_system,
                        mapping.task,
                        mapping.region.start,
                        mapping.region.end,
                    );
                }

                Some(Err(err)) => {
                    debug!("Error iterating memory mappings: {err:?}");
                    return StageStepResult::Continue;
                }

                None => {
                    *current_mappings_iter = None;
                }
            }
        }

        // Get next task and its mappings iterator
        loop {
            match task_iter.next() {
                Some(Ok(task)) => {
                    match self
                        .operating_system
                        .iter_task_memory_mappings_impl(task.virtual_address)
                    {
                        Ok(mappings_iter) => {
                            *current_mappings_iter = Some(mappings_iter);
                            return StageStepResult::Continue;
                        }

                        Err(err) => {
                            debug!(
                                "Failed to get memory mappings for task {:?}: {err:?}",
                                task.virtual_address
                            );

                            continue;
                        }
                    }
                }

                Some(Err(err)) => {
                    debug!("Error iterating tasks: {err:?}");
                    continue;
                }

                None => return StageStepResult::Done,
            }
        }
    }

    /// Transition to the next stage
    fn transition_to_next_stage(&mut self) {
        self.iterator_stage = match &self.iterator_stage {
            SyslogIteratorStage::OpenFiles { .. } => {
                match self.operating_system.iter_tasks_impl() {
                    Ok(task_iter) => SyslogIteratorStage::MemoryMappings {
                        task_iter,
                        current_mappings_iter: None,
                    },

                    Err(err) => {
                        debug!("Failed to create task iterator: {err:?}");
                        SyslogIteratorStage::Done
                    }
                }
            }

            SyslogIteratorStage::MemoryMappings { .. } => SyslogIteratorStage::Done,
            SyslogIteratorStage::Done => SyslogIteratorStage::Done,
        };
    }

    /// Process an open file and return a SyslogFile if valid
    fn process_open_file(
        &self,
        file_vaddr: VirtualAddress,
        task: VirtualAddress,
        tgid: u32,
    ) -> Option<SyslogFile> {
        let reader = match self.operating_system.get_file_reader(file_vaddr) {
            Ok(reader) => reader,

            Err(err) => {
                debug!(
                    "Failed to create file reader for {SYSLOG_PATH} at {:?}: {err:?}",
                    file_vaddr
                );

                return None;
            }
        };

        let file_region_list = match reader.regions() {
            Ok(region_list) => region_list,

            Err(err) => {
                debug!(
                    "Failed to enumerate regions for {SYSLOG_PATH} at {:?}: {err:?}",
                    file_vaddr
                );

                return None;
            }
        };

        let syslog_region_list: Vec<SyslogFileRegion> = file_region_list
            .iter()
            .filter_map(|region| {
                let region_size = region.end - region.start;
                let mut buffer = vec![0; region_size as usize];

                let buffer = match reader.read(&mut buffer, region.start).map(|bytes_read| {
                    buffer.truncate(bytes_read);
                    buffer
                }) {
                    Ok(buffer) => buffer,

                    Err(err) => {
                        debug!(
                            "Failed to read region {:?} for {SYSLOG_PATH} at {:?}: {err:?}",
                            region, file_vaddr
                        );

                        return None;
                    }
                };

                let lines = extract_valid_lines(&buffer, 10);
                if lines.is_empty() {
                    debug!(
                        "Skipping syslog region {:?} at {:?}: no valid text lines found",
                        region, file_vaddr
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
            virtual_address: file_vaddr,
            task,
            tgid,
            data_source: SyslogFileDataSource::PageCache,
            region_list: syslog_region_list,
        })
    }

    /// Process a memory mapping and return a StageStepResult
    fn process_memory_mapping(
        operating_system: &LinuxOperatingSystem,
        task_vaddr: VirtualAddress,
        region_start: VirtualAddress,
        region_end: VirtualAddress,
    ) -> StageStepResult {
        let vmem_reader = VirtualMemoryReader::new(
            operating_system.memory_dump.as_ref(),
            operating_system.architecture.as_ref(),
        );

        let region_size = (region_end.value() - region_start.value()) as usize;
        let mut buffer = vec![0u8; region_size];

        match vmem_reader.read(&mut buffer, region_start) {
            Ok(bytes_read) => {
                buffer.truncate(bytes_read);

                let lines = extract_valid_lines(&buffer, 10);
                if lines.is_empty() {
                    debug!(
                        "Skipping syslog memory mapping at {:?}: no valid text lines found",
                        region_start
                    );

                    return StageStepResult::Continue;
                }

                let syslog_region = SyslogFileRegion {
                    offset_range: PhysicalAddress::new(0)..PhysicalAddress::new(bytes_read as u64),
                    lines,
                };

                let task_struct = match VirtualStruct::from_name(
                    &vmem_reader,
                    &operating_system.kernel_type_info,
                    "task_struct",
                    &task_vaddr,
                ) {
                    Ok(task_struct) => task_struct,

                    Err(err) => {
                        debug!("{err:?}");
                        return StageStepResult::Error(err);
                    }
                };

                let tgid = match try_chain!(task_struct.traverse("tgid")?.read_u32()) {
                    Ok(tgid) => tgid,

                    Err(err) => {
                        debug!(
                            "Failed to read the tgid field from task {:?}{err:?}",
                            task_vaddr
                        );

                        0
                    }
                };

                StageStepResult::Yield(SyslogFile {
                    virtual_address: region_start,
                    task: task_vaddr,
                    tgid,
                    data_source: SyslogFileDataSource::MemoryMapping,
                    region_list: vec![syslog_region],
                })
            }

            Err(err) => {
                debug!(
                    "Failed to read memory mapping for {SYSLOG_PATH} at {:?}: {err:?}",
                    region_start
                );

                StageStepResult::Continue
            }
        }
    }
}

impl LinuxOperatingSystem {
    /// Returns an iterator over syslog file regions from memory
    pub(super) fn iter_syslog_file_regions_impl(&self) -> Result<SyslogFileIterator<'_>> {
        let task_iter = self.iter_tasks_impl()?;

        Ok(SyslogFileIterator {
            operating_system: self,
            iterator_stage: SyslogIteratorStage::OpenFiles {
                task_iter,
                current_files_iter: None,
            },
            visited_file_vaddr_set: BTreeSet::new(),
        })
    }
}

/// Validates if a text string contains mostly (80%) printable characters
pub(crate) fn is_valid_text(text: &str, min_length: usize) -> bool {
    if text.len() < min_length {
        return false;
    }

    let printable_count = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();

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
#[allow(clippy::unwrap_used)]
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
