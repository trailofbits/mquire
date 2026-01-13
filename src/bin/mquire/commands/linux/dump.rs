//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::commands::command_registry::{Command, CommandContext};

use mquire::{
    core::operating_system::OperatingSystem, memory::virtual_address::VirtualAddress,
    operating_system::linux::operating_system::LinuxOperatingSystem,
};

use {
    clap::{Parser, error::ErrorKind as ClapErrorKind},
    log::{debug, error},
};

use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

/// Read buffer size for file extraction
const READ_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Dump all open files from tasks to disk
#[derive(Parser, Debug)]
#[command(name = "dump")]
#[command(about = "Dump all open files from tasks to disk", long_about = None)]
struct DumpArgs {
    /// Output directory for extracted files
    output: PathBuf,
}

/// Represents the state of a dumped file
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileState {
    /// File has been skipped because it was empty
    Skipped,

    /// File has been dumped successfully
    Success,

    /// An error occurred while dumping the file
    Error,
}

impl FileState {
    fn as_str(&self) -> &str {
        match self {
            FileState::Skipped => "SK",
            FileState::Success => "OK",
            FileState::Error => "ER",
        }
    }
}

/// Summary information for a dumped file
struct FileSummary {
    /// The state of the file dump
    state: FileState,

    /// The file path
    path: String,

    /// The TGID of the task owning the file
    tgid: u32,
}

/// A command that dumps all open files from tasks to disk
pub struct DumpCommand;

impl DumpCommand {
    pub fn new() -> Self {
        Self
    }

    /// Sanitizes a path component to be safe for filesystem usage
    fn sanitize_path_component(component: &str) -> String {
        component
            .chars()
            .map(|c| match c {
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                c if c.is_control() => '_',
                c => c,
            })
            .collect()
    }

    /// Creates the output path for a given file and TGID
    fn create_output_path(base_dir: &Path, file_path: &str, tgid: u32) -> PathBuf {
        let mut output_path = base_dir.to_path_buf();

        output_path.push(format!("tgid_{}", tgid));

        let cleaned_path = if let Some(stripped) = file_path.strip_prefix('/') {
            stripped
        } else {
            file_path
        };

        let components: Vec<String> = cleaned_path
            .split('/')
            .map(Self::sanitize_path_component)
            .collect();

        for component in &components[..components.len().saturating_sub(1)] {
            if !component.is_empty() {
                output_path.push(component);
            }
        }

        if let Some(filename) = components.last() {
            if !filename.is_empty() {
                output_path.push(filename);
            } else {
                output_path.push("_unnamed_");
            }
        }

        output_path
    }

    /// Dumps a single file to the output directory
    fn dump_file(
        os: &dyn OperatingSystem,
        file_path: &str,
        tgid: u32,
        virtual_address: VirtualAddress,
        output_dir: &Path,
    ) -> FileState {
        let output_path = Self::create_output_path(output_dir, file_path, tgid);

        let reader = match os.get_file_reader(virtual_address) {
            Ok(reader) => reader,

            Err(e) => {
                error!("Failed to get file reader for {}: {:?}", file_path, e);
                return FileState::Error;
            }
        };

        let region_list = match reader.regions() {
            Ok(region_list) => region_list,

            Err(e) => {
                error!("Failed to get region list for {}: {:?}", file_path, e);
                return FileState::Error;
            }
        };

        if region_list.is_empty() {
            return FileState::Skipped;
        }

        if let Some(parent) = output_path.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            error!("Failed to create directory {}: {}", parent.display(), e);
            return FileState::Error;
        }

        let file_size = match reader.len() {
            Ok(size) => size,

            Err(e) => {
                error!("Failed to get file size for {}: {:?}", file_path, e);
                return FileState::Error;
            }
        };

        let mut out_file = match File::create(&output_path) {
            Ok(file) => file,

            Err(e) => {
                error!(
                    "Failed to create output file {}: {}",
                    output_path.display(),
                    e
                );
                return FileState::Error;
            }
        };

        let mut section_errors = 0;
        let mut first_error = true;
        let mut current_file_offset: u64 = 0;

        let mut buffer = vec![0u8; READ_BUFFER_SIZE];

        for region in &region_list {
            let region_size = region.end.value() - region.start.value();
            let region_file_offset = region.start.value();

            // Fill gap with zeros if needed
            if region_file_offset > current_file_offset {
                let gap_size =
                    (region_file_offset - current_file_offset).min(file_size - current_file_offset);

                if gap_size > 0 {
                    let mut remaining = gap_size;
                    while remaining > 0 {
                        let chunk_size = (remaining as usize).min(READ_BUFFER_SIZE);
                        buffer[..chunk_size].fill(0);

                        if let Err(e) = out_file.write_all(&buffer[..chunk_size]) {
                            error!("Failed to write gap padding for {}: {}", file_path, e);
                            section_errors += 1;
                            break;
                        }

                        remaining -= chunk_size as u64;
                    }

                    current_file_offset += gap_size;
                }
            }

            let mut region_offset = 0u64;
            let mut region_had_error = false;

            while region_offset < region_size {
                let chunk_size = ((region_size - region_offset) as usize).min(READ_BUFFER_SIZE);
                let chunk_address = region.start + region_offset;

                let bytes_to_process = if current_file_offset >= file_size {
                    0
                } else {
                    let remaining_in_file = file_size.saturating_sub(current_file_offset);
                    (chunk_size as u64).min(remaining_in_file) as usize
                };

                if bytes_to_process == 0 {
                    break;
                }

                match reader.read(&mut buffer[..chunk_size], chunk_address) {
                    Ok(bytes_read) => {
                        if bytes_read != chunk_size && !region_had_error {
                            if first_error {
                                error!(
                                    "Partial read for {}: expected {} bytes, got {}",
                                    file_path, chunk_size, bytes_read
                                );

                                first_error = false;
                            }

                            section_errors += 1;
                            region_had_error = true;
                        }

                        let bytes_to_write = bytes_read.min(bytes_to_process);
                        match out_file.write_all(&buffer[..bytes_to_write]) {
                            Ok(_) => {
                                current_file_offset += bytes_to_write as u64;
                            }

                            Err(e) => {
                                if first_error {
                                    error!("Failed to write region for {}: {}", file_path, e);
                                    first_error = false;
                                }

                                section_errors += 1;
                                break;
                            }
                        }
                    }

                    Err(e) => {
                        if !region_had_error {
                            if first_error {
                                error!("Failed to read region for {}: {:?}", file_path, e);
                                first_error = false;
                            }

                            section_errors += 1;
                            region_had_error = true;
                        }

                        buffer[..bytes_to_process].fill(0);
                        if let Err(write_err) = out_file.write_all(&buffer[..bytes_to_process]) {
                            if first_error {
                                error!(
                                    "Failed to write zero-padded region for {}: {}",
                                    file_path, write_err
                                );

                                first_error = false;
                            }

                            section_errors += 1;
                            break;
                        } else {
                            current_file_offset += bytes_to_process as u64;
                        }
                    }
                }

                region_offset += chunk_size as u64;
            }
        }

        if section_errors == 0 {
            FileState::Success
        } else {
            FileState::Error
        }
    }
}

impl Command for DumpCommand {
    fn name(&self) -> &str {
        "dump"
    }

    fn description(&self) -> &str {
        "Dump all open files from tasks to disk"
    }

    fn execute(&self, args: &str, context: &CommandContext) -> io::Result<()> {
        let args_vec: Vec<&str> = if args.is_empty() {
            vec!["dump"]
        } else {
            let mut v = vec!["dump"];
            v.extend(args.split_whitespace());
            v
        };

        let parsed_args = match DumpArgs::try_parse_from(args_vec) {
            Ok(args) => args,

            Err(e) => {
                if e.kind() == ClapErrorKind::DisplayHelp
                    || e.kind() == ClapErrorKind::DisplayVersion
                {
                    print!("{}", e);
                    return Ok(());
                }

                return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()));
            }
        };

        let system = context
            .system
            .clone()
            .as_any_arc()
            .downcast::<LinuxOperatingSystem>()
            .map_err(|_| {
                io::Error::other("Failed to downcast to LinuxOperatingSystem".to_string())
            })?;

        let output_dir = &parsed_args.output;

        let task_iter = system
            .iter_tasks()
            .map_err(|e| io::Error::other(format!("Failed to get task iterator: {:?}", e)))?;

        let mut success_count = 0;
        let mut error_count = 0;
        let mut skipped_count = 0;
        let mut summary: Vec<FileSummary> = Vec::new();

        for task_result in task_iter {
            let task = match task_result {
                Ok(task) => task,
                Err(e) => {
                    debug!("Failed to read task: {:?}", e);
                    continue;
                }
            };

            let files_iter = match system.iter_task_open_files(task.virtual_address) {
                Ok(iter) => iter,
                Err(e) => {
                    debug!("Failed to get open files for task {}: {:?}", task.tgid, e);
                    continue;
                }
            };

            for file_result in files_iter {
                let file_info = match file_result {
                    Ok(file_info) => file_info,
                    Err(e) => {
                        debug!("Failed to read file info: {:?}", e);
                        continue;
                    }
                };

                let state = Self::dump_file(
                    system.as_ref(),
                    &file_info.path,
                    file_info.tgid,
                    file_info.virtual_address,
                    output_dir,
                );

                match state {
                    FileState::Success => success_count += 1,
                    FileState::Error => error_count += 1,
                    FileState::Skipped => skipped_count += 1,
                }

                summary.push(FileSummary {
                    state,
                    path: file_info.path,
                    tgid: file_info.tgid,
                });
            }
        }

        println!("Legend: SK = skipped, OK = all good, ER = errored\n");

        println!("Summary:");
        println!("  Total files processed: {}", summary.len());
        println!("  Successfully dumped: {}", success_count);
        println!("  Skipped: {}", skipped_count);
        println!("  Errors: {}\n", error_count);

        println!("File Status:");
        for file_summary in &summary {
            println!(
                "  {} {} (TGID {})",
                file_summary.state.as_str(),
                file_summary.path,
                file_summary.tgid
            );
        }

        Ok(())
    }
}

impl Default for DumpCommand {
    fn default() -> Self {
        Self::new()
    }
}
