//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use mquire::{
    architecture::intel::architecture::IntelArchitecture,
    core::operating_system::OperatingSystem,
    memory::{readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::operating_system::LinuxOperatingSystem,
    snapshot::{lime_snapshot::LimeSnapshot, raw_snapshot::RawSnapshot},
};

use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

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

    /// The PID of the task owning the file
    pid: u32,
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

/// Creates the output path for a given file and PID
fn create_output_path(base_dir: &Path, file_path: &str, pid: u32) -> PathBuf {
    let mut output_path = base_dir.to_path_buf();

    output_path.push(format!("pid_{}", pid));

    let cleaned_path = if let Some(stripped) = file_path.strip_prefix('/') {
        stripped
    } else {
        file_path
    };

    let components: Vec<String> = cleaned_path
        .split('/')
        .map(sanitize_path_component)
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
    pid: u32,
    virtual_address: VirtualAddress,
    output_dir: &Path,
) -> FileState {
    let output_path = create_output_path(output_dir, file_path, pid);

    let reader = match os.get_file_reader(virtual_address) {
        Ok(reader) => reader,
        Err(e) => {
            log::error!("Failed to get file reader for {}: {:?}", file_path, e);
            return FileState::Error;
        }
    };

    let region_list = match reader.regions() {
        Ok(region_list) => region_list,

        Err(e) => {
            log::error!("Failed to get region list for {}: {:?}", file_path, e);
            return FileState::Error;
        }
    };

    if region_list.is_empty() {
        return FileState::Skipped;
    }

    if let Some(parent) = output_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            log::error!("Failed to create directory {}: {}", parent.display(), e);
            return FileState::Error;
        }
    }

    let file_size = match reader.len() {
        Ok(size) => size,

        Err(e) => {
            log::error!("Failed to get file size for {}: {:?}", file_path, e);
            return FileState::Error;
        }
    };

    let mut out_file = match File::create(&output_path) {
        Ok(file) => file,

        Err(e) => {
            log::error!(
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

    for region in &region_list {
        let region_size = (region.end.value() - region.start.value()) as usize;
        let mut buffer = vec![0u8; region_size];

        let region_file_offset = region.start.value();
        let region_file_end = region.end.value();

        if region_file_offset > current_file_offset {
            let gap_size =
                (region_file_offset - current_file_offset).min(file_size - current_file_offset);

            if gap_size > 0 {
                let zero_buffer = vec![0u8; gap_size as usize];
                if let Err(e) = out_file.write_all(&zero_buffer) {
                    log::error!("Failed to write gap padding for {}: {}", file_path, e);
                    section_errors += 1;
                }

                current_file_offset += gap_size;
            }
        }

        match reader.read(&mut buffer, region.start) {
            Ok(bytes_read) => {
                let bytes_to_write = if current_file_offset >= file_size {
                    0
                } else if region_file_end <= file_size {
                    bytes_read
                } else {
                    let valid_bytes = file_size.saturating_sub(region_file_offset);
                    (bytes_read as u64).min(valid_bytes) as usize
                };

                if bytes_read != region_size {
                    if first_error {
                        log::error!(
                            "Partial read for {}: expected {} bytes, got {}",
                            file_path,
                            region_size,
                            bytes_read
                        );
                        first_error = false;
                    }
                    section_errors += 1;
                }

                match out_file.write_all(&buffer[..bytes_to_write]) {
                    Ok(_) => {
                        current_file_offset += bytes_to_write as u64;
                    }

                    Err(e) => {
                        if first_error {
                            log::error!("Failed to write region for {}: {}", file_path, e);
                            first_error = false;
                        }
                        section_errors += 1;
                    }
                }
            }

            Err(e) => {
                if first_error {
                    log::error!("Failed to read region for {}: {:?}", file_path, e);
                    first_error = false;
                }
                section_errors += 1;

                let bytes_to_write = if current_file_offset >= file_size {
                    0
                } else if region_file_end <= file_size {
                    region_size
                } else {
                    let valid_bytes = file_size.saturating_sub(region_file_offset);
                    (region_size as u64).min(valid_bytes) as usize
                };

                if let Err(write_err) = out_file.write_all(&buffer[..bytes_to_write]) {
                    if first_error {
                        log::error!(
                            "Failed to write zero-padded region for {}: {}",
                            file_path,
                            write_err
                        );
                        first_error = false;
                    }
                    section_errors += 1;
                } else {
                    current_file_offset += bytes_to_write as u64;
                }
            }
        }
    }

    if section_errors == 0 {
        FileState::Success
    } else {
        FileState::Error
    }
}

/// Dumps all open files from the memory dump to the output directory
pub fn dump_files(memory_dump_path: &Path, output_dir: &Path) -> io::Result<()> {
    log::info!("Opening memory dump: {}", memory_dump_path.display());

    let memory_dump: Arc<dyn Readable> =
        match memory_dump_path.extension().and_then(|ext| ext.to_str()) {
            Some("raw") => RawSnapshot::new(memory_dump_path)
                .map_err(|e| io::Error::other(format!("Failed to open raw snapshot: {:?}", e)))?,

            Some("lime") => LimeSnapshot::new(memory_dump_path)
                .map_err(|e| io::Error::other(format!("Failed to open lime snapshot: {:?}", e)))?,

            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unsupported memory dump format. Use .raw or .lime extension.",
                ));
            }
        };

    log::info!("Initializing Linux operating system analyzer...");
    let os = LinuxOperatingSystem::new(memory_dump, IntelArchitecture::new())
        .map_err(|e| io::Error::other(format!("Failed to initialize OS: {:?}", e)))?;

    log::info!("Getting task open file list...");
    let file_list = os
        .get_task_open_file_list()
        .map_err(|e| io::Error::other(format!("Failed to get file list: {:?}", e)))?;

    log::info!("Found {} open files", file_list.len());

    let mut success_count = 0;
    let mut error_count = 0;
    let mut skipped_count = 0;
    let mut summary: Vec<FileSummary> = Vec::new();

    for file_info in &file_list {
        let state = dump_file(
            os.as_ref(),
            &file_info.path,
            file_info.pid,
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
            path: file_info.path.clone(),
            pid: file_info.pid,
        });
    }

    println!("Legend: SK = skipped, OK = all good, ER = errored\n");

    println!("Summary:");
    println!("  Total files found: {}", file_list.len());
    println!("  Successfully dumped: {}", success_count);
    println!("  Skipped: {}", skipped_count);
    println!("  Errors: {}\n", error_count);

    println!("File Status:");
    for file_summary in &summary {
        println!(
            "  {} {} (PID {})",
            file_summary.state.as_str(),
            file_summary.path,
            file_summary.pid
        );
    }

    Ok(())
}
