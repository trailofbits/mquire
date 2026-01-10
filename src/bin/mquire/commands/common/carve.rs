//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::commands::command_registry::{Command, CommandContext};

use mquire::{
    core::virtual_memory_reader::VirtualMemoryReader,
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        virtual_address::VirtualAddress,
    },
};

use clap::{Parser, error::ErrorKind as ClapErrorKind};

use std::{
    cmp,
    collections::BTreeMap,
    fs::File,
    io::{self, Write},
    ops::Range,
    path::PathBuf,
};

/// Buffer size for reading/writing operations (4MB)
const CARVE_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Carve a region of virtual memory to disk
#[derive(Parser, Debug)]
#[command(name = "carve")]
#[command(about = "Carve a region of virtual memory to disk", long_about = None)]
struct CarveArgs {
    /// Root page table address (hex string with optional 0x prefix)
    #[arg(value_name = "ROOT_PAGE_TABLE")]
    root_page_table: String,

    /// Virtual address to start carving from (hex string with optional 0x prefix)
    #[arg(value_name = "VIRTUAL_ADDRESS")]
    virtual_address: String,

    /// Number of bytes to carve
    #[arg(value_name = "SIZE")]
    size: usize,

    /// Output file path
    #[arg(value_name = "DESTINATION_PATH")]
    destination_path: PathBuf,
}

/// Parses a hex string (with or without 0x prefix) into a u64
fn parse_hex_address(hex_str: &str) -> Result<u64, String> {
    let cleaned = hex_str
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    u64::from_str_radix(cleaned, 16)
        .map_err(|e| format!("Failed to parse hex address '{}': {}", hex_str, e))
}

/// A region in the carving plan
enum CarveRegion<'a> {
    /// A mapped region
    Mapped(&'a Range<u64>),

    /// An unmapped region
    Unmapped(&'a Range<u64>),
}

/// Plan for a carve operation, describing which regions are mapped vs unmapped
struct CarvingPlan {
    /// Root page table
    root_page_table: PhysicalAddress,

    /// Start of the carve range
    carve_start: u64,

    /// Total size of the carve range
    total_size: usize,

    /// Memory ranges that are readable using the provided root page table
    mapped_ranges: BTreeMap<PhysicalAddress, Range<u64>>,

    /// Unreadable memory ranges
    unmapped_ranges: Vec<Range<u64>>,
}

impl CarvingPlan {
    /// Generates a carving plan by determining which parts of the range are mapped vs unmapped
    fn new(
        context: &CommandContext,
        root_page_table: PhysicalAddress,
        carve_start: u64,
        carve_size: usize,
    ) -> io::Result<CarvingPlan> {
        let regions = {
            let mut regions = context
                .architecture
                .enumerate_page_table_regions(context.snapshot.as_ref(), root_page_table)
                .map_err(|e| {
                    io::Error::other(format!("Failed to enumerate page table regions: {:?}", e))
                })?;

            regions.sort_by_key(|region| {
                let raw_vaddr = region.virtual_address.value();
                raw_vaddr.value()
            });

            regions
        };

        let mut mapped_ranges = BTreeMap::new();
        let mut unmapped_ranges = Vec::new();

        let mut current_pos = carve_start;
        let carve_end = carve_start.saturating_add(carve_size as u64);

        for region in regions {
            let region_start = region.virtual_address.value().value();
            let region_end = region_start.saturating_add(region.size);

            if region_end <= carve_start || region_start >= carve_end {
                continue;
            }

            if current_pos < region_start {
                let gap_size = cmp::min(region_start - current_pos, carve_end - current_pos);
                unmapped_ranges.push(current_pos..current_pos + gap_size);

                current_pos = region_start;
            }

            let overlap_start = cmp::max(current_pos, region_start);
            let overlap_end = cmp::min(carve_end, region_end);

            if overlap_start < overlap_end {
                let offset_in_region = overlap_start - region_start;

                mapped_ranges.insert(
                    region.physical_address + offset_in_region,
                    overlap_start..overlap_end,
                );

                current_pos = overlap_end;
            }

            if current_pos >= carve_end {
                break;
            }
        }

        if current_pos < carve_end {
            unmapped_ranges.push(current_pos..carve_end);
        }

        Ok(CarvingPlan {
            root_page_table,
            carve_start,
            total_size: carve_size,
            mapped_ranges,
            unmapped_ranges,
        })
    }

    // Writes a summary of the carving plan
    fn write_summary(&self, w: &mut impl Write) -> io::Result<()> {
        let range_start = VirtualAddress::new(
            self.root_page_table,
            RawVirtualAddress::new(self.carve_start),
        );

        writeln!(w, "Range start\n  {}\n", range_start)?;
        writeln!(w, "Range end\n  {}\n", range_start + self.total_size)?;
        writeln!(w, "Count\n {} bytes\n", self.total_size)?;

        if !self.mapped_ranges.is_empty() {
            writeln!(w, "Mapped regions")?;

            for (phys_addr, virt_range) in &self.mapped_ranges {
                writeln!(
                    w,
                    "  0x{:016x} - 0x{:016x} => {}",
                    virt_range.start, virt_range.end, phys_addr
                )?;
            }
            writeln!(w)?;
        }

        if !self.unmapped_ranges.is_empty() {
            writeln!(w, "Unmapped regions")?;

            for range in &self.unmapped_ranges {
                writeln!(w, "  0x{:016x} - 0x{:016x}", range.start, range.end,)?;
            }

            writeln!(w)?;
        }

        Ok(())
    }

    /// Returns an iterator over all regions in virtual address order
    fn iter(&self) -> impl Iterator<Item = CarveRegion<'_>> {
        let mut regions: Vec<_> = self
            .mapped_ranges
            .values()
            .map(|r| (r.start, CarveRegion::Mapped(r)))
            .chain(
                self.unmapped_ranges
                    .iter()
                    .map(|r| (r.start, CarveRegion::Unmapped(r))),
            )
            .collect();

        regions.sort_by_key(|(start, _)| *start);
        regions.into_iter().map(|(_, region)| region)
    }
}

/// Writes a mapped range to the output file
fn write_mapped_range(
    output_file: &mut File,
    virtual_memory_reader: &VirtualMemoryReader,
    root_page_table: PhysicalAddress,
    virt_range: &Range<u64>,
    buffer: &mut [u8],
) -> io::Result<()> {
    let mut remaining = virt_range.end - virt_range.start;
    let mut current_vaddr =
        VirtualAddress::new(root_page_table, RawVirtualAddress::new(virt_range.start));

    while remaining > 0 {
        let chunk_size = cmp::min(remaining as usize, buffer.len());

        let bytes_read = virtual_memory_reader
            .read(&mut buffer[..chunk_size], current_vaddr)
            .map_err(|e| {
                io::Error::other(format!(
                    "Failed to read mapped region at {}: {:?}",
                    current_vaddr, e
                ))
            })?;

        if bytes_read == 0 {
            return Err(io::Error::other(format!(
                "Unexpected zero-length read at {}",
                current_vaddr
            )));
        }

        output_file.write_all(&buffer[..bytes_read])?;
        current_vaddr = current_vaddr + bytes_read as u64;

        remaining -= bytes_read as u64;
    }

    Ok(())
}

/// Writes an unmapped range (filled with zeros) to the output file
fn write_unmapped_range(
    output_file: &mut File,
    range: &Range<u64>,
    buffer: &mut [u8],
) -> io::Result<()> {
    let mut remaining = range.end - range.start;
    buffer.fill(0);

    while remaining > 0 {
        let chunk_size = cmp::min(remaining as usize, buffer.len());

        output_file.write_all(&buffer[..chunk_size])?;
        remaining -= chunk_size as u64;
    }

    Ok(())
}

/// Performs the actual carve operation
fn execute_carve(
    virtual_memory_reader: &VirtualMemoryReader,
    root_page_table: PhysicalAddress,
    plan: &CarvingPlan,
    output_path: &PathBuf,
) -> io::Result<()> {
    let mut output_file = File::create(output_path)?;
    let mut buffer = vec![0u8; CARVE_BUFFER_SIZE];

    for region in plan.iter() {
        match region {
            CarveRegion::Mapped(virt_range) => {
                write_mapped_range(
                    &mut output_file,
                    virtual_memory_reader,
                    root_page_table,
                    virt_range,
                    &mut buffer,
                )?;
            }

            CarveRegion::Unmapped(range) => {
                write_unmapped_range(&mut output_file, range, &mut buffer)?;
            }
        }
    }

    Ok(())
}

pub struct CarveCommand;

impl CarveCommand {
    pub fn new() -> Self {
        Self
    }
}

impl Command for CarveCommand {
    fn name(&self) -> &str {
        "carve"
    }

    fn description(&self) -> &str {
        "Carve a region of virtual memory to disk"
    }

    fn execute(&self, args: &str, context: &CommandContext) -> io::Result<()> {
        let args_vec: Vec<&str> = if args.is_empty() {
            vec!["carve"]
        } else {
            let mut v = vec!["carve"];
            v.extend(args.split_whitespace());

            v
        };

        let parsed_args = match CarveArgs::try_parse_from(args_vec) {
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

        let root_page_table_addr = parse_hex_address(&parsed_args.root_page_table)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let virtual_address_raw = parse_hex_address(&parsed_args.virtual_address)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let root_page_table = PhysicalAddress::new(root_page_table_addr);

        let plan = CarvingPlan::new(
            context,
            root_page_table,
            virtual_address_raw,
            parsed_args.size,
        )?;

        plan.write_summary(&mut io::stdout())?;

        let virtual_memory_reader =
            VirtualMemoryReader::new(context.snapshot.as_ref(), context.architecture.as_ref());

        execute_carve(
            &virtual_memory_reader,
            root_page_table,
            &plan,
            &parsed_args.destination_path,
        )?;

        Ok(())
    }
}

impl Default for CarveCommand {
    fn default() -> Self {
        Self::new()
    }
}
