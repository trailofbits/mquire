//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

//! ELF core dump snapshot format.
//!
//! ELF core files (as produced by `virsh dump --memory-only` or QEMU's
//! `dump-guest-memory`) contain physical memory in PT_LOAD segments. Each
//! segment maps a physical address range to a file offset.
//!
//! [`Readable::regions`] returns all PT_LOAD ranges. PT_NOTE and other
//! segment types are ignored.
//!
//! # Creating a dump with virsh
//!
//! ```sh
//! virsh -c qemu:///system dump <domain> /path/to/output.elf --memory-only --format elf
//! ```
//!
//! `--memory-only` skips device state, producing only physical memory.
//! The VM is paused during the dump and resumed after (add `--live` to
//! avoid pausing, at the cost of snapshot consistency).

use crate::{
    memory::{
        error::{Error, ErrorKind, Result},
        primitives::PhysicalAddress,
        readable::Readable,
    },
    utils::{readable_file::ReadableFile, reader::Reader},
};

use {log::info, memmap2::Mmap};

use std::{cmp::Ordering, fs::File, ops::Range, path::Path, sync::Arc};

/// Header magic number at the start of every ELF file
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// e_ident[EI_CLASS] value for 32-bit ELF
const ELFCLASS32: u8 = 1;

/// e_ident[EI_CLASS] value for 64-bit ELF
const ELFCLASS64: u8 = 2;

/// e_ident[EI_DATA] value for little-endian
const ELFDATA2LSB: u8 = 1;

/// e_ident[EI_DATA] value for big-endian
const ELFDATA2MSB: u8 = 2;

/// e_type value for core dump files
const ET_CORE: u16 = 4;

/// p_type value for loadable segments
const PT_LOAD: u32 = 1;

/// Offset of the ELF class byte in e_ident
const EI_CLASS: usize = 4;

/// Offset of the data encoding byte in e_ident
const EI_DATA: usize = 5;

/// Offset of e_type (ELF file type)
const E_TYPE_OFFSET: usize = 16;

/// ELF32 Offset of e_phoff (program header table file offset)
const E32_PHOFF_OFFSET: usize = 28;

/// ELF32 Offset of e_phentsize (program header entry size)
const E32_PHENTSIZE_OFFSET: usize = 42;

/// ELF32 Offset of e_phnum (program header entry count)
const E32_PHNUM_OFFSET: usize = 44;

/// ELF32 Offset of p_offset (segment file offset)
const P32_OFFSET_OFFSET: usize = 4;

/// ELF32 Offset of p_paddr (segment physical address)
const P32_PADDR_OFFSET: usize = 12;

/// ELF32 Offset of p_filesz (segment size in file)
const P32_FILESZ_OFFSET: usize = 16;

/// ELF64 Offset of e_phoff (program header table file offset)
const E64_PHOFF_OFFSET: usize = 32;

/// ELF64 Offset of e_phentsize (program header entry size)
const E64_PHENTSIZE_OFFSET: usize = 54;

/// ELF64 Offset of e_phnum (program header entry count)
const E64_PHNUM_OFFSET: usize = 56;

/// ELF64 Offset of p_offset (segment file offset)
const P64_OFFSET_OFFSET: usize = 8;

/// ELF64 Offset of p_paddr (segment physical address)
const P64_PADDR_OFFSET: usize = 24;

/// ELF64 Offset of p_filesz (segment size in file)
const P64_FILESZ_OFFSET: usize = 32;

/// ELF class (bitness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElfClass {
    Elf32,
    Elf64,
}

/// Represents an ELF core dump snapshot.
pub struct ElfCoreSnapshot {
    /// Memory-mapped view of the snapshot file.
    mmap: Mmap,

    /// Memory ranges from PT_LOAD segments, sorted by physical address.
    memory_range_list: Vec<MemoryRange>,

    /// Total size of all mapped memory.
    size: u64,
}

impl ElfCoreSnapshot {
    /// Creates a new ELF core snapshot from the given path.
    pub fn new(file_path: &Path) -> Result<Arc<Self>> {
        let mut file = File::open(file_path)?;
        let readable = ReadableFile::new(&mut file);

        let loads = ElfCoreLoads::new(&readable)?;

        Ok(Arc::new(ElfCoreSnapshot {
            #[allow(unsafe_code)]
            mmap: unsafe { Mmap::map(&file)? },
            memory_range_list: loads.memory_range_list,
            size: loads.size,
        }))
    }
}

impl Readable for ElfCoreSnapshot {
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
                    &format!("Address {physical_address} is not mapped by the snapshot file"),
                )
            })?;

        let memory_range = self
            .memory_range_list
            .get(memory_range_index)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::IOError,
                    &format!("Address {physical_address} is not mapped by the snapshot file"),
                )
            })?;

        let range_offset = physical_address.value() - memory_range.s_addr;

        let readable_bytes =
            std::cmp::min(buffer.len() as u64, memory_range.len() - range_offset) as usize;

        let read_buffer = buffer.get_mut(..readable_bytes).ok_or_else(|| {
            Error::new(
                ErrorKind::IOError,
                &format!("Failed to get mutable slice of buffer for {readable_bytes} bytes"),
            )
        })?;

        let file_offset = memory_range.file_offset + range_offset;

        let start = file_offset as usize;
        if start >= self.mmap.len() {
            return Err(Error::new(
                ErrorKind::IOError,
                &format!(
                    "File offset 0x{start:X} exceeds snapshot file size for address {physical_address}",
                ),
            ));
        }

        let end = (start + readable_bytes).min(self.mmap.len());

        let bytes_to_read = end - start;
        if bytes_to_read > 0 {
            read_buffer[..bytes_to_read].copy_from_slice(&self.mmap[start..end]);
        }

        Ok(bytes_to_read)
    }

    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }

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

/// A memory range within the ELF core file.
struct MemoryRange {
    /// File offset of the segment data.
    file_offset: u64,

    /// Starting physical address.
    s_addr: u64,

    /// Ending physical address (exclusive).
    e_addr: u64,
}

impl MemoryRange {
    fn len(&self) -> u64 {
        self.e_addr - self.s_addr
    }
}

/// PT_LOAD segment fields from a program header entry.
struct LoadSegment {
    /// File offset of the segment data.
    offset: u64,

    /// Physical address of the segment.
    paddr: u64,

    /// Size of the segment in the file.
    filesz: u64,
}

/// ELF program header table location.
struct ProgramHeaderTable {
    /// File offset of the program header table.
    offset: u64,

    /// Size of each program header entry.
    entry_size: u16,

    /// Number of program header entries.
    entry_count: u16,
}

/// Parsed PT_LOAD segments from an ELF core file.
struct ElfCoreLoads {
    /// Memory ranges from PT_LOAD segments, sorted by physical address.
    memory_range_list: Vec<MemoryRange>,

    /// Total size of all mapped memory.
    size: u64,
}

impl ElfCoreLoads {
    /// Parses an ELF core file, validating headers and extracting PT_LOAD segments.
    fn new(readable: &ReadableFile) -> Result<Self> {
        let mut magic = [0u8; 4];
        readable.read(&mut magic, PhysicalAddress::default())?;
        if magic != ELF_MAGIC {
            return Err(Error::new(
                ErrorKind::InvalidSnapshotFormat,
                &format!(
                    "Invalid ELF magic: expected {:02X?}, got {:02X?}",
                    ELF_MAGIC, magic
                ),
            ));
        }

        let class = Self::read_class(readable)?;
        let little_endian = Self::read_endianness(readable)?;

        info!(
            "ELF core file: {}, {}",
            match class {
                ElfClass::Elf32 => "32-bit",
                ElfClass::Elf64 => "64-bit",
            },
            if little_endian {
                "little-endian"
            } else {
                "big-endian"
            },
        );

        let reader = Reader::new(readable, little_endian);

        let e_type = reader.read_u16(PhysicalAddress::new(E_TYPE_OFFSET as u64))?;
        if e_type != ET_CORE {
            return Err(Error::new(
                ErrorKind::InvalidSnapshotFormat,
                &format!("Expected ET_CORE (type {}), got type {}", ET_CORE, e_type),
            ));
        }

        let ph_table = Self::read_program_header_table(&reader, class)?;

        // Parse program headers, collecting PT_LOAD segments
        let mut memory_range_list: Vec<MemoryRange> = Vec::new();
        let mut size: u64 = 0;

        for i in 0..ph_table.entry_count as u64 {
            let ph_offset = i
                .checked_mul(ph_table.entry_size as u64)
                .and_then(|off| ph_table.offset.checked_add(off))
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidSnapshotFormat,
                        &format!("Offset overflow at program header {i}"),
                    )
                })?;

            let p_type = reader.read_u32(PhysicalAddress::new(ph_offset))?;
            if p_type != PT_LOAD {
                continue;
            }

            let segment = Self::read_load_segment(&reader, class, ph_offset)?;
            if segment.filesz == 0 {
                continue;
            }

            let e_addr = segment.paddr.checked_add(segment.filesz).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidSnapshotFormat,
                    &format!(
                        "Address overflow in PT_LOAD segment at program header {}",
                        i
                    ),
                )
            })?;

            let memory_range = MemoryRange {
                file_offset: segment.offset,
                s_addr: segment.paddr,
                e_addr,
            };

            if memory_range_list.iter().any(|range| {
                memory_range.s_addr < range.e_addr && range.s_addr < memory_range.e_addr
            }) {
                return Err(Error::new(
                    ErrorKind::InvalidSnapshotFormat,
                    &format!(
                        "Overlapping PT_LOAD segment at program header {} (paddr {:#x})",
                        i, segment.paddr
                    ),
                ));
            }

            size = size.checked_add(memory_range.len()).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidSnapshotFormat,
                    &format!("Total size overflow at program header {i}"),
                )
            })?;

            let pos = memory_range_list
                .binary_search_by(|range| range.s_addr.cmp(&memory_range.s_addr))
                .unwrap_or_else(|e| e);

            memory_range_list.insert(pos, memory_range);
        }

        if memory_range_list.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidSnapshotFormat,
                "No PT_LOAD segments found in ELF core file",
            ));
        }

        Ok(Self {
            memory_range_list,
            size,
        })
    }

    /// Reads and validates the ELF class.
    fn read_class(readable: &ReadableFile) -> Result<ElfClass> {
        let mut class_byte = [0u8; 1];
        readable.read(&mut class_byte, PhysicalAddress::new(EI_CLASS as u64))?;

        match class_byte[0] {
            ELFCLASS32 => Ok(ElfClass::Elf32),
            ELFCLASS64 => Ok(ElfClass::Elf64),

            other => Err(Error::new(
                ErrorKind::InvalidSnapshotFormat,
                &format!("Unknown ELF class: {other}"),
            )),
        }
    }

    /// Reads the program header table location from the ELF header.
    fn read_program_header_table(reader: &Reader, class: ElfClass) -> Result<ProgramHeaderTable> {
        match class {
            ElfClass::Elf32 => Ok(ProgramHeaderTable {
                offset: reader.read_u32(PhysicalAddress::new(E32_PHOFF_OFFSET as u64))? as u64,
                entry_size: reader.read_u16(PhysicalAddress::new(E32_PHENTSIZE_OFFSET as u64))?,
                entry_count: reader.read_u16(PhysicalAddress::new(E32_PHNUM_OFFSET as u64))?,
            }),

            ElfClass::Elf64 => Ok(ProgramHeaderTable {
                offset: reader.read_u64(PhysicalAddress::new(E64_PHOFF_OFFSET as u64))?,
                entry_size: reader.read_u16(PhysicalAddress::new(E64_PHENTSIZE_OFFSET as u64))?,
                entry_count: reader.read_u16(PhysicalAddress::new(E64_PHNUM_OFFSET as u64))?,
            }),
        }
    }

    /// Reads a PT_LOAD segment's fields from a program header entry.
    fn read_load_segment(reader: &Reader, class: ElfClass, ph_offset: u64) -> Result<LoadSegment> {
        match class {
            ElfClass::Elf32 => Ok(LoadSegment {
                offset: reader
                    .read_u32(PhysicalAddress::new(ph_offset + P32_OFFSET_OFFSET as u64))?
                    as u64,
                paddr: reader.read_u32(PhysicalAddress::new(ph_offset + P32_PADDR_OFFSET as u64))?
                    as u64,
                filesz: reader
                    .read_u32(PhysicalAddress::new(ph_offset + P32_FILESZ_OFFSET as u64))?
                    as u64,
            }),

            ElfClass::Elf64 => Ok(LoadSegment {
                offset: reader
                    .read_u64(PhysicalAddress::new(ph_offset + P64_OFFSET_OFFSET as u64))?,
                paddr: reader
                    .read_u64(PhysicalAddress::new(ph_offset + P64_PADDR_OFFSET as u64))?,
                filesz: reader
                    .read_u64(PhysicalAddress::new(ph_offset + P64_FILESZ_OFFSET as u64))?,
            }),
        }
    }

    /// Returns `true` for little-endian, `false` for big-endian.
    fn read_endianness(readable: &ReadableFile) -> Result<bool> {
        let mut data = [0u8; 1];
        readable.read(&mut data, PhysicalAddress::new(EI_DATA as u64))?;
        match data[0] {
            ELFDATA2LSB => Ok(true),
            ELFDATA2MSB => Ok(false),

            other => Err(Error::new(
                ErrorKind::InvalidSnapshotFormat,
                &format!("Unknown ELF data encoding: {other}"),
            )),
        }
    }
}
