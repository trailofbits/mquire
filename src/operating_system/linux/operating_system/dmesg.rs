//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        architecture::Architecture,
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        entities::dmesg::{DmesgDataSource, DmesgEntry},
        operating_system::{LinuxOperatingSystem, syslog_file::is_valid_text},
        virtual_struct::VirtualStruct,
    },
};

use {btfparse::TypeInformation, log::debug};

use std::sync::Arc;

//
// Constants for the printk ringbuffer
//

// Mask for extracting descriptor state
const PRB_DESC_FLAGS_SHIFT: u64 = 64 - 2;
const PRB_DESC_STATE_MASK: u64 = 0x3;
const PRB_DESC_ID_MASK: u64 = !(PRB_DESC_STATE_MASK << PRB_DESC_FLAGS_SHIFT);

// State values
const PRB_DESC_FINALIZED: u64 = 0x2;
const PRB_DESC_COMMITTED: u64 = 0x1;

// Special lpos values indicating no data
const PRB_FAILED_LPOS: u64 = 0x1;
const PRB_EMPTY_LINE_LPOS: u64 = 0x3;

/// Descriptor ring information from printk_ringbuffer
struct PrbDescRing {
    /// Pointer to the prb_desc array
    descs_array_vaddr: VirtualAddress,

    /// Pointer to the printk_info array
    infos_array_vaddr: VirtualAddress,

    /// Number of descriptors in the ring
    count: u64,

    /// Size of the prb_desc struct (descs_array_vaddr elements)
    prb_desc_size: u64,

    /// Size of the printk_info struct (infos_array_vaddr elements)
    printk_info_size: u64,

    /// ID of the oldest descriptor
    tail_id: u64,

    /// ID of the newest descriptor
    head_id: u64,
}

/// Text data ring information from printk_ringbuffer
struct TextDataRing {
    /// Pointer to the text data buffer
    virtual_address: VirtualAddress,

    /// Size of the text data buffer in bytes
    size: u64,
}

/// Iterator over kernel dmesg entries from the printk ringbuffer
pub struct DmesgEntryIterator<'a> {
    /// Memory dump to read from
    memory_dump: Arc<dyn Readable>,

    /// Target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel type information (BTF)
    kernel_type_info: &'a TypeInformation,

    /// Descriptor ring metadata
    desc_ring: PrbDescRing,

    /// Text data ring metadata
    text_ring: TextDataRing,

    /// Current descriptor ID being processed
    current_id: u64,

    /// Number of descriptors processed so far
    iteration_count: u64,
}

impl<'a> DmesgEntryIterator<'a> {
    /// Creates a new DmesgEntryIterator
    fn new(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        kernel_type_info: &'a TypeInformation,
        desc_ring: PrbDescRing,
        text_ring: TextDataRing,
    ) -> Self {
        let current_id = desc_ring.tail_id;

        Self {
            memory_dump,
            architecture,
            kernel_type_info,
            desc_ring,
            text_ring,
            current_id,
            iteration_count: 0,
        }
    }
}

impl<'a> Iterator for DmesgEntryIterator<'a> {
    type Item = Result<DmesgEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        loop {
            if self.current_id == self.desc_ring.head_id
                || self.iteration_count >= self.desc_ring.count
            {
                return None;
            }

            let index = self.current_id % self.desc_ring.count;
            self.iteration_count += 1;

            let desc_vaddr =
                self.desc_ring.descs_array_vaddr + (index * self.desc_ring.prb_desc_size);

            let desc = match VirtualStruct::from_name(
                &vmem_reader,
                self.kernel_type_info,
                "prb_desc",
                &desc_vaddr,
            ) {
                Ok(desc) => desc,

                Err(err) => {
                    debug!("Failed to read descriptor at index {index}: {err:?}");
                    self.current_id = self.current_id.wrapping_add(1);

                    continue;
                }
            };

            let state_var = match desc.traverse("state_var").and_then(|f| f.read_u64()) {
                Ok(v) => v,

                Err(err) => {
                    debug!("Failed to read state_var at index {index}: {err:?}");
                    self.current_id = self.current_id.wrapping_add(1);

                    continue;
                }
            };

            let state = (state_var >> PRB_DESC_FLAGS_SHIFT) & PRB_DESC_STATE_MASK;
            let desc_id = state_var & PRB_DESC_ID_MASK;

            let expected_id = self.current_id;
            self.current_id = self.current_id.wrapping_add(1);

            // Each descriptor stores its own ID, so if the buffer wrapped around
            // and overwrote old entries, desc_id won't match expected_id
            if desc_id != expected_id {
                continue;
            }

            // Only process finalized or committed descriptors
            if state != PRB_DESC_FINALIZED && state != PRB_DESC_COMMITTED {
                continue;
            }

            let info_vaddr =
                self.desc_ring.infos_array_vaddr + (index * self.desc_ring.printk_info_size);

            let info = match VirtualStruct::from_name(
                &vmem_reader,
                self.kernel_type_info,
                "printk_info",
                &info_vaddr,
            ) {
                Ok(info) => info,

                Err(err) => {
                    debug!("Failed to read printk_info at index {index}: {err:?}");
                    continue;
                }
            };

            let sequence = match info.traverse("seq").and_then(|f| f.read_u64()) {
                Ok(sequence) => sequence,

                Err(err) => {
                    debug!("Failed to read seq at index {index}: {err:?}");
                    continue;
                }
            };

            let timestamp_ns = match info.traverse("ts_nsec").and_then(|f| f.read_u64()) {
                Ok(timestamp) => timestamp,

                Err(err) => {
                    debug!("Failed to read ts_nsec at index {index}: {err:?}");
                    continue;
                }
            };

            let text_len = match info.traverse("text_len").and_then(|f| f.read_u16()) {
                Ok(length) => length as usize,

                Err(err) => {
                    debug!("Failed to read text_len at index {index}: {err:?}");
                    continue;
                }
            };

            let facility = match info.traverse("facility").and_then(|f| f.read_u8()) {
                Ok(facility) => facility,

                Err(err) => {
                    debug!("Failed to read facility at index {index}: {err:?}");
                    continue;
                }
            };

            //
            // btfparse parses bitfields and returns an Offset::BitOffsetAndSize(bit_offset, bit_size),
            // but VirtualStruct::traverse() only accepts Offset::ByteOffset and explicitly rejects anything
            // else. As a workaround, we traverse to the last regular field (facility), get its address,
            // then manually offset by 1 byte to read the bitfield byte.
            //
            // Here's the layout from kernel 6.8.0:
            //
            // struct printk_info {
            //     u64 seq;
            //     u64 ts_nsec;
            //     u16 text_len;
            //     u8 facility;
            //     u8 flags: 5;
            //     u8 level: 3;
            //     u32 caller_id;
            //     struct dev_printk_info dev_info;
            // };
            //

            let flags_level_vaddr = match info.traverse("facility") {
                Ok(field) => field.virtual_address() + 1u64,

                Err(err) => {
                    debug!("Failed to traverse to facility at index {index}: {err:?}");
                    continue;
                }
            };

            let mut flags_level_byte = [0u8; 1];
            if let Err(err) = vmem_reader.read(&mut flags_level_byte, flags_level_vaddr) {
                debug!("Failed to read flags_level_byte at index {index}: {err:?}");
                continue;
            }

            let level = (flags_level_byte[0] >> 5) & 0x7;

            let caller_id = match info.traverse("caller_id").and_then(|f| f.read_u32()) {
                Ok(v) => v,

                Err(err) => {
                    debug!("Failed to read caller_id at index {index}: {err:?}");
                    continue;
                }
            };

            let text_blk_lpos = match desc.traverse("text_blk_lpos") {
                Ok(text_blk_lpos) => text_blk_lpos,

                Err(err) => {
                    debug!("Failed to traverse to text_blk_lpos at index {index}: {err:?}");
                    continue;
                }
            };

            let text_begin = match text_blk_lpos.traverse("begin").and_then(|f| f.read_u64()) {
                Ok(text_begin) => text_begin,

                Err(err) => {
                    debug!("Failed to read text_begin at index {index}: {err:?}");
                    continue;
                }
            };

            if text_begin == PRB_FAILED_LPOS || text_begin == PRB_EMPTY_LINE_LPOS {
                continue;
            }

            // Read the text data, skipping the ID prefix
            let text_pos = text_begin % self.text_ring.size;
            let text_vaddr = self.text_ring.virtual_address + text_pos + 8u64;
            let mut text_buffer = vec![0u8; text_len];

            let message = match vmem_reader.read(&mut text_buffer, text_vaddr) {
                Ok(bytes_read) => {
                    if bytes_read == text_len {
                        let msg = String::from_utf8_lossy(&text_buffer).to_string();

                        if !is_valid_text(&msg, 1) {
                            debug!(
                                "Invalid/corrupted message text at index {index}: not enough printable characters"
                            );
                            continue;
                        }

                        msg
                    } else {
                        debug!(
                            "Partial read of message text at index {index}: expected {text_len} bytes, got {bytes_read}"
                        );
                        continue;
                    }
                }

                Err(err) => {
                    debug!("Failed to read message text at index {index}: {err:?}");
                    continue;
                }
            };

            return Some(Ok(DmesgEntry {
                data_source: DmesgDataSource::PrintkRingbuffer,
                timestamp_ns,
                level,
                facility,
                sequence,
                message,
                caller_id: if caller_id != 0 {
                    Some(caller_id)
                } else {
                    None
                },
            }));
        }
    }
}

impl LinuxOperatingSystem {
    /// Returns an iterator over kernel log messages (dmesg) from the printk_ringbuffer
    pub(super) fn iter_dmesg_entries_impl(&self) -> Result<DmesgEntryIterator<'_>> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })?;

        let prb_ptr_vaddr = match kallsyms.get("prb") {
            Some(vaddr) => {
                VirtualAddress::new(self.init_task_vaddr.root_page_table(), vaddr.value())
            }

            None => {
                return Err(Error::new(
                    ErrorKind::EntityNotFound,
                    "Failed to find 'prb' symbol in kallsyms - printk ringbuffer not available",
                ));
            }
        };

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let prb_vaddr = vmem_reader.read_vaddr(prb_ptr_vaddr)?;

        let prb = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "printk_ringbuffer",
            &prb_vaddr,
        )?;

        let desc_ring = prb.traverse("desc_ring")?;

        let count_bits = desc_ring.traverse("count_bits")?.read_u32()? as u64;
        let descriptor_count = 1u64 << count_bits;

        let descs_array_vaddr = desc_ring.traverse("descs")?.read_vaddr()?;
        let infos_array_vaddr = desc_ring.traverse("infos")?.read_vaddr()?;

        let tail_id = desc_ring.traverse("tail_id")?.read_u64()?;
        let head_id = desc_ring.traverse("head_id")?.read_u64()?;

        let text_data_ring = prb.traverse("text_data_ring")?;
        let text_size_bits = text_data_ring.traverse("size_bits")?.read_u32()? as u64;
        let text_data_ptr = text_data_ring.traverse("data")?.read_vaddr()?;
        let text_data_size = 1u64 << text_size_bits;

        let prb_desc_tid = self.kernel_type_info.id_of("prb_desc").ok_or_else(|| {
            Error::new(
                ErrorKind::TypeInformationError,
                "Failed to find prb_desc type",
            )
        })?;

        let printk_info_tid = self.kernel_type_info.id_of("printk_info").ok_or_else(|| {
            Error::new(
                ErrorKind::TypeInformationError,
                "Failed to find printk_info type",
            )
        })?;

        let prb_desc_size = self.kernel_type_info.size_of(prb_desc_tid)? as u64;
        let printk_info_size = self.kernel_type_info.size_of(printk_info_tid)? as u64;

        let desc_ring = PrbDescRing {
            descs_array_vaddr,
            infos_array_vaddr,
            count: descriptor_count,
            prb_desc_size,
            printk_info_size,
            tail_id,
            head_id,
        };

        let text_ring = TextDataRing {
            virtual_address: text_data_ptr,
            size: text_data_size,
        };

        Ok(DmesgEntryIterator::new(
            self.memory_dump.clone(),
            self.architecture.clone(),
            &self.kernel_type_info,
            desc_ring,
            text_ring,
        ))
    }
}
