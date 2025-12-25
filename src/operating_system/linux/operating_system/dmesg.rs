//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::virtual_address::VirtualAddress,
    operating_system::linux::{
        entities::dmesg::{DmesgDataSource, DmesgEntry},
        operating_system::{syslog_file::is_valid_text, LinuxOperatingSystem},
        virtual_struct::VirtualStruct,
    },
};

use log::debug;

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

impl LinuxOperatingSystem {
    /// Returns kernel log messages (dmesg) from the printk_ringbuffer
    pub(super) fn get_dmesg_entries_impl(&self) -> Result<Vec<DmesgEntry>> {
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

        debug!("Found 'prb' symbol at {:?}", prb_ptr_vaddr);

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());
        let prb_vaddr = vmem_reader.read_vaddr(prb_ptr_vaddr)?;

        debug!("Dereferenced 'prb' pointer to {:?}", prb_vaddr);

        let prb = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "printk_ringbuffer",
            &prb_vaddr,
        )?;

        let desc_ring = prb.traverse("desc_ring")?;

        let count_bits = desc_ring.traverse("count_bits")?.read_u32()? as u64;
        let descriptor_count = 1u64 << count_bits;

        debug!(
            "Descriptor ring has {} entries (count_bits={})",
            descriptor_count, count_bits
        );

        let descs_ptr = desc_ring.traverse("descs")?.read_vaddr()?;
        let infos_ptr = desc_ring.traverse("infos")?.read_vaddr()?;

        let tail_id = desc_ring.traverse("tail_id")?.read_u64()?;
        let head_id = desc_ring.traverse("head_id")?.read_u64()?;

        debug!("Descriptor ring: tail_id={}, head_id={}", tail_id, head_id);

        let text_data_ring = prb.traverse("text_data_ring")?;
        let text_size_bits = text_data_ring.traverse("size_bits")?.read_u32()? as u64;
        let text_data_ptr = text_data_ring.traverse("data")?.read_vaddr()?;
        let text_data_size = 1u64 << text_size_bits;

        debug!(
            "Text data ring: size={} bytes (size_bits={})",
            text_data_size, text_size_bits
        );

        let mut entries = Vec::new();

        let mut current_id = tail_id;
        let mut iteration_count = 0;

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

        let desc_size = self.kernel_type_info.size_of(prb_desc_tid)? as u64;
        let info_size = self.kernel_type_info.size_of(printk_info_tid)? as u64;

        while current_id != head_id && iteration_count < descriptor_count {
            let index = current_id % descriptor_count;
            iteration_count += 1;

            let desc_vaddr = descs_ptr + (index * desc_size);
            let desc = match VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
                "prb_desc",
                &desc_vaddr,
            ) {
                Ok(desc) => desc,
                Err(err) => {
                    debug!("Failed to read descriptor at index {index}: {err:?}");
                    current_id = current_id.wrapping_add(1);
                    continue;
                }
            };

            let state_var = match desc.traverse("state_var").and_then(|f| f.read_u64()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read state_var at index {index}: {err:?}");
                    current_id = current_id.wrapping_add(1);
                    continue;
                }
            };

            let state = (state_var >> PRB_DESC_FLAGS_SHIFT) & PRB_DESC_STATE_MASK;
            let desc_id = state_var & PRB_DESC_ID_MASK;

            let expected_id = current_id;
            current_id = current_id.wrapping_add(1);

            // Each descriptor stores its own ID, so if the buffer wrapped around
            // and overwrote old entries, desc_id won't match expected_id
            if desc_id != expected_id {
                continue;
            }

            // Only process finalized or committed descriptors
            if state != PRB_DESC_FINALIZED && state != PRB_DESC_COMMITTED {
                continue;
            }

            let info_vaddr = infos_ptr + (index * info_size);
            let info = match VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
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
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read seq at index {index}: {err:?}");
                    continue;
                }
            };

            let timestamp_ns = match info.traverse("ts_nsec").and_then(|f| f.read_u64()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read ts_nsec at index {index}: {err:?}");
                    continue;
                }
            };

            let text_len = match info.traverse("text_len").and_then(|f| f.read_u16()) {
                Ok(v) => v as usize,
                Err(err) => {
                    debug!("Failed to read text_len at index {index}: {err:?}");
                    continue;
                }
            };

            let facility = match info.traverse("facility").and_then(|f| f.read_u8()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read facility at index {index}: {err:?}");
                    continue;
                }
            };

            //
            // btfparse can parse bitfields and returns an Offset::BitOffsetAndSize(bit_offset, bit_size),
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

            let facility_field = match info.traverse("facility") {
                Ok(f) => f,
                Err(err) => {
                    debug!("Failed to traverse to facility at index {index}: {err:?}");
                    continue;
                }
            };

            let flags_level_vaddr = facility_field.virtual_address() + 1u64;

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
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to traverse to text_blk_lpos at index {index}: {err:?}");
                    continue;
                }
            };

            let text_begin = match text_blk_lpos.traverse("begin").and_then(|f| f.read_u64()) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to read text_begin at index {index}: {err:?}");
                    continue;
                }
            };

            if text_begin == PRB_FAILED_LPOS || text_begin == PRB_EMPTY_LINE_LPOS {
                continue;
            }

            // Read the text data, skipping the ID prefix
            let text_pos = text_begin % text_data_size;
            let text_vaddr = text_data_ptr + text_pos + 8u64;
            let mut text_buffer = vec![0u8; text_len];

            let message = match vmem_reader.read(&mut text_buffer, text_vaddr) {
                Ok(bytes_read) => {
                    if bytes_read == text_len {
                        let msg = String::from_utf8_lossy(&text_buffer).to_string();

                        if !is_valid_text(&msg, 1) {
                            debug!("Invalid/corrupted message text at index {index}: not enough printable characters");
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

            entries.push(DmesgEntry {
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
            });
        }

        Ok(entries)
    }
}
