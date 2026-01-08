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
    memory::{primitives::RawVirtualAddress, virtual_address::VirtualAddress},
    operating_system::linux::{
        utils::get_struct_member_byte_offset, virtual_struct::VirtualStruct,
    },
    try_chain,
};

use {btfparse::TypeInformation, log::debug};

use std::collections::{BTreeSet, VecDeque};

/// The base of the kernel virtual address space
const KERNEL_VIRTUAL_ADDRESS_BASE: u64 = 0xFFFF000000000000;

/// Default time to live for task discovery queue items
const TASK_DISCOVERY_QUEUE_ITEM_TTL: usize = 2;

/// Max pid value
const PID_MAX_LIMIT: u32 = 4 * 1024 * 1024;

/// Queue item for task struct discovery
#[derive(Clone)]
struct TaskDiscoveryQueueItem {
    vaddr: VirtualAddress,
    time_to_live: usize,
}

/// Iterator that yields VirtualStruct instances for related task_struct entries
pub struct TaskStructIterator<'a> {
    vmem_reader: &'a VirtualMemoryReader<'a>,
    kernel_type_info: &'a TypeInformation,
    visited_raw_vaddrs: BTreeSet<RawVirtualAddress>,
    next_vaddr_queue: VecDeque<TaskDiscoveryQueueItem>,
    current_vaddr_queue: VecDeque<TaskDiscoveryQueueItem>,
    sibling_offset: u64,
}

impl<'a> TaskStructIterator<'a> {
    /// Creates a new TaskStructIterator starting from the given task_struct address
    pub fn new(
        vmem_reader: &'a VirtualMemoryReader<'a>,
        kernel_type_info: &'a TypeInformation,
        task_struct: VirtualAddress,
    ) -> Result<Self> {
        let task_struct_tid = kernel_type_info.id_of("task_struct").ok_or_else(|| {
            Error::new(
                ErrorKind::TypeInformationError,
                "Failed to find task_struct type in kernel type information",
            )
        })?;

        let sibling_offset =
            get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "sibling")?;

        let mut current_vaddr_queue = VecDeque::new();
        current_vaddr_queue.push_back(TaskDiscoveryQueueItem {
            vaddr: task_struct,
            time_to_live: TASK_DISCOVERY_QUEUE_ITEM_TTL,
        });

        Ok(Self {
            vmem_reader,
            kernel_type_info,
            visited_raw_vaddrs: BTreeSet::new(),
            next_vaddr_queue: VecDeque::new(),
            current_vaddr_queue,
            sibling_offset,
        })
    }
}

impl<'a> Iterator for TaskStructIterator<'a> {
    type Item = VirtualStruct<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_vaddr_queue.is_empty() {
                if self.next_vaddr_queue.is_empty() {
                    return None;
                }

                std::mem::swap(&mut self.current_vaddr_queue, &mut self.next_vaddr_queue);
            }

            let queue_item = self.current_vaddr_queue.pop_front()?;

            let raw_vaddr = queue_item.vaddr.value();
            if raw_vaddr.value() < KERNEL_VIRTUAL_ADDRESS_BASE {
                continue;
            }

            if !self.visited_raw_vaddrs.insert(raw_vaddr) {
                continue;
            }

            let task_struct = match VirtualStruct::from_name(
                self.vmem_reader,
                self.kernel_type_info,
                "task_struct",
                &queue_item.vaddr,
            ) {
                Ok(ts) => ts,
                Err(err) => {
                    debug!(
                        "Failed to create VirtualStruct for task_struct at {:?}: {err:?}",
                        queue_item.vaddr
                    );

                    continue;
                }
            };

            let field_offset_map = [
                ("last_wakee", 0u64),
                ("real_parent", 0u64),
                ("parent", 0u64),
                ("group_leader", 0u64),
                ("pi_top_task", 0u64),
                ("oom_reaper_list", 0u64),
                ("children.prev", self.sibling_offset),
                ("children.next", self.sibling_offset),
                ("sibling.prev", self.sibling_offset),
                ("sibling.next", self.sibling_offset),
            ];

            let mut read_error = false;
            let mut valid_vaddr_list = Vec::new();
            let mut skipped_vaddr_count = 0;

            for (field_path, offset) in field_offset_map {
                match try_chain!(task_struct.traverse(field_path)?.read_vaddr()) {
                    Ok(pointer_vaddr) => {
                        let adjusted_vaddr = pointer_vaddr - offset;

                        let adjusted_raw_vaddr = adjusted_vaddr.value();
                        if adjusted_vaddr.is_null() || adjusted_vaddr == queue_item.vaddr {
                            skipped_vaddr_count += 1;
                        } else if adjusted_raw_vaddr.value() >= KERNEL_VIRTUAL_ADDRESS_BASE {
                            valid_vaddr_list.push(adjusted_vaddr);
                        }
                    }

                    Err(err) => {
                        read_error = true;

                        debug!(
                            "Failed to read task_struct::{field_path} from {:?}: {err:?}",
                            queue_item.vaddr
                        );

                        break;
                    }
                }
            }

            let tgid = match try_chain!(task_struct.traverse("tgid")?.read_u32()) {
                Ok(tgid) => tgid,

                Err(error) => {
                    read_error = true;

                    debug!(
                        "Failed to read task_struct::tgid from {:?}: {error:?}",
                        queue_item.vaddr
                    );

                    0
                }
            };

            let pid = match try_chain!(task_struct.traverse("pid")?.read_u32()) {
                Ok(pid) => pid,

                Err(error) => {
                    read_error = true;

                    debug!(
                        "Failed to read task_struct::pid from {:?}: {error:?}",
                        queue_item.vaddr
                    );

                    0
                }
            };

            if let Ok(mm_struct) = try_chain!(task_struct.traverse("mm")?.dereference()) {
                if !mm_struct.virtual_address().is_null() {
                    if let Ok(exe_file_vaddr) =
                        try_chain!(mm_struct.traverse("exe_file")?.read_vaddr())
                    {
                        if !exe_file_vaddr.is_null() {
                            read_error = try_chain!(
                                mm_struct
                                    .traverse("exe_file")?
                                    .dereference()?
                                    .traverse("f_path.dentry")?
                                    .read_u8()
                            )
                            .is_err();
                        }
                    } else {
                        read_error = true;
                    }
                }
            } else {
                read_error = true;
            }

            let has_invalid_fields = valid_vaddr_list.len() + skipped_vaddr_count
                < field_offset_map.len()
                || tgid > PID_MAX_LIMIT
                || pid > PID_MAX_LIMIT;

            let time_to_live = if read_error {
                0
            } else if has_invalid_fields {
                queue_item.time_to_live.saturating_sub(1)
            } else {
                queue_item.time_to_live
            };

            if time_to_live > 0 {
                self.next_vaddr_queue
                    .extend(
                        valid_vaddr_list
                            .iter()
                            .map(|&vaddr| TaskDiscoveryQueueItem {
                                vaddr,
                                time_to_live,
                            }),
                    );
            }

            return Some(task_struct);
        }
    }
}
