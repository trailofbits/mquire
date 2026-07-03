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
        entities::ftrace_ops::FtraceOps, kallsyms::Kallsyms,
        operating_system::LinuxOperatingSystem, virtual_struct::VirtualStruct,
    },
};

use {btfparse::TypeInformation, log::debug, std::collections::HashSet};

/// Upper bound on the number of nodes we will walk
const MAX_FTRACE_OPS: usize = 8192;

/// Iterator over registered ftrace callbacks (`struct ftrace_ops`).
pub struct FtraceOpsIterator {
    /// The materialized results
    inner: std::vec::IntoIter<Result<FtraceOps>>,

    /// The address of the first node the walk started from
    start_vaddr: VirtualAddress,
}

impl FtraceOpsIterator {
    /// Creates a new FtraceOpsIterator
    fn new(inner: std::vec::IntoIter<Result<FtraceOps>>, start_vaddr: VirtualAddress) -> Self {
        Self { inner, start_vaddr }
    }

    /// Returns the virtual address of the first node the walk started from
    pub fn start_vaddr(&self) -> VirtualAddress {
        self.start_vaddr
    }
}

impl Iterator for FtraceOpsIterator {
    type Item = Result<FtraceOps>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl LinuxOperatingSystem {
    /// Returns the registered ftrace callback read from the `struct ftrace_ops`
    /// at the given virtual address.
    pub(super) fn ftrace_ops_at_impl(&self, vaddr: VirtualAddress) -> Result<FtraceOps> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        Self::parse_ftrace_ops(&vmem_reader, &self.kernel_type_info, vaddr)
    }

    /// Returns an iterator over the whole `ftrace_ops` list, resolving both the
    /// head (`*ftrace_ops_list`) and the terminating `ftrace_list_end` sentinel
    /// from kallsyms
    pub(super) fn iter_ftrace_ops_impl(&self) -> Result<FtraceOpsIterator> {
        let kallsyms = self.require_kallsyms()?;
        let list_ptr_vaddr = kallsyms.get("ftrace_ops_list").ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate 'ftrace_ops_list' symbol in kallsyms",
            )
        })?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let start_vaddr = vmem_reader.read_vaddr(list_ptr_vaddr).inspect_err(|err| {
            debug!("iter_ftrace_ops_impl: failed to deref ftrace_ops_list: {err:?}")
        })?;

        let end_vaddr = kallsyms.get("ftrace_list_end");
        self.iter_ftrace_ops_from_impl(start_vaddr, end_vaddr)
    }

    /// Returns an iterator over the `ftrace_ops` list starting from the node at
    /// `start_vaddr`, stopping when it reaches either a null pointer or `end_vaddr`
    pub(super) fn iter_ftrace_ops_from_impl(
        &self,
        start_vaddr: VirtualAddress,
        end_vaddr: Option<VirtualAddress>,
    ) -> Result<FtraceOpsIterator> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        if matches!(end_vaddr, Some(end) if end.root_page_table() != start_vaddr.root_page_table())
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "iter_ftrace_ops_from: start and end addresses are in different root page tables",
            ));
        }

        let mut visited_addr_list: HashSet<u64> = HashSet::new();

        let mut current_vaddr = start_vaddr;
        let mut results: Vec<Result<FtraceOps>> = Vec::new();

        while !current_vaddr.is_null() {
            if Some(current_vaddr) == end_vaddr {
                break;
            }

            let current_raw_vaddr = current_vaddr.value();
            if !visited_addr_list.insert(current_raw_vaddr.value()) {
                debug!("iter_ftrace_ops_from_impl: loop detected, stopping at {current_vaddr}");
                break;
            }

            if visited_addr_list.len() > MAX_FTRACE_OPS {
                debug!(
                    "iter_ftrace_ops_from_impl: reached the max amount of nodes, stopping at {current_vaddr}"
                );

                break;
            }

            let ftrace_ops = match VirtualStruct::from_name(
                &vmem_reader,
                &self.kernel_type_info,
                "ftrace_ops",
                &current_vaddr,
            ) {
                Ok(s) => s,
                Err(err) => {
                    debug!(
                        "iter_ftrace_ops_from_impl: failed to read ftrace_ops at {current_vaddr}: {err:?}"
                    );
                    results.push(Err(err));
                    break;
                }
            };

            let next_vaddr = ftrace_ops
                .traverse("next")
                .and_then(|f| f.read_vaddr())
                .inspect_err(|err| {
                    debug!(
                        "iter_ftrace_ops_from_impl: failed to read next at {current_vaddr}: {err:?}"
                    )
                });

            results.push(Self::parse_ftrace_ops(
                &vmem_reader,
                &self.kernel_type_info,
                current_vaddr,
            ));

            if let Ok(n) = next_vaddr {
                current_vaddr = n;
            } else {
                break;
            }
        }

        Ok(FtraceOpsIterator::new(results.into_iter(), start_vaddr))
    }

    /// Reads a single `struct ftrace_ops` object
    fn parse_ftrace_ops(
        vmem_reader: &VirtualMemoryReader,
        type_information: &TypeInformation,
        vaddr: VirtualAddress,
    ) -> Result<FtraceOps> {
        let ops_struct =
            VirtualStruct::from_name(vmem_reader, type_information, "ftrace_ops", &vaddr)?;

        let func = ops_struct
            .traverse("func")
            .and_then(|f| f.read_vaddr())
            .ok()
            .filter(|f| !f.is_null());

        let flags = ops_struct.traverse("flags").and_then(|f| f.read_u64()).ok();

        Ok(FtraceOps {
            virtual_address: vaddr,
            func,
            flags,
        })
    }

    /// Returns the initialized kallsyms or an error
    fn require_kallsyms(&self) -> Result<&Kallsyms> {
        self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })
    }
}
