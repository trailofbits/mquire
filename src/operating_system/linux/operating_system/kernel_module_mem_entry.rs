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
        entities::kernel_module_mem_entry::{KernelModuleMemEntry, KernelModuleMemType},
        operating_system::LinuxOperatingSystem,
        virtual_struct::VirtualStruct,
    },
};

use {
    btfparse::{TypeInformation, TypeVariant},
    log::{debug, warn},
};

/// Iterator over a kernel module's `mem[]` entries
pub struct KernelModuleMemEntryIterator {
    /// The materialized regions
    inner: std::vec::IntoIter<Result<KernelModuleMemEntry>>,

    /// The address of the module these regions belong to
    module_vaddr: VirtualAddress,
}

impl KernelModuleMemEntryIterator {
    /// Creates a new KernelModuleMemEntryIterator
    fn new(
        inner: std::vec::IntoIter<Result<KernelModuleMemEntry>>,
        module_vaddr: VirtualAddress,
    ) -> Self {
        Self {
            inner,
            module_vaddr,
        }
    }

    /// Returns the address of the module whose regions are being iterated
    pub fn module_vaddr(&self) -> VirtualAddress {
        self.module_vaddr
    }
}

impl Iterator for KernelModuleMemEntryIterator {
    type Item = Result<KernelModuleMemEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl LinuxOperatingSystem {
    /// Returns an iterator over the memory regions of the kernel module at the
    /// given address
    pub(super) fn iter_kernel_module_mem_entries_impl(
        &self,
        module_vaddr: VirtualAddress,
    ) -> Result<KernelModuleMemEntryIterator> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let module_struct = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "module",
            &module_vaddr,
        )?;

        let regions =
            parse_module_mem_entries(&vmem_reader, &self.kernel_type_info, &module_struct)?;

        let results: Vec<Result<KernelModuleMemEntry>> = regions.into_iter().map(Ok).collect();

        Ok(KernelModuleMemEntryIterator::new(
            results.into_iter(),
            module_vaddr,
        ))
    }
}

/// Parses the memory regions for the `struct module` at the given virtual address
fn parse_module_mem_entries(
    vmem_reader: &VirtualMemoryReader,
    type_information: &TypeInformation,
    module_struct: &VirtualStruct,
) -> Result<Vec<KernelModuleMemEntry>> {
    if !module_struct.has_field("mem") {
        warn!("The 'module::mem' field is missing, skipping memory regions");
        return Ok(Vec::new());
    }

    let mem_array = module_struct.traverse("mem")?;
    let mem_array_vaddr = mem_array.virtual_address();

    // The `mem[]` array should be made of `struct module_memory` entries, but do not
    // hardcode the type
    let (element_tid, region_count) = match type_information.from_id(mem_array.tid()) {
        Some(TypeVariant::Array(array)) => (*array.element_tid(), *array.element_count() as usize),

        _ => {
            return Err(Error::new(
                ErrorKind::TypeInformationError,
                "`module::mem` is not an array type",
            ));
        }
    };

    let mem_array_elem_size = type_information.size_of(element_tid)? as u64;

    let mut regions = Vec::new();

    for index in 0..region_count {
        let mem_type = match module_mem_type_from_index(index) {
            Some(mem_type) => mem_type,

            None => {
                warn!(
                    "module mem[] entry {index} of {region_count} has no known mem_type \
                     mapping; returning partial regions"
                );

                break;
            }
        };

        let region_vaddr = mem_array_vaddr + (index as u64 * mem_array_elem_size);

        let region_struct =
            match VirtualStruct::from_id(vmem_reader, type_information, element_tid, &region_vaddr)
            {
                Ok(region_struct) => region_struct,

                Err(err) => {
                    debug!("Failed to read mem[] region at {region_vaddr}: {err:?}");
                    continue;
                }
            };

        let base = match region_struct.traverse("base").and_then(|f| f.read_vaddr()) {
            Ok(base) => base,

            Err(err) => {
                debug!("Failed to read module_memory.base at {region_vaddr}: {err:?}");
                continue;
            }
        };

        let size = region_struct
            .traverse("size")
            .and_then(|f| f.read_u32())
            .unwrap_or(0);

        regions.push(KernelModuleMemEntry {
            mem_type,
            base,
            size,
        });
    }

    Ok(regions)
}

/// Maps a `mem[]` index to its `mod_mem_type` (kernels >= 6.4).
fn module_mem_type_from_index(index: usize) -> Option<KernelModuleMemType> {
    match index {
        0 => Some(KernelModuleMemType::Text),
        1 => Some(KernelModuleMemType::Data),
        2 => Some(KernelModuleMemType::RoData),
        3 => Some(KernelModuleMemType::RoAfterInit),
        4 => Some(KernelModuleMemType::InitText),
        5 => Some(KernelModuleMemType::InitData),
        6 => Some(KernelModuleMemType::InitRoData),
        _ => None,
    }
}
