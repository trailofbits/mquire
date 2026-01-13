//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{architecture::Architecture, error::Result, virtual_memory_reader::VirtualMemoryReader},
    memory::{primitives::RawVirtualAddress, readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        entities::memory_mapping::{FileBacking, MemoryMapping, MemoryProtection},
        maple_tree::{MapleTree, MapleTreeEntry, MapleTreeValue},
        operating_system::LinuxOperatingSystem,
        virtual_struct::VirtualStruct,
    },
    try_chain,
};

use {btfparse::TypeInformation, log::debug, std::sync::Arc};

use std::{ops::Range, path::PathBuf};

// VM flag constants
const VM_READ: u64 = 0x00000001;
const VM_WRITE: u64 = 0x00000002;
const VM_EXEC: u64 = 0x00000004;
const VM_SHARED: u64 = 0x00000008;

/// File backing information
#[derive(Debug, Clone, Copy)]
struct VmAreaStructBackingFile {
    /// File virtual address
    pub file: VirtualAddress,

    /// Page offset within the file (in PAGE_SIZE units)
    pub offset: u64,
}

/// A representation of a vm_area_struct object
#[derive(Debug, Clone)]
struct VmAreaStruct {
    /// Virtual address of the vm_area_struct
    pub virtual_address: VirtualAddress,

    /// Memory region
    pub region: Range<u64>,

    /// VMA flags
    pub flags: u64,

    /// Backing file information
    pub backing_file: Option<VmAreaStructBackingFile>,
}

impl MapleTreeValue for VmAreaStruct {
    fn from_vaddr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<Self> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let vm_area_struct = VirtualStruct::from_name(
            &vmem_reader,
            type_information,
            "vm_area_struct",
            &virtual_address,
        )?;

        let start = vm_area_struct.traverse("vm_start")?.read_u64()?;
        let end = vm_area_struct.traverse("vm_end")?.read_u64()?;
        let flags = vm_area_struct.traverse("vm_flags")?.read_u64()?;
        let offset = vm_area_struct.traverse("vm_pgoff")?.read_u64()?;

        let file = vm_area_struct.traverse("vm_file")?.read_vaddr()?;
        let backing_file = if file.is_null() {
            None
        } else {
            Some(VmAreaStructBackingFile { file, offset })
        };

        Ok(VmAreaStruct {
            virtual_address,
            region: Range { start, end },
            flags,
            backing_file,
        })
    }
}

/// Iterator over memory mappings for a single task
pub struct MemoryMappingIterator<'a> {
    /// The memory dump
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel debug symbols
    kernel_type_info: &'a TypeInformation,

    /// The task virtual address
    task_vaddr: VirtualAddress,

    /// The task's page table
    task_page_table: VirtualAddress,

    /// The maple tree entries iterator
    entries: std::vec::IntoIter<MapleTreeEntry<VmAreaStruct>>,
}

impl Iterator for MemoryMappingIterator<'_> {
    type Item = Result<MemoryMapping>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.next()?;
        let vma_info = &entry.value;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let shared = vma_info.flags & VM_SHARED != 0;

        let protection = MemoryProtection::new(
            vma_info.flags & VM_READ != 0,
            vma_info.flags & VM_WRITE != 0,
            vma_info.flags & VM_EXEC != 0,
        );

        let file_backing = if let Some(backing_file) = vma_info.backing_file {
            VirtualStruct::from_name(
                &vmem_reader,
                self.kernel_type_info,
                "file",
                &backing_file.file,
            )
            .inspect_err(|err| debug!("{err:?}"))
            .ok()
            .and_then(|file| {
                let f_path_vaddr = match file.traverse("f_path") {
                    Ok(f_path) => f_path.virtual_address(),

                    Err(err) => {
                        debug!("{err:?}");
                        return None;
                    }
                };

                LinuxOperatingSystem::read_path(
                    self.memory_dump.as_ref(),
                    self.architecture.as_ref(),
                    self.kernel_type_info,
                    f_path_vaddr,
                )
                .map(|path| FileBacking {
                    path: PathBuf::from(path),
                    offset: backing_file.offset,
                })
                .inspect_err(|err| debug!("{err:?}"))
                .ok()
            })
        } else {
            None
        };

        let vm_start = VirtualAddress::new(
            self.task_page_table.root_page_table(),
            RawVirtualAddress::new(vma_info.region.start),
        );

        let vm_end = VirtualAddress::new(
            self.task_page_table.root_page_table(),
            RawVirtualAddress::new(vma_info.region.end),
        );

        Some(Ok(MemoryMapping {
            task: self.task_vaddr,
            virtual_address: vma_info.virtual_address,
            region: vm_start..vm_end,
            protection,
            shared,
            file_backing,
        }))
    }
}

impl LinuxOperatingSystem {
    /// Returns an iterator over memory mappings for a single task
    pub(super) fn iter_task_memory_mappings_impl(
        &self,
        task_vaddr: VirtualAddress,
    ) -> Result<MemoryMappingIterator<'_>> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let task_struct = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "task_struct",
            &task_vaddr,
        )?;

        let mm_vaddr = try_chain!(task_struct.traverse("mm")?.read_vaddr())?;

        let mm_mt = try_chain!(task_struct.traverse("mm")?.dereference()?.traverse("mm_mt"))?;

        let maple_tree = MapleTree::<VmAreaStruct>::new(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            &self.kernel_type_info,
            mm_mt.virtual_address(),
        )?;

        Ok(MemoryMappingIterator {
            memory_dump: self.memory_dump.clone(),
            architecture: self.architecture.clone(),
            kernel_type_info: &self.kernel_type_info,
            task_vaddr,
            task_page_table: mm_vaddr,
            entries: maple_tree.into_entries().into_iter(),
        })
    }
}
