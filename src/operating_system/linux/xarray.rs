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
    operating_system::linux::virtual_struct::VirtualStruct,
};

use {
    btfparse::{TypeInformation, TypeVariant},
    log::debug,
};

/// XArray chunk size constant
const XA_CHUNK_SIZE: u64 = 64;

/// Represents the contents of an XArray.
pub struct XArray {
    /// A flat list of all the entries in the XArray
    entry_list: Vec<VirtualAddress>,
}

impl XArray {
    /// Creates a new `XArray` parser instance
    pub fn new(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<Self> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let x_array =
            VirtualStruct::from_name(&vmem_reader, type_information, "xarray", &virtual_address)?;

        let xa_head_vaddr = x_array.traverse("xa_head")?.read_vaddr()?;
        if xa_head_vaddr.is_null() {
            return Ok(Self {
                entry_list: Vec::new(),
            });
        }

        let mut entry_list = Vec::new();

        if Self::is_xa_node(xa_head_vaddr) {
            let xa_node = VirtualStruct::from_name(
                &vmem_reader,
                type_information,
                "xa_node",
                &Self::to_xa_node(xa_head_vaddr),
            )?;

            let xa_chunk_size = Self::get_xa_chunk_size(type_information)?;
            for i in 0..xa_chunk_size {
                let slot = xa_node.traverse(&format!("slots[{i}]"))?.read_vaddr()?;
                Self::collect_xa_node_children(
                    &vmem_reader,
                    type_information,
                    &xa_node,
                    slot,
                    &mut entry_list,
                )?;
            }
        } else if !Self::is_xa_value(xa_head_vaddr) && !Self::is_xa_internal_node(xa_head_vaddr) {
            entry_list.push(xa_head_vaddr);
        }

        Ok(Self { entry_list })
    }

    /// Returns the list of entries in the XArray
    pub fn entries(&self) -> &[VirtualAddress] {
        &self.entry_list
    }

    /// Gets the number of slots in a xa_node
    fn get_xa_chunk_size(type_information: &TypeInformation) -> Result<u32> {
        let tid = type_information
            .id_of("xa_node")
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "Failed to acquire the type definition of `struct xa_node`",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let struct_type_var = type_information
            .from_id(tid)
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                &format!(
                    "Failed to acquire the type information for `struct xa_node` from tid {tid}"
                ),
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let struct_type = match struct_type_var {
            TypeVariant::Struct(struct_type) => struct_type,

            _ => {
                let err = Error::new(
                    ErrorKind::TypeInformationError,
                    &format!(
                        "Failed to acquire the type information for `struct xa_node` from tid {tid}"
                    ),
                );

                debug!("{err:?}");
                return Err(err);
            }
        };

        let member_tid = struct_type
            .member_list()
            .iter()
            .find(|member| member.name().map(|name| name == "slots").unwrap_or(false))
            .map(|member| member.tid())
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "No field `slots` found inside the `xa_node` structure",
            ))?;

        let member_type_var = type_information.from_id(member_tid).ok_or(Error::new(
            ErrorKind::TypeInformationError,
            &format!("Type ID {member_tid} for member `xa_node::slots` was not found"),
        ))?;

        match member_type_var {
            TypeVariant::Array(array_type) => Ok(*array_type.element_count()),

            _ => Err(Error::new(
                ErrorKind::TypeInformationError,
                "Not an array: `xa_node::slots`",
            )),
        }
    }

    /// Recursively collects all page/folio entries from an XArray internal node
    fn collect_xa_node_children(
        vmem_reader: &VirtualMemoryReader,
        type_information: &TypeInformation,
        xa_node: &VirtualStruct,
        entry_vaddr: VirtualAddress,
        data_node_list: &mut Vec<VirtualAddress>,
    ) -> Result<()> {
        if entry_vaddr.is_null() {
            return Ok(());
        }

        // Handle sibling entries by following them to the actual entry
        let mut entry = entry_vaddr;
        while Self::is_xa_sibling(entry) {
            let sibling_offset = Self::xa_to_sibling(entry);
            entry = xa_node
                .traverse(&format!("slots[{sibling_offset}]"))?
                .read_vaddr()?;
        }

        if Self::is_xa_node(entry) {
            // Internal node - recursively traverse its slots
            let child_node = VirtualStruct::from_name(
                vmem_reader,
                type_information,
                "xa_node",
                &Self::to_xa_node(entry),
            )?;

            let xa_chunk_size = Self::get_xa_chunk_size(type_information)?;
            for i in 0..xa_chunk_size {
                let slot = child_node.traverse(&format!("slots[{i}]"))?.read_vaddr()?;
                Self::collect_xa_node_children(
                    vmem_reader,
                    type_information,
                    &child_node,
                    slot,
                    data_node_list,
                )?;
            }
        } else if !Self::is_xa_value(entry) && !Self::is_xa_internal_node(entry) {
            // Regular pointer entry (page/folio)
            data_node_list.push(entry);
        }

        // Skip value entries and other internal entries
        Ok(())
    }

    /// Converts an XArray internal node pointer to the actual xa_node address
    /// Internal nodes have the bottom 2 bits set to 0b10, so we subtract 2
    fn to_xa_node(vaddr: VirtualAddress) -> VirtualAddress {
        vaddr - 2u32
    }

    /// Checks if an entry is an internal entry (bottom 2 bits = 0b10)
    fn is_xa_internal_node(vaddr: VirtualAddress) -> bool {
        vaddr.value().value() & 3 == 2
    }

    /// Checks if an entry is a node pointer (internal entry with address > 4096)
    fn is_xa_node(vaddr: VirtualAddress) -> bool {
        Self::is_xa_internal_node(vaddr) && vaddr.value().value() > 4096
    }

    /// Checks if an entry is a value entry (bottom bit = 1)
    fn is_xa_value(vaddr: VirtualAddress) -> bool {
        vaddr.value().value() & 1 != 0
    }

    /// Extracts the internal value from an XArray internal entry
    fn xa_to_internal(vaddr: VirtualAddress) -> u64 {
        vaddr.value().value() >> 2
    }

    /// Converts a sibling entry to its slot offset
    fn xa_to_sibling(vaddr: VirtualAddress) -> u32 {
        Self::xa_to_internal(vaddr) as u32
    }

    /// Checks if an entry is a sibling entry (internal entry with value 0-63)
    /// Sibling entries are used for multi-index entries spanning multiple slots
    fn is_xa_sibling(vaddr: VirtualAddress) -> bool {
        Self::is_xa_internal_node(vaddr) && vaddr.value().value() < ((XA_CHUNK_SIZE << 2) | 2)
    }
}
