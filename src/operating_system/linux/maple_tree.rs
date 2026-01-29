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
    operating_system::linux::virtual_struct::VirtualStruct,
};

use {btfparse::TypeInformation, log::debug};

use std::ops::Range;

/// Dense maple tree node type
const MAPLE_TYPE_DENSE: u8 = 0;

/// Dense maple tree node type
const MAPLE_TYPE_LEAF_64: u8 = 1;

/// Dense maple tree node type
const MAPLE_TYPE_RANGE_64: u8 = 2;

/// Dense maple tree node type
const MAPLE_TYPE_ARANGE_64: u8 = 3;

/// Slot counts per type (64-bit architecture)
const MAPLE_NODE_SLOTS: usize = 31;

/// Pivot counts for dense nodes
const PIVOTS_DENSE: usize = 0;

/// Pivot counts for RANGE64 nodes (MAPLE_RANGE64_SLOTS - 1)
const PIVOTS_RANGE64: usize = 15;

/// Pivot counts for ARANGE64 nodes (MAPLE_ARANGE64_SLOTS - 1)
const PIVOTS_ARANGE64: usize = 9;

/// Shift count used to extract the node type from entry pointers
const MAPLE_NODE_TYPE_SHIFT: u64 = 0x03;

/// Bitmask used to extract the node type from entry pointers
const MAPLE_NODE_TYPE_MASK: u64 = 0x0F;

/// The bitmask used to mask off pointer tag data
const MAPLE_NODE_MASK: u64 = 0xFF;

/// The trait used to define a single MapleTree value
pub trait MapleTreeValue: Sized {
    fn from_vaddr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<Self>;
}

/// Represents a single entry in the Maple Tree, mapping a range of keys to a value.
pub struct MapleTreeEntry<T> {
    /// The range of keys covered by this entry.
    #[allow(unused)]
    pub key: Range<u64>,

    /// The value associated with the key range.
    pub value: T,
}

/// Represents the contents of a Maple Tree.
pub struct MapleTree<T: MapleTreeValue> {
    /// A flat list of all the entries in the tree
    entry_list: Vec<MapleTreeEntry<T>>,
}

/// Contains a mapping between a range and the virtual address of the associated value
struct MapleTreeEntryValuePointer {
    /// The range of keys covered by this entry.
    pub key: Range<u64>,

    /// The virtual address of the value associated with the key range.
    pub value: VirtualAddress,
}

impl<T> MapleTree<T>
where
    T: MapleTreeValue,
{
    /// Consumes the maple tree and returns the owned list of entries
    pub fn into_entries(self) -> Vec<MapleTreeEntry<T>> {
        self.entry_list
    }

    /// Creates a new `MapleTree` parser instance
    pub fn new(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<Self> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let maple_tree = VirtualStruct::from_name(
            &vmem_reader,
            type_information,
            "maple_tree",
            &virtual_address,
        )?;

        let ma_root = maple_tree.traverse("ma_root")?.read_vaddr()?;
        if ma_root.is_null() {
            return Ok(Self { entry_list: vec![] });
        }

        let mut value_vaddr_list = Vec::new();
        if Self::is_ma_node(ma_root) {
            // It's an internal node - traverse the tree
            Self::collect_ma_node_entries(
                &vmem_reader,
                type_information,
                ma_root,
                0,
                u64::MAX,
                &mut value_vaddr_list,
            )?;
        } else if !Self::is_ma_value(ma_root) && !Self::is_ma_internal_entry(ma_root) {
            // It's a direct entry (single entry stored directly in ma_root)
            value_vaddr_list.push(MapleTreeEntryValuePointer {
                key: 0..u64::MAX,
                value: ma_root,
            });
        }

        let mut entry_list = Vec::new();
        for value_vaddr in value_vaddr_list {
            match T::from_vaddr(readable, architecture, type_information, value_vaddr.value) {
                Ok(value) => {
                    entry_list.push(MapleTreeEntry {
                        key: value_vaddr.key,
                        value,
                    });
                }

                Err(err) => {
                    debug!(
                        "Failed to parse maple tree value at {:?}: {err:?}",
                        value_vaddr.value
                    );
                }
            }
        }

        Ok(Self { entry_list })
    }

    /// Checks if a node is marked as dead (parent pointer points to self)
    /// Dead nodes occur during RCU-based tree modifications and should be skipped
    fn is_dead_node(ma_node: &VirtualStruct) -> Result<bool> {
        let parent_value = ma_node.traverse("parent")?.read_u64()?;
        let parent_addr = parent_value & !MAPLE_NODE_MASK;
        let node_addr = ma_node.virtual_address().value().value();

        Ok(parent_addr == node_addr)
    }

    /// Returns the number of pivots for a given node type
    fn get_pivots_per_type(node_type: u8) -> usize {
        match node_type {
            MAPLE_TYPE_DENSE => PIVOTS_DENSE,
            MAPLE_TYPE_LEAF_64 => PIVOTS_RANGE64,
            MAPLE_TYPE_RANGE_64 => PIVOTS_RANGE64,
            MAPLE_TYPE_ARANGE_64 => PIVOTS_ARANGE64,
            _ => 0,
        }
    }

    /// Reads the meta.end field from a node
    fn ma_meta_end(node_struct: &VirtualStruct, node_type: u8) -> Result<u8> {
        if node_type == MAPLE_TYPE_ARANGE_64 {
            node_struct
                .traverse("ma64")?
                .traverse("meta")?
                .traverse("end")?
                .read_u8()
        } else {
            node_struct
                .traverse("mr64")?
                .traverse("meta")?
                .traverse("end")?
                .read_u8()
        }
    }

    /// Determines the last valid slot index in a node
    fn ma_data_end(node_struct: &VirtualStruct, node_type: u8, node_max: u64) -> Result<usize> {
        // Dense nodes don't have pivots
        if node_type == MAPLE_TYPE_DENSE {
            return Ok(0);
        }

        // For arange_64, always use metadata
        if node_type == MAPLE_TYPE_ARANGE_64 {
            let end = Self::ma_meta_end(node_struct, node_type)?;
            return Ok(end as usize);
        }

        // For range_64 and leaf_64
        let mr64 = node_struct.traverse("mr64")?;
        let max_pivot_index = Self::get_pivots_per_type(node_type);
        let last_pivot_index = max_pivot_index - 1;

        // Read the last pivot
        let last_pivot = mr64
            .traverse(&format!("pivot[{last_pivot_index}]"))?
            .read_u64()?;

        // If last pivot is 0, use metadata
        if last_pivot == 0 {
            return Self::ma_meta_end(node_struct, node_type).map(|end| end as usize);
        }

        // If last pivot equals node max, that's the end
        if last_pivot == node_max {
            return Ok(last_pivot_index);
        }

        // All pivot slots are used
        Ok(max_pivot_index)
    }

    /// Recursively collects all the value pointers from a maple tree node
    fn collect_ma_node_entries(
        vmem_reader: &VirtualMemoryReader,
        type_information: &TypeInformation,
        entry_vaddr: VirtualAddress,
        range_min: u64,
        range_max: u64,
        entry_list: &mut Vec<MapleTreeEntryValuePointer>,
    ) -> Result<()> {
        if entry_vaddr.is_null() {
            return Ok(());
        }

        let node_type =
            ((entry_vaddr.value().value() >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK) as u8;

        // Decode the node pointer, stripping the tag bits
        let node_vaddr = Self::to_ma_node(entry_vaddr);
        let ma_node =
            VirtualStruct::from_name(vmem_reader, type_information, "maple_node", &node_vaddr)
                .inspect_err(|err| debug!("Failed to create maple_node VirtualStruct: {err:?}"))?;

        // Check if node is dead
        if let Ok(is_dead) = Self::is_dead_node(&ma_node)
            && is_dead
        {
            debug!("Skipping dead node at 0x{:x}", node_vaddr.value().value());
            return Ok(());
        }

        // Handle different node types
        match node_type {
            MAPLE_TYPE_LEAF_64 => {
                // Leaf node containing value entries
                Self::collect_leaf64_entries(
                    &ma_node, node_type, range_min, range_max, entry_list,
                )?;
            }

            MAPLE_TYPE_RANGE_64 => {
                // Internal node, slots point to child nodes
                Self::collect_internal_range64_entries(
                    vmem_reader,
                    type_information,
                    &ma_node,
                    node_type,
                    range_min,
                    range_max,
                    entry_list,
                )?;
            }

            MAPLE_TYPE_ARANGE_64 => {
                // Internal node with gap tracking
                Self::collect_internal_arange64_entries(
                    vmem_reader,
                    type_information,
                    &ma_node,
                    node_type,
                    range_min,
                    range_max,
                    entry_list,
                )?;
            }

            MAPLE_TYPE_DENSE => {
                // Leaf node with sequential storage
                Self::collect_dense_entries(&ma_node, range_min, range_max, entry_list)?;
            }

            _ => {
                debug!("Unknown node type: {}", node_type);
            }
        }

        Ok(())
    }

    /// Collects entries from a maple_leaf_64 leaf node
    fn collect_leaf64_entries(
        ma_node: &VirtualStruct,
        node_type: u8,
        range_min: u64,
        range_max: u64,
        entry_list: &mut Vec<MapleTreeEntryValuePointer>,
    ) -> Result<()> {
        let data_end = Self::ma_data_end(ma_node, node_type, range_max)?;
        let slot_len = data_end + 1; // data_end is 0-based index, slot_len is count
        let mr64 = ma_node.traverse("mr64")?;

        for i in 0..slot_len {
            let slot_entry = mr64
                .traverse(&format!("slot[{i}]"))?
                .read_vaddr()
                .inspect_err(|err| debug!("Failed to read mr64.slot[{i}]: {err:?}"))?;

            if slot_entry.is_null() {
                continue;
            }

            // Calculate the range for this slot
            let slot_min = if i == 0 {
                range_min
            } else {
                mr64.traverse(&format!("pivot[{}]", i - 1))?
                    .read_u64()
                    .inspect_err(|err| debug!("Failed to read pivot[{}]: {err:?}", i - 1))?
                    .wrapping_add(1)
            };

            let slot_max = if i < slot_len - 1 {
                mr64.traverse(&format!("pivot[{i}]"))?
                    .read_u64()
                    .inspect_err(|err| debug!("Failed to read pivot[{i}]: {err:?}"))?
            } else {
                range_max
            };

            // If it is a leaf node, all non-null slots are value pointers (no recursion)
            if !Self::is_ma_value(slot_entry) && !Self::is_ma_internal_entry(slot_entry) {
                // Ensure it is a kernel address
                if slot_entry.is_in_high_canonical_space() {
                    entry_list.push(MapleTreeEntryValuePointer {
                        key: slot_min..slot_max.wrapping_add(1),
                        value: slot_entry,
                    });
                }
            }
        }

        Ok(())
    }

    /// Collects entries from a maple_range_64 internal node
    fn collect_internal_range64_entries(
        vmem_reader: &VirtualMemoryReader,
        type_information: &TypeInformation,
        ma_node: &VirtualStruct,
        node_type: u8,
        range_min: u64,
        range_max: u64,
        entry_list: &mut Vec<MapleTreeEntryValuePointer>,
    ) -> Result<()> {
        let mr64 = ma_node.traverse("mr64")?;
        let data_end = Self::ma_data_end(ma_node, node_type, range_max)?;
        let slot_len = data_end + 1;

        for i in 0..slot_len {
            let slot_entry = mr64.traverse(&format!("slot[{i}]"))?.read_vaddr()?;

            if slot_entry.is_null() {
                continue;
            }

            let slot_min = if i == 0 {
                range_min
            } else {
                mr64.traverse(&format!("pivot[{}]", i - 1))?
                    .read_u64()?
                    .wrapping_add(1)
            };

            let slot_max = if i < slot_len - 1 {
                mr64.traverse(&format!("pivot[{i}]"))?.read_u64()?
            } else {
                range_max
            };

            // For internal nodes, all non-null slots are child node pointers
            Self::collect_ma_node_entries(
                vmem_reader,
                type_information,
                slot_entry,
                slot_min,
                slot_max,
                entry_list,
            )?;
        }

        Ok(())
    }

    /// Collects child node entries from a maple_arange_64 internal node slots
    fn collect_internal_arange64_entries(
        vmem_reader: &VirtualMemoryReader,
        type_information: &TypeInformation,
        ma_node: &VirtualStruct,
        node_type: u8,
        range_min: u64,
        range_max: u64,
        entry_list: &mut Vec<MapleTreeEntryValuePointer>,
    ) -> Result<()> {
        let ma64 = ma_node.traverse("ma64")?;

        let data_end = Self::ma_data_end(ma_node, node_type, range_max)?;
        let slot_len = data_end + 1; // data_end is 0-based index, slot_len is count

        for i in 0..slot_len {
            let slot_entry = ma64
                .traverse(&format!("slot[{i}]"))?
                .read_vaddr()
                .inspect_err(|err| debug!("Failed to read ma64.slot[{i}]: {err:?}"))?;

            if slot_entry.is_null() {
                continue;
            }

            // Calculate the range for this slot
            let slot_min = if i == 0 {
                range_min
            } else {
                ma64.traverse(&format!("pivot[{}]", i - 1))?
                    .read_u64()
                    .inspect_err(|err| debug!("Failed to read pivot[{}]: {err:?}", i - 1))?
                    .wrapping_add(1)
            };

            let slot_max = if i < slot_len - 1 {
                ma64.traverse(&format!("pivot[{i}]"))?
                    .read_u64()
                    .inspect_err(|err| debug!("Failed to read pivot[{i}]: {err:?}"))?
            } else {
                range_max
            };

            Self::collect_ma_node_entries(
                vmem_reader,
                type_information,
                slot_entry,
                slot_min,
                slot_max,
                entry_list,
            )?;
        }

        Ok(())
    }

    /// Collects entries from a maple_dense node, which just uses indices and no pivots
    fn collect_dense_entries(
        ma_node: &VirtualStruct,
        range_min: u64,
        range_max: u64,
        entry_list: &mut Vec<MapleTreeEntryValuePointer>,
    ) -> Result<()> {
        for offset in 0..MAPLE_NODE_SLOTS {
            let index = range_min + offset as u64;
            if index > range_max {
                break;
            }

            let slot_entry = ma_node
                .traverse(&format!("slot[{offset}]"))?
                .read_vaddr()
                .inspect_err(|err| debug!("Failed to read dense slot[{offset}]: {err:?}"))?;

            if slot_entry.is_null() {
                continue;
            }

            // Check that this is a kernel address first
            if slot_entry.is_in_high_canonical_space() {
                // For dense nodes, each entry covers a single index
                entry_list.push(MapleTreeEntryValuePointer {
                    key: index..index + 1,
                    value: slot_entry,
                });
            }
        }

        Ok(())
    }

    /// Converts a maple tree internal node pointer to the actual node address
    /// Maple tree stores metadata in the lower 8 bits (MAPLE_NODE_MASK = 255)
    /// We need to mask these bits off to get the actual aligned address
    fn to_ma_node(vaddr: VirtualAddress) -> VirtualAddress {
        let raw_addr = vaddr.value().value();
        let aligned_addr = raw_addr & !MAPLE_NODE_MASK;

        VirtualAddress::new(
            vaddr.root_page_table(),
            RawVirtualAddress::new(aligned_addr),
        )
    }

    /// Checks if an entry is an internal entry (bottom 2 bits = 0b10)
    fn is_ma_internal_entry(vaddr: VirtualAddress) -> bool {
        vaddr.value().value() & 3 == 2
    }

    /// Checks if an entry is a node pointer (internal entry with address > 4096)
    fn is_ma_node(vaddr: VirtualAddress) -> bool {
        Self::is_ma_internal_entry(vaddr) && vaddr.value().value() > 4096
    }

    /// Checks if an entry is a value entry (bottom bit = 1)
    /// These are encoded values, not pointers
    fn is_ma_value(vaddr: VirtualAddress) -> bool {
        vaddr.value().value() & 1 != 0
    }
}
