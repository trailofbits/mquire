//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::error::Result,
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
};

/// Represents the endianness of the target architecture
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Endianness {
    /// Little endian
    Little,

    /// Big endian
    Big,
}

/// The architecture bitness
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Bitness {
    /// 64-bit
    Bit64,
}

/// Represents a physical address range
#[derive(Copy, Clone, Debug)]
pub struct PhysicalAddressRange {
    /// The starting physical address
    address: PhysicalAddress,

    /// How many bytes are readable from the starting physical address
    size: u64,
}

impl PhysicalAddressRange {
    /// Creates a new physical address range
    pub fn new(address: PhysicalAddress, remaining_bytes: u64) -> Self {
        Self {
            address,
            size: remaining_bytes,
        }
    }

    /// Returns the starting physical address
    pub fn address(&self) -> PhysicalAddress {
        self.address
    }

    /// Returns the size of the physical address range
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Returns true if the physical address range is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A virtual memory region
pub struct Region {
    pub virtual_address: VirtualAddress,
    pub physical_address: PhysicalAddress,
    pub size: u64,
}

pub trait Architecture {
    /// Returns the endianness of the target architecture
    fn endianness(&self) -> Endianness;

    /// Returns the bitness of the target architecture
    fn bitness(&self) -> Bitness;

    /// Locates the page table required to translate the given virtual address into the specified physical address
    fn locate_page_table_for_virtual_address(
        &self,
        readable: &dyn Readable,
        physical_address: PhysicalAddress,
        raw_virtual_address: RawVirtualAddress,
    ) -> Result<PhysicalAddress>;

    /// Translates the given virtual address into a physical address range
    fn translate_virtual_address(
        &self,
        readable: &dyn Readable,
        virtual_address: VirtualAddress,
    ) -> Result<PhysicalAddressRange>;

    /// Returns a list of valid virtual memory regions for the given root page table
    fn enumerate_page_table_regions(
        &self,
        readable: &dyn Readable,
        root_page_table: PhysicalAddress,
    ) -> Result<Vec<Region>>;
}
