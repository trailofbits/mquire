//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{PhysicalAddress, Readable, Result as MemoryResult};

/// Provides a convenient interface for reading from a `Readable` instance
pub struct Reader<'a> {
    /// The `Readable` instance
    readable: &'a dyn Readable,

    /// The endianness of the target architecture
    little_endian: bool,
}

impl<'a> Reader<'a> {
    /// Creates a new `Reader` instance
    pub fn new(readable: &'a dyn Readable, little_endian: bool) -> Reader<'a> {
        Reader {
            readable,
            little_endian,
        }
    }

    /// Reads the specified number of bytes from the given physical address
    pub fn read(&self, physical_address: PhysicalAddress, buffer: &mut [u8]) -> MemoryResult<()> {
        self.readable.read(buffer, physical_address)
    }

    /// Returns the size of the readable instance
    pub fn len(&self) -> MemoryResult<u64> {
        self.readable.len()
    }

    /// Returns true if the readable instance is empty
    pub fn is_empty(&self) -> MemoryResult<bool> {
        self.readable.is_empty()
    }

    /// Reads a single unsigned byte from the given physical address
    pub fn read_u8(&self, physical_address: PhysicalAddress) -> MemoryResult<u8> {
        let mut buffer = [0; 1];
        self.readable.read(&mut buffer, physical_address)?;
        Ok(buffer[0])
    }

    /// Reads a 16-bit unsigned integer from the given physical address
    pub fn read_u16(&self, physical_address: PhysicalAddress) -> MemoryResult<u16> {
        let mut buffer = [0; 2];
        self.readable.read(&mut buffer, physical_address)?;

        match self.little_endian {
            true => Ok(u16::from_le_bytes(buffer)),
            false => Ok(u16::from_be_bytes(buffer)),
        }
    }

    /// Reads a 32-bit unsigned integer from the given physical address
    pub fn read_u32(&self, physical_address: PhysicalAddress) -> MemoryResult<u32> {
        let mut buffer = [0; 4];
        self.readable.read(&mut buffer, physical_address)?;

        match self.little_endian {
            true => Ok(u32::from_le_bytes(buffer)),
            false => Ok(u32::from_be_bytes(buffer)),
        }
    }

    /// Reads a 64-bit unsigned integer from the given physical address
    pub fn read_u64(&self, physical_address: PhysicalAddress) -> MemoryResult<u64> {
        let mut buffer = [0; 8];
        self.readable.read(&mut buffer, physical_address)?;

        match self.little_endian {
            true => Ok(u64::from_le_bytes(buffer)),
            false => Ok(u64::from_be_bytes(buffer)),
        }
    }

    /// Reads a single signed byte from the given physical address
    pub fn read_i8(&self, physical_address: PhysicalAddress) -> MemoryResult<i8> {
        self.read_u8(physical_address).map(|value| value as i8)
    }

    /// Reads a 16-bit signed integer from the given physical address
    pub fn read_i16(&self, physical_address: PhysicalAddress) -> MemoryResult<i16> {
        self.read_u16(physical_address).map(|value| value as i16)
    }

    /// Reads a 32-bit signed integer from the given physical address
    pub fn read_i32(&self, physical_address: PhysicalAddress) -> MemoryResult<i32> {
        self.read_u32(physical_address).map(|value| value as i32)
    }

    /// Reads a 64-bit signed integer from the given physical address
    pub fn read_i64(&self, physical_address: PhysicalAddress) -> MemoryResult<i64> {
        self.read_u64(physical_address).map(|value| value as i64)
    }
}
