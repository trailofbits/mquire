//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        architecture::{Architecture, Endianness},
        error::{Error, ErrorKind, Result},
    },
    memory::{primitives::RawVirtualAddress, readable::Readable, virtual_address::VirtualAddress},
};

use std::cmp;

/// Provides a way to read from virtual memory
pub struct VirtualMemoryReader<'a> {
    /// The memory dump
    readable: &'a dyn Readable,

    /// The target architecture
    architecture: &'a dyn Architecture,

    /// True if the target architecture is little endian
    little_endian: bool,
}

impl<'a> VirtualMemoryReader<'a> {
    /// Creates a new VirtualMemoryReader instance
    pub fn new(readable: &'a dyn Readable, architecture: &'a dyn Architecture) -> Self {
        Self {
            readable,
            architecture,
            little_endian: architecture.endianness() == Endianness::Little,
        }
    }

    /// Attempts to read the specified amount of bytes from the given virtual address
    pub fn read(&self, buffer: &mut [u8], virtual_address: VirtualAddress) -> Result<usize> {
        let physical_address_range = self
            .architecture
            .translate_virtual_address(self.readable, virtual_address)?;

        let bytes_readable = cmp::min(physical_address_range.len() as usize, buffer.len());

        let physical_address = physical_address_range.address();
        let dest_buffer = &mut buffer[..bytes_readable];

        self.readable
            .read(dest_buffer, physical_address)
            .map_err(|memory_error| -> Error { memory_error.into() })
    }

    /// Reads the specified number of bytes from the given virtual address
    pub fn read_exact(
        &self,
        mut buffer: &mut [u8],
        mut virtual_address: VirtualAddress,
    ) -> Result<()> {
        let bytes_requested = buffer.len();
        let mut total_bytes_read = 0;

        while !buffer.is_empty() {
            let bytes_read = self.read(buffer, virtual_address)?;
            total_bytes_read += bytes_read;

            if bytes_read == 0 {
                return Err(Error::new(
                    ErrorKind::MemoryError,
                    &format!(
                        "Could not read more than {total_bytes_read} bytes (requested: {bytes_requested})",
                    ),
                ));
            }

            virtual_address = virtual_address + bytes_read;
            buffer = &mut buffer[bytes_read..];
        }

        Ok(())
    }

    /// Returns the size of the memory dump
    pub fn len(&self) -> Result<u64> {
        self.readable
            .len()
            .map_err(|memory_error| memory_error.into())
    }

    /// Returns true if the memory dump is empty
    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|len| len == 0)
    }

    /// Reads a single unsigned byte from the given virtual address
    pub fn read_u8(&self, virtual_address: VirtualAddress) -> Result<u8> {
        let mut buffer = [0; 1];
        self.read_exact(&mut buffer, virtual_address)?;
        Ok(buffer[0])
    }

    /// Reads a 16-bit unsigned integer from the given virtual address
    pub fn read_u16(&self, virtual_address: VirtualAddress) -> Result<u16> {
        let mut buffer = [0; 2];
        self.read_exact(&mut buffer, virtual_address)?;

        match self.little_endian {
            true => Ok(u16::from_le_bytes(buffer)),
            false => Ok(u16::from_be_bytes(buffer)),
        }
    }

    /// Reads a 32-bit unsigned integer from the given virtual address
    pub fn read_u32(&self, virtual_address: VirtualAddress) -> Result<u32> {
        let mut buffer = [0; 4];
        self.read_exact(&mut buffer, virtual_address)?;

        match self.little_endian {
            true => Ok(u32::from_le_bytes(buffer)),
            false => Ok(u32::from_be_bytes(buffer)),
        }
    }

    /// Reads a 64-bit unsigned integer from the given virtual address
    pub fn read_u64(&self, virtual_address: VirtualAddress) -> Result<u64> {
        let mut buffer = [0; 8];
        self.read_exact(&mut buffer, virtual_address)?;

        match self.little_endian {
            true => Ok(u64::from_le_bytes(buffer)),
            false => Ok(u64::from_be_bytes(buffer)),
        }
    }

    /// Reads a single signed byte from the given virtual address
    pub fn read_i8(&self, virtual_address: VirtualAddress) -> Result<i8> {
        self.read_u8(virtual_address).map(|value| value as i8)
    }

    /// Reads a signed 16-bit integer from the given virtual address
    pub fn read_i16(&self, virtual_address: VirtualAddress) -> Result<i16> {
        self.read_u16(virtual_address).map(|value| value as i16)
    }

    /// Reads a signed 32-bit integer from the given virtual address
    pub fn read_i32(&self, virtual_address: VirtualAddress) -> Result<i32> {
        self.read_u32(virtual_address).map(|value| value as i32)
    }

    /// Reads a signed 64-bit integer from the given virtual address
    pub fn read_i64(&self, virtual_address: VirtualAddress) -> Result<i64> {
        self.read_u64(virtual_address).map(|value| value as i64)
    }

    /// Reads a virtual address from the given virtual address
    pub fn read_vaddr(&self, virtual_address: VirtualAddress) -> Result<VirtualAddress> {
        let raw_virtual_address = RawVirtualAddress::new(self.read_u64(virtual_address)?);

        Ok(VirtualAddress::new(
            virtual_address.root_page_table(),
            raw_virtual_address,
        ))
    }
}
