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
};

use btfparse::{Offset, TypeInformation};

use std::fmt;

/// The chunk size to use when reading strings of unknown length
const READ_STRING_BYTES_CHUNK_SIZE: usize = 128;

/// A virtual structure, backed by debug symbols, located in the virtual address space
#[derive(Clone, Copy)]
pub struct VirtualStruct<'a> {
    /// The virtual memory reader
    vmem_reader: &'a VirtualMemoryReader<'a>,

    /// The type information referenced by this virtual struct
    type_information: &'a TypeInformation,

    /// The ID of the type this virtual struct is based on
    tid: u32,

    /// The current virtual address of the struct
    virtual_address: VirtualAddress,
}

impl<'a> VirtualStruct<'a> {
    /// Creates a new VirtualStruct from the specified type id
    pub fn from_id(
        vmem_reader: &'a VirtualMemoryReader,
        type_information: &'a TypeInformation,
        tid: u32,
        virtual_address: &VirtualAddress,
    ) -> Result<Self> {
        if type_information.from_id(tid).is_none() {
            Err(Error::new(
                ErrorKind::TypeInformationError,
                &format!("Invalid virtual struct ID: {tid}"),
            ))
        } else {
            Ok(Self {
                vmem_reader,
                type_information,
                tid,
                virtual_address: *virtual_address,
            })
        }
    }

    /// Creates a new VirtualStruct from the specified type name
    pub fn from_name(
        vmem_reader: &'a VirtualMemoryReader,
        type_information: &'a TypeInformation,
        name: &str,
        virtual_address: &VirtualAddress,
    ) -> Result<Self> {
        type_information
            .id_of(name)
            .map(|tid| Self::from_id(vmem_reader, type_information, tid, virtual_address))
            .unwrap_or_else(|| {
                Err(Error::new(
                    ErrorKind::TypeInformationError,
                    &format!("Invalid virtual struct type name: {name}"),
                ))
            })
    }

    /// Returns the type id of the virtual struct
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Returns the virtual address of the virtual struct
    pub fn virtual_address(&self) -> VirtualAddress {
        self.virtual_address
    }

    /// Traverses the current type using the specified path
    pub fn traverse(&self, path: &str) -> Result<Self> {
        // TODO: This will fail if there's a ptr
        let (destination_tid, destination_offset) =
            self.type_information.offset_of(self.tid, path).map_err(
              |error| {
                Error::new(
                  ErrorKind::TypeTraversalError,
                  &format!("The following path could not be used to traverse type #{}: {path}. BTF error: {error:?}", self.tid),
                )
              }
            )?;

        let virtual_address = self.virtual_address
            + match destination_offset {
                Offset::ByteOffset(offset) => offset as u64,
                _ => {
                    return Err(Error::new(
                        ErrorKind::TypeInformationError,
                        &format!("Invalid offset: {destination_offset:?}"),
                    ))
                }
            };

        Ok(Self {
            vmem_reader: self.vmem_reader,
            type_information: self.type_information,
            tid: destination_tid,
            virtual_address,
        })
    }

    /// Dereferences the current pointer
    pub fn dereference(&self) -> Result<Self> {
        let pointee_tid = self
            .type_information
            .pointee_tid(self.tid)
            .map_err(|error| {
                Error::new(
                    ErrorKind::TypeTraversalError,
                    &format!(
                        "Failed to get the pointee type id for type #{}. BTF error: {:?}",
                        self.tid, error
                    ),
                )
            })?;

        let virtual_address = self.read_vaddr()?;

        Ok(Self {
            vmem_reader: self.vmem_reader,
            type_information: self.type_information,
            tid: pointee_tid,
            virtual_address,
        })
    }

    /// Casts to another type
    #[allow(unused)]
    pub fn cast_to(&self, name: &str) -> Result<Self> {
        self.type_information
            .id_of(name)
            .map(|tid| Self {
                vmem_reader: self.vmem_reader,
                type_information: self.type_information,
                tid,
                virtual_address: self.virtual_address,
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::TypeInformationError,
                    &format!("Invalid virtual struct type name: {name}"),
                )
            })
    }

    /// Reads a virtual address from the current position
    pub fn read_vaddr(&self) -> Result<VirtualAddress> {
        self.vmem_reader.read_vaddr(self.virtual_address)
    }

    /// Reads a u8 from the current position
    #[allow(unused)]
    pub fn read_u8(&self) -> Result<u8> {
        self.vmem_reader.read_u8(self.virtual_address)
    }

    /// Reads a u16 from the current position
    pub fn read_u16(&self) -> Result<u16> {
        self.vmem_reader.read_u16(self.virtual_address)
    }

    /// Reads a u32 from the current position
    pub fn read_u32(&self) -> Result<u32> {
        self.vmem_reader.read_u32(self.virtual_address)
    }

    /// Reads a u64 from the current position
    pub fn read_u64(&self) -> Result<u64> {
        self.vmem_reader.read_u64(self.virtual_address)
    }

    // Helper function for read_string and read_string_lossy
    fn read_string_bytes(&self, max_size: Option<usize>) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut offset = 0;

        loop {
            let remaining = max_size.map(|max| max.saturating_sub(offset));
            let chunk_size = match remaining {
                Some(0) => break,
                Some(r) => r.min(READ_STRING_BYTES_CHUNK_SIZE),
                None => READ_STRING_BYTES_CHUNK_SIZE,
            };

            let mut chunk = vec![0u8; chunk_size];
            let bytes_read = match self
                .vmem_reader
                .read(&mut chunk, self.virtual_address + offset as u64)
            {
                Ok(n) => n,
                Err(e) => {
                    if !buffer.is_empty() {
                        log::debug!(
                            "String read error at offset {}, returning partial data ({} bytes)",
                            offset,
                            buffer.len()
                        );
                        return Ok(buffer);
                    }

                    return Err(e);
                }
            };

            if bytes_read == 0 {
                break;
            }

            if let Some(null_pos) = chunk[..bytes_read].iter().position(|&b| b == 0) {
                buffer.extend_from_slice(&chunk[..null_pos]);
                break;
            }

            buffer.extend_from_slice(&chunk[..bytes_read]);
            offset += bytes_read;

            if bytes_read < chunk_size {
                break;
            }
        }

        Ok(buffer)
    }

    /// Reads a string from the current position
    pub fn read_string_lossy(&self, max_size: Option<usize>) -> Result<String> {
        let buffer = self.read_string_bytes(max_size)?;

        let mut string = String::from_utf8_lossy(&buffer).to_string();
        if let Some(0) = string.as_bytes().first().cloned() {
            string.clear();
        }

        Ok(string)
    }

    /// Reads a byte vector from the current position
    pub fn read_bytes(&self, size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; size];
        self.vmem_reader
            .read_exact(&mut buffer, self.virtual_address)?;

        Ok(buffer)
    }
}

impl fmt::Debug for VirtualStruct<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "tid:{}, virtual_address:{:?}",
            self.tid, self.virtual_address
        )
    }
}
