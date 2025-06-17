//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        error::{Error as CoreError, ErrorKind as CoreErrorKind, Result as CoreResult},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::virtual_address::VirtualAddress,
};

use btfparse::{Offset, TypeInformation};

use std::fmt;

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
    ) -> CoreResult<Self> {
        if type_information.from_id(tid).is_none() {
            Err(CoreError::new(
                CoreErrorKind::TypeInformationError,
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
    ) -> CoreResult<Self> {
        if let Some(tid) = type_information.id_of(name) {
            Self::from_id(vmem_reader, type_information, tid, virtual_address)
        } else {
            Err(CoreError::new(
                CoreErrorKind::TypeInformationError,
                &format!("Invalid virtual struct type name: {name}"),
            ))
        }
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
    pub fn traverse(&self, path: &str) -> CoreResult<Self> {
        // TODO: This will fail if there's a ptr
        let (destination_tid, destination_offset) =
            self.type_information.offset_of(self.tid, path).map_err(
              |error| {
                CoreError::new(
                  CoreErrorKind::TypeTraversalError,
                  &format!("The following path could not be used to traverse type #{}: {path}. BTF error: {error:?}", self.tid),
                )
              }
            )?;

        let virtual_address = self.virtual_address
            + match destination_offset {
                Offset::ByteOffset(offset) => offset as u64,
                _ => {
                    return Err(CoreError::new(
                        CoreErrorKind::TypeInformationError,
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
    pub fn dereference(&self) -> CoreResult<Self> {
        let pointee_tid = self
            .type_information
            .pointee_tid(self.tid)
            .map_err(|error| {
                CoreError::new(
                    CoreErrorKind::TypeTraversalError,
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

    /// Reads a virtual address from the current position
    pub fn read_vaddr(&self) -> CoreResult<VirtualAddress> {
        self.vmem_reader.read_vaddr(self.virtual_address)
    }

    /// Reads a u32 from the current position
    pub fn read_u32(&self) -> CoreResult<u32> {
        self.vmem_reader.read_u32(self.virtual_address)
    }

    /// Reads a u64 from the current position
    pub fn read_u64(&self) -> CoreResult<u64> {
        self.vmem_reader.read_u64(self.virtual_address)
    }

    /// Reads a string from the current position
    pub fn read_string(&self, max_size: Option<usize>, lossy: bool) -> CoreResult<String> {
        let mut buffer = Vec::new();

        for offset in 0.. {
            if let Some(max_size) = max_size {
                if offset >= max_size {
                    break;
                }
            }

            let byte = self
                .vmem_reader
                .read_u8(self.virtual_address + offset as u64)?;

            if byte == 0 {
                break;
            }

            buffer.push(byte);
        }

        let string = if lossy {
            String::from_utf8_lossy(&buffer).to_string()
        } else {
            String::from_utf8(buffer.to_vec()).map_err(|_| {
                CoreError::new(
                    CoreErrorKind::InvalidData,
                    "Failed to convert the string to UTF-8",
                )
            })?
        };

        Ok(string)
    }

    /// Reads a byte vector from the current position
    pub fn read_bytes(&self, size: usize) -> CoreResult<Vec<u8>> {
        let mut buffer = Vec::new();

        for offset in 0..size {
            buffer.push(
                self.vmem_reader
                    .read_u8(self.virtual_address + offset as u64)?,
            );
        }

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
