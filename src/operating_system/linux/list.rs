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
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    operating_system::linux::virtual_struct::VirtualStruct,
};

use {
    btfparse::{Offset, TypeInformation},
    log::debug,
};

use std::collections::BTreeSet;

/// Trait for types that can be extracted from a linked list node
pub trait ListValue: Sized {
    fn from_vaddr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<Self>;
}

/// The type of linked list structure
#[derive(Debug, Clone, Copy, PartialEq)]
enum ListType {
    /// Hash list - singly-linked list with only 'next' pointer
    HList,

    /// Doubly-linked list with 'next' and 'prev' pointers
    DoublyLinked,
}

/// A parsed linked list containing extracted values
pub struct List<T: ListValue> {
    entry_list: Vec<T>,
}

impl<T: ListValue> List<T> {
    /// Creates a new builder for constructing a List parser
    pub fn builder() -> ListBuilder<T> {
        ListBuilder {
            list_type: ListType::HList,
            container_type: None,
            node_path: None,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Returns a reference to the entry list
    #[allow(dead_code)]
    pub fn entries(&self) -> &[T] {
        &self.entry_list
    }
}

impl<T: ListValue> IntoIterator for List<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.entry_list.into_iter()
    }
}

/// Builder for configuring and parsing a linked list
pub struct ListBuilder<T: ListValue> {
    /// The list type
    list_type: ListType,

    /// The name of the container type
    container_type: Option<String>,

    /// The path to the list_node/hlist_node, starting from container_type
    node_path: Option<Vec<String>>,

    /// Internal field, use to link to T even if it's not used in the builder
    _phantom: std::marker::PhantomData<T>,
}

impl<T: ListValue> ListBuilder<T> {
    /// Configure this as a hash list (singly-linked with only 'next')
    pub fn hlist(mut self) -> Self {
        self.list_type = ListType::HList;
        self
    }

    /// Configure this as a doubly-linked list (with 'next' and 'prev')
    #[allow(dead_code)]
    pub fn doubly_linked(mut self) -> Self {
        self.list_type = ListType::DoublyLinked;
        self
    }

    /// Set the container type name that holds the list node
    pub fn container(mut self, type_name: &str) -> Self {
        self.container_type = Some(type_name.to_string());
        self
    }

    /// Set the path to the list node within the container
    pub fn node_path(mut self, path: &[&str]) -> Self {
        self.node_path = Some(path.iter().map(|s| s.to_string()).collect());
        self
    }

    /// Parse the linked list and extract all values
    pub fn parse(
        self,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        start_node_vaddr: VirtualAddress,
        kernel_page_table: PhysicalAddress,
    ) -> Result<List<T>> {
        let container_type = self.container_type.ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Container type not specified",
            )
        })?;

        let node_path = self.node_path.ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Node path not specified",
            )
        })?;

        let node_path_refs: Vec<&str> = node_path.iter().map(|s| s.as_str()).collect();

        let node_offset =
            Self::resolve_node_path(type_information, &container_type, &node_path_refs)?;

        let node_struct_name = match self.list_type {
            ListType::HList => "hlist_node",
            ListType::DoublyLinked => "list_head",
        };

        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let mut entry_list = Vec::new();

        let mut next_address_queue = vec![start_node_vaddr];
        let mut visited_raw_addr_set = BTreeSet::new();

        while !next_address_queue.is_empty() {
            let address_queue = next_address_queue;
            next_address_queue = Vec::new();

            for address in address_queue {
                if address.is_null() {
                    continue;
                }

                let current_node_raw_addr = &address.value();
                if current_node_raw_addr.value() & 1 != 0 {
                    continue;
                }

                if !visited_raw_addr_set.insert(address.value()) {
                    continue;
                }

                let current_value_vaddr = address - node_offset;

                match T::from_vaddr(
                    readable,
                    architecture,
                    type_information,
                    current_value_vaddr,
                ) {
                    Ok(value) => {
                        entry_list.push(value);
                    }

                    Err(err) => {
                        debug!(
                            "Failed to parse List value at {:?}: {err:?}",
                            current_value_vaddr
                        );
                    }
                }

                let list_node = match VirtualStruct::from_name(
                    &vmem_reader,
                    type_information,
                    node_struct_name,
                    &address,
                ) {
                    Ok(n) => n,
                    Err(_) => break,
                };

                let path_list = match self.list_type {
                    ListType::HList => vec!["next"],
                    ListType::DoublyLinked => vec!["next", "prev"],
                };

                for path in path_list {
                    let discovered_address = list_node
                        .traverse(path)
                        .and_then(|f| f.read_vaddr())
                        .unwrap_or_else(|_| {
                            VirtualAddress::new(kernel_page_table, RawVirtualAddress::new(0))
                        });

                    next_address_queue.push(discovered_address);
                }
            }
        }

        Ok(List { entry_list })
    }

    /// Resolves the byte offset of a list node within its container type
    fn resolve_node_path(
        type_information: &TypeInformation,
        container_type_name: &str,
        node_path: &[&str],
    ) -> Result<u64> {
        let mut current_container_tid =
            type_information.id_of(container_type_name).ok_or_else(|| {
                let msg = format!("Failed to locate type: {}", container_type_name);
                Error::new(ErrorKind::TypeInformationError, &msg)
            })?;

        let mut byte_offset = 0_u64;

        for path_component in node_path {
            if let (next_container_tid, Offset::ByteOffset(current_byte_offset)) =
                type_information.offset_of(current_container_tid, path_component)?
            {
                byte_offset += current_byte_offset as u64;
                current_container_tid = next_container_tid;
            } else {
                let msg = format!(
                    "Unexpected bitfield offset found when retrieving offset for {}",
                    path_component
                );
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    &msg,
                ));
            }
        }

        Ok(byte_offset)
    }
}
