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
    operating_system::linux::{
        entities::cgroup::Cgroup, operating_system::LinuxOperatingSystem,
        task_struct_iterator::TaskStructIterator,
    },
    try_chain,
};

use {
    btfparse::{Integer32Value, TypeVariant},
    log::debug,
};

use std::collections::BTreeSet;

impl LinuxOperatingSystem {
    /// Returns the cgroup list
    pub(super) fn get_cgroup_list_impl(&self) -> Result<Vec<Cgroup>> {
        // Acquire the necessary types; if anything fails, we can't proceed
        let cpuset_cgrp_id = self
            .kernel_type_info
            .id_of("cgroup_subsys_id")
            .and_then(|type_id| self.kernel_type_info.from_id(type_id))
            .and_then(|type_variant| {
                if let TypeVariant::Enum(enum_type) = type_variant {
                    enum_type.named_value_list().iter().find_map(|named_value| {
                        if named_value.name == "cpuset_cgrp_id" {
                            Some(named_value.value)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
            .map(|integer_value| match integer_value {
                Integer32Value::Signed(value) => value as u32,
                Integer32Value::Unsigned(value) => value,
            })
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "Failed to acquire the cgroup_subsys_id::cpuset_cgrp_id enum value",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let css_type = self
            .kernel_type_info
            .id_of("css_set")
            .and_then(|type_id| self.kernel_type_info.from_id(type_id))
            .and_then(|type_variant| {
                if let TypeVariant::Struct(struct_type) = type_variant {
                    Some(struct_type)
                } else {
                    None
                }
            })
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "No `struct css_set` found",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let subsys_field = css_type
            .member_list()
            .iter()
            .find(|member| member.name().map(|name| name == "subsys").unwrap_or(false))
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "No field `subsys` found inside the `struct css_set` structure",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let subsys_array_type = self
            .kernel_type_info
            .from_id(subsys_field.tid())
            .and_then(|type_variant| {
                if let TypeVariant::Array(array_type) = type_variant {
                    Some(array_type)
                } else {
                    None
                }
            })
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "The `subsys` field inside the `struct css_set` structure is not an array",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        if cpuset_cgrp_id >= *subsys_array_type.element_count() {
            let err = Error::new(
                ErrorKind::TypeInformationError,
                "The `cpuset_cgrp_id` index is outside of the subsys array size",
            );

            debug!("{err:?}");
            return Err(err);
        }

        // From now on, if any error happens we can just skip the current entry
        let mut cgroup_list = Vec::new();
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let task_iter =
            TaskStructIterator::new(&vmem_reader, &self.kernel_type_info, self.init_task_vaddr)?;

        for task_struct in task_iter {
            let mut kn = match try_chain!(
                task_struct
                    .traverse("cgroups")?
                    .dereference()?
                    .traverse(&format!("subsys[{cpuset_cgrp_id}]"))?
                    .dereference()?
                    .traverse("cgroup")?
                    .dereference()?
                    .traverse("kn")?
                    .dereference()
            ) {
                Ok(kn) => kn,
                Err(err) => {
                    debug!("{err:?}");
                    continue;
                }
            };

            let mut visited_address_list = BTreeSet::new();
            let mut name_list = Vec::new();

            while !kn.virtual_address().is_null() {
                if !visited_address_list.insert(kn.virtual_address().value()) {
                    break;
                }

                let parent_kn = match try_chain!(kn.traverse("parent")?.dereference()) {
                    Ok(parent_kn) => parent_kn,
                    Err(err) => {
                        debug!("{err:?}");
                        continue;
                    }
                };

                match kn
                    .traverse("name")
                    .and_then(|obj| obj.dereference())
                    .and_then(|obj| obj.read_string_lossy(None))
                    .and_then(|buffer| {
                        if buffer.is_empty() {
                            Err(Error::new(
                                ErrorKind::InvalidData,
                                "Found an empty kn node name",
                            ))
                        } else {
                            Ok(buffer)
                        }
                    }) {
                    Ok(name) => {
                        name_list.push(name);
                    }

                    Err(err) => {
                        debug!("{err:?}");
                        break;
                    }
                };

                kn = parent_kn;
            }

            if !name_list.is_empty() {
                cgroup_list.push(Cgroup {
                    task: task_struct.virtual_address(),
                    name: name_list.into_iter().rev().collect::<Vec<_>>().join("/"),
                });
            }
        }

        Ok(cgroup_list)
    }
}
