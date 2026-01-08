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
        entities::{system_information::SystemInformation, system_version::SystemVersion},
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        operating_system::LinuxOperatingSystem, virtual_struct::VirtualStruct,
    },
    try_chain,
};

use {
    btfparse::{TypeInformation, TypeVariant},
    log::debug,
};

impl LinuxOperatingSystem {
    /// Returns the OS version
    pub(super) fn get_system_version(
        memory_dump: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
        init_task_vaddr: &VirtualAddress,
    ) -> Result<SystemVersion> {
        let release_array_len =
            Self::get_struct_array_member_len(kernel_type_info, "new_utsname", "release")
                .inspect_err(|err| debug!("{err:?}"))?;

        let version_array_len =
            Self::get_struct_array_member_len(kernel_type_info, "new_utsname", "version")
                .inspect_err(|err| debug!("{err:?}"))?;

        let machine_array_len =
            Self::get_struct_array_member_len(kernel_type_info, "new_utsname", "machine")
                .inspect_err(|err| debug!("{err:?}"))?;

        let vmem_reader = VirtualMemoryReader::new(memory_dump, architecture);

        let init_task_struct = VirtualStruct::from_name(
            &vmem_reader,
            kernel_type_info,
            "task_struct",
            init_task_vaddr,
        )
        .inspect_err(|err| debug!("{err:?}"))?;

        let new_utsname = try_chain!(
            init_task_struct
                .traverse("nsproxy")?
                .dereference()?
                .traverse("uts_ns")?
                .dereference()?
                .traverse("name")
        )
        .inspect_err(|err| debug!("{err:?}"))?;

        let kernel_version = try_chain!(
            new_utsname
                .traverse("release")?
                .read_string_lossy(Some(release_array_len))
        )
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        let system_version = try_chain!(
            new_utsname
                .traverse("version")?
                .read_string_lossy(Some(version_array_len))
        )
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        let arch = try_chain!(
            new_utsname
                .traverse("machine")?
                .read_string_lossy(Some(machine_array_len))
        )
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        Ok(SystemVersion {
            system_version,
            kernel_version,
            arch,
        })
    }

    /// Returns the system information
    pub(super) fn get_system_information_impl(&self) -> Result<SystemInformation> {
        let nodename_array_len =
            Self::get_struct_array_member_len(&self.kernel_type_info, "new_utsname", "nodename")
                .inspect_err(|err| debug!("{err:?}"))?;

        let domainname_array_len =
            Self::get_struct_array_member_len(&self.kernel_type_info, "new_utsname", "domainname")
                .inspect_err(|err| debug!("{err:?}"))?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let init_task_struct = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "task_struct",
            &self.init_task_vaddr,
        )
        .inspect_err(|err| debug!("{err:?}"))?;

        let new_utsname = try_chain!(
            init_task_struct
                .traverse("nsproxy")?
                .dereference()?
                .traverse("uts_ns")?
                .dereference()?
                .traverse("name")
        )
        .inspect_err(|err| debug!("{err:?}"))?;

        let hostname = try_chain!(
            new_utsname
                .traverse("nodename")?
                .read_string_lossy(Some(nodename_array_len))
        )
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        let domain = try_chain!(
            new_utsname
                .traverse("domainname")?
                .read_string_lossy(Some(domainname_array_len))
        )
        .inspect_err(|err| debug!("{err:?}"))
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) });

        Ok(SystemInformation { hostname, domain })
    }

    /// Returns the length of an array located in a structure
    pub(super) fn get_struct_array_member_len(
        kernel_type_info: &TypeInformation,
        struct_name: &str,
        member_name: &str,
    ) -> Result<usize> {
        let tid = kernel_type_info
            .id_of(struct_name)
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                "Failed to acquire the type definition of `struct {struct_name}`",
            ))
            .inspect_err(|err| debug!("{err:?}"))?;

        let struct_type_var = kernel_type_info.from_id(tid).ok_or(
            Error::new(
                ErrorKind::TypeInformationError,
                &format!("Failed to acquire the type information for `struct {struct_name}` from tid {tid}"),
            )
        ).inspect_err(|err| debug!("{err:?}"))?;

        let struct_type = match struct_type_var {
            TypeVariant::Struct(struct_type) => struct_type,
            _ => {
                let err = Error::new(
                    ErrorKind::TypeInformationError,
                    &format!(
                        "Failed to acquire the type information for `struct {struct_name}` from tid {tid}"
                    ),
                );

                debug!("{err:?}");
                return Err(err);
            }
        };

        let member_tid = struct_type
            .member_list()
            .iter()
            .find(|member| {
                member
                    .name()
                    .map(|name| name == member_name)
                    .unwrap_or(false)
            })
            .map(|member| member.tid())
            .ok_or(Error::new(
                ErrorKind::TypeInformationError,
                &format!("No field `{member_name}` found inside the `{struct_name}` structure",),
            ))?;

        let member_type_var = kernel_type_info.from_id(member_tid).ok_or(Error::new(
            ErrorKind::TypeInformationError,
            &format!(
                "Type ID {member_tid} for member `{struct_name}::{member_name}` was not found",
            ),
        ))?;

        match member_type_var {
            TypeVariant::Array(array_type) => Ok(*array_type.element_count() as usize),

            _ => Err(Error::new(
                ErrorKind::TypeInformationError,
                &format!("Not an array: `{struct_name}::{member_name}`",),
            )),
        }
    }
}
