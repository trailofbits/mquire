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
        entities::boot_time::BootTime, kernel_version::KernelVersion,
        operating_system::LinuxOperatingSystem, virtual_struct::VirtualStruct,
    },
    try_chain,
};

use btfparse::TypeVariant;

impl LinuxOperatingSystem {
    /// Finds the type ID of the tk_core structure based on kernel version
    fn find_tk_core_type_id(&self) -> Result<u32> {
        let kernel_version = self.kernel_version.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kernel version is required but not available",
            )
        })?;

        let (expected_field_list, structure_name) =
            if kernel_version >= &KernelVersion::new(6, 14, 0) {
                // 6.14.0+: tk_data struct with seq, timekeeper, shadow_timekeeper, lock
                (
                    vec!["seq", "timekeeper", "shadow_timekeeper", "lock"],
                    "tk_data struct (6.14.0+)",
                )
            } else if kernel_version >= &KernelVersion::new(6, 8, 0) {
                // 6.8.0-6.13.x: Anonymous struct with seq and timekeeper only
                (
                    vec!["seq", "timekeeper"],
                    "anonymous tk_core struct (6.8.0-6.13.x)",
                )
            } else {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    &format!(
                        "Unsupported kernel version: {}.{}.{}",
                        kernel_version.major, kernel_version.minor, kernel_version.patch
                    ),
                ));
            };

        for (tid, type_variant) in self.kernel_type_info.get() {
            let tid = *tid;

            if let TypeVariant::Struct(struct_type) = type_variant {
                let field_name_list: Vec<String> = struct_type
                    .member_list()
                    .iter()
                    .filter_map(|member| member.name())
                    .collect();

                if field_name_list.len() == expected_field_list.len()
                    && expected_field_list
                        .iter()
                        .all(|field| field_name_list.iter().any(|f| f == field))
                {
                    return Ok(tid);
                }
            }
        }

        Err(Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            &format!("Could not find {} in BTF", structure_name),
        ))
    }

    /// Returns the system boot time
    pub(super) fn get_boot_time_impl(&self) -> Result<Vec<BootTime>> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })?;

        let tk_core_vaddr = kallsyms.get("tk_core").ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate tk_core symbol",
            )
        })?;

        let tk_core_tid = self.find_tk_core_type_id()?;
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let tk_core_struct = VirtualStruct::from_id(
            &vmem_reader,
            &self.kernel_type_info,
            tk_core_tid,
            &tk_core_vaddr,
        )?;

        let timekeeper = tk_core_struct.traverse("timekeeper")?;
        let wall_clock_time = try_chain!(timekeeper.traverse("xtime_sec")?.read_u64())?;
        let time_since_boot = try_chain!(timekeeper.traverse("ktime_sec")?.read_u64())?;

        Ok(vec![BootTime {
            virtual_address: tk_core_vaddr,
            boot_time: wall_clock_time.saturating_sub(time_since_boot),
        }])
    }
}
