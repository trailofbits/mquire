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
    memory::{readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        entities::kernel_module::{KernelModule, KernelModuleParam, KernelModuleState},
        list::{List, ListValue},
        operating_system::LinuxOperatingSystem,
        virtual_struct::VirtualStruct,
    },
};

use {btfparse::TypeInformation, log::debug};

impl LinuxOperatingSystem {
    /// Returns the list of loaded kernel modules
    pub(super) fn get_kernel_module_list_impl(&self) -> Result<Vec<KernelModule>> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })?;

        let modules_vaddr = kallsyms
            .get("modules")
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "Failed to locate 'modules' symbol in kallsyms",
                )
            })
            .inspect_err(|err| debug!("{err:?}"))?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let modules_list_head = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "list_head",
            &modules_vaddr,
        )
        .inspect_err(|err| debug!("{err:?}"))?;

        let first_module_list_vaddr = modules_list_head
            .traverse("next")
            .and_then(|f| f.read_vaddr())
            .inspect_err(|err| debug!("{err:?}"))?;

        if first_module_list_vaddr == modules_vaddr {
            debug!("[kernel_module] Module list is empty");
            return Ok(Vec::new());
        }

        let module_list = List::<KernelModule>::builder()
            .doubly_linked()
            .container("module")
            .node_path(&["list"])
            .parse(
                self.memory_dump.as_ref(),
                self.architecture.as_ref(),
                &self.kernel_type_info,
                first_module_list_vaddr,
                self.init_task_vaddr.root_page_table(),
            )
            .inspect_err(|err| debug!("{err:?}"))?;

        Ok(module_list.into_iter().collect())
    }
}

impl ListValue for KernelModule {
    fn from_vaddr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        module_vaddr: VirtualAddress,
    ) -> Result<Self> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);
        let module_struct =
            VirtualStruct::from_name(&vmem_reader, type_information, "module", &module_vaddr)?;

        parse_kernel_module(&vmem_reader, type_information, &module_struct)
    }
}

/// Parses a `struct module` kernel object
fn parse_kernel_module(
    vmem_reader: &VirtualMemoryReader,
    type_information: &TypeInformation,
    module_struct: &VirtualStruct,
) -> Result<KernelModule> {
    let name = module_struct
        .traverse("name")
        .and_then(|f| f.read_string_lossy(Some(56)))
        .ok();

    let state = module_struct
        .traverse("state")
        .and_then(|f| f.read_u32())
        .ok()
        .and_then(|state_val| match state_val {
            0 => Some(KernelModuleState::Live),
            1 => Some(KernelModuleState::Coming),
            2 => Some(KernelModuleState::Going),
            3 => Some(KernelModuleState::Unformed),
            _ => None,
        });

    let version = module_struct
        .traverse("version")
        .and_then(|f| f.dereference())
        .and_then(|f| f.read_string_lossy(None))
        .ok();

    let src_version = module_struct
        .traverse("srcversion")
        .and_then(|f| f.dereference())
        .and_then(|f| f.read_string_lossy(None))
        .ok();

    let taints = module_struct
        .traverse("taints")
        .and_then(|f| f.read_u64())
        .ok();

    let using_gpl_only_symbols = module_struct
        .traverse("using_gplonly_symbols")
        .and_then(|f| f.read_u8())
        .ok()
        .map(|v| v != 0);

    let parameter_list =
        parse_module_parameters(vmem_reader, type_information, module_struct).unwrap_or_default();

    Ok(KernelModule {
        virtual_address: module_struct.virtual_address(),
        name,
        version,
        src_version,
        taints,
        using_gpl_only_symbols,
        state,
        parameter_list,
    })
}

/// Parses module parameters from the kernel_param array
fn parse_module_parameters(
    vmem_reader: &VirtualMemoryReader,
    type_information: &TypeInformation,
    module_struct: &VirtualStruct,
) -> Result<Vec<KernelModuleParam>> {
    let num_kp = module_struct
        .traverse("num_kp")
        .and_then(|f| f.read_u32())?;

    if num_kp == 0 {
        return Ok(Vec::new());
    }

    let kp_vaddr = module_struct.traverse("kp")?.read_vaddr()?;
    if kp_vaddr.is_null() {
        return Ok(Vec::new());
    }

    let kernel_param_size =
        type_information.size_of(type_information.id_of("kernel_param").ok_or_else(|| {
            Error::new(
                ErrorKind::TypeInformationError,
                "Failed to find kernel_param type",
            )
        })?)?;

    let mut parameters = Vec::new();

    for i in 0..num_kp {
        let param_vaddr = kp_vaddr + (i as u64 * kernel_param_size as u64);

        let param = match parse_kernel_param(vmem_reader, type_information, param_vaddr) {
            Ok(p) => p,

            Err(err) => {
                debug!("Failed to parse kernel param at {}: {err:?}", param_vaddr);
                continue;
            }
        };

        parameters.push(param);
    }

    Ok(parameters)
}

/// Parses a single kernel_param structure
fn parse_kernel_param(
    vmem_reader: &VirtualMemoryReader,
    type_information: &TypeInformation,
    param_vaddr: VirtualAddress,
) -> Result<KernelModuleParam> {
    let param_struct =
        VirtualStruct::from_name(vmem_reader, type_information, "kernel_param", &param_vaddr)?;

    let name = param_struct
        .traverse("name")
        .and_then(|f| f.dereference())
        .and_then(|f| f.read_string_lossy(None))
        .ok();

    let permissions = param_struct
        .traverse("perm")
        .and_then(|f| f.read_u16())
        .ok();

    let flags = param_struct
        .traverse("flags")
        .and_then(|f| f.read_u8())
        .ok();

    Ok(KernelModuleParam {
        virtual_address: param_vaddr,
        name,
        permissions,
        flags,
    })
}
