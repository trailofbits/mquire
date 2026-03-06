//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

mod boot_time;
mod dmesg;
mod file;
mod kallsyms_symbol;
mod kernel_module;
mod memory_mapping;
mod network_connection;
mod network_interface;
mod readable_file_linux_object;
mod syslog_file;
mod system_information;
mod task;

use crate::{
    core::{
        architecture::{Architecture, Endianness},
        entities::{
            network_interface::NetworkInterface, system_information::SystemInformation,
            system_version::SystemVersion,
        },
        error::{Error, ErrorKind, Result},
        operating_system::OperatingSystem,
        virtual_memory_reader::VirtualMemoryReader,
    },
    generate_address_ranges,
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    operating_system::linux::{
        btf::BtfparseReadableAdapter,
        entities::{
            boot_time::BootTime, kernel_module::KernelModule, network_connection::Protocol,
            task::Task,
        },
        kallsyms::Kallsyms,
        kernel_version::KernelVersion,
        operating_system::{
            dmesg::DmesgEntryIterator,
            file::TaskOpenFilesIterator,
            kallsyms_symbol::KallsymsSymbolIterator,
            kernel_module::KernelModuleIterator,
            memory_mapping::MemoryMappingIterator,
            network_connection::NetworkConnectionIterator,
            network_interface::NetworkInterfaceIterator,
            readable_file_linux_object::ReadableLinuxFileObject,
            syslog_file::SyslogFileIterator,
            task::{PidNsTaskIterator, TaskIterator},
        },
        task_struct_iterator::TaskStructIterator,
        utils::get_struct_member_byte_offset,
        virtual_struct::VirtualStruct,
    },
    try_chain,
    utils::reader::Reader,
};

use {
    btfparse::{Error as BtfparseError, TypeInformation},
    log::debug,
    rayon::prelude::*,
};

use std::sync::Arc;

/// Buffer size used for initial data discovery
const SCAN_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Swapper process comm string
const SWAPPER_PROCESS_COMM: &str = "swapper/0";

/// BTF signature for little endian machines
const BTF_LITTLE_ENDIAN_SIGNATURE: [u8; 3] = [
    0x9F, 0xEB, // Magic number
    0x01, // Version
];

/// The physical and virtual address of a swapper task_struct candidate
struct SwapperLocation {
    /// The physical address of the swapper task_struct in the memory dump
    physical_address: PhysicalAddress,

    /// The raw virtual address of the swapper task_struct
    raw_virtual_address: RawVirtualAddress,
}

/// Implements the OperatingSystem trait for Linux
pub struct LinuxOperatingSystem {
    /// The memory dump
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel debug symbols
    kernel_type_info: TypeInformation,

    /// The virtual address of the init task
    init_task_vaddr: VirtualAddress,

    /// The kernel symbol table
    kallsyms: Option<Kallsyms>,

    /// The kernel version
    kernel_version: Option<KernelVersion>,
}

impl LinuxOperatingSystem {
    /// Creates a new `LinuxOperatingSystem` instance
    pub fn new(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
    ) -> Result<Arc<Self>> {
        let kernel_type_info = Self::get_kernel_type_info(memory_dump.as_ref())
            .inspect_err(|err| debug!("{err:?}"))?;

        let init_task_vaddr = Self::get_init_task_vaddr(
            memory_dump.clone(),
            architecture.clone(),
            &kernel_type_info,
        )?;

        let system_version = Self::get_system_version(
            memory_dump.as_ref(),
            architecture.as_ref(),
            &kernel_type_info,
            &init_task_vaddr,
        )?;

        let kernel_version: Option<KernelVersion> = system_version
            .kernel_version
            .and_then(|version_string| version_string.parse().ok());

        let kallsyms = Kallsyms::new(
            memory_dump.as_ref(),
            architecture.as_ref(),
            init_task_vaddr.root_page_table(),
            &kernel_version,
        )
        .inspect_err(|err| debug!("{err:?}"))
        .ok();

        Ok(Arc::new(Self {
            memory_dump,
            architecture,
            kernel_type_info,
            init_task_vaddr,
            kallsyms,
            kernel_version,
        }))
    }

    /// Returns a task at the given virtual address
    pub fn task_at(&self, vaddr: VirtualAddress) -> Result<Task> {
        self.task_at_impl(vaddr)
    }

    /// Returns an iterator over all tasks starting from init_task
    pub fn iter_tasks(&self) -> Result<TaskIterator<'_>> {
        self.iter_tasks_impl()
    }

    /// Returns an iterator over tasks starting from a custom root
    pub fn iter_tasks_from(&self, root: VirtualAddress) -> Result<TaskIterator<'_>> {
        self.iter_tasks_from_impl(root)
    }

    /// Returns an iterator over the init_pid_ns namespace
    pub fn iter_pid_ns_tasks(&self) -> Result<PidNsTaskIterator<'_>> {
        self.iter_pid_ns_tasks_impl()
    }

    /// Returns an iterator over the specified pid_namespace
    pub fn iter_pid_ns_tasks_at(&self, pid_ns: VirtualAddress) -> Result<PidNsTaskIterator<'_>> {
        self.iter_pid_ns_tasks_at_impl(pid_ns)
    }

    /// Returns an iterator over open files for a single task
    pub fn iter_task_open_files(
        &self,
        task_vaddr: VirtualAddress,
    ) -> Result<TaskOpenFilesIterator<'_>> {
        self.iter_task_open_files_impl(task_vaddr)
    }

    /// Returns an iterator over memory mappings for a single task
    pub fn iter_task_memory_mappings(
        &self,
        task_vaddr: VirtualAddress,
    ) -> Result<MemoryMappingIterator<'_>> {
        self.iter_task_memory_mappings_impl(task_vaddr)
    }

    /// Returns an iterator over syslog file regions from memory
    pub fn iter_syslog_file_regions(&self) -> Result<SyslogFileIterator<'_>> {
        self.iter_syslog_file_regions_impl()
    }

    /// Returns an iterator over kernel log messages (dmesg) from the printk_ringbuffer
    pub fn iter_dmesg_entries(&self) -> Result<DmesgEntryIterator<'_>> {
        self.iter_dmesg_entries_impl()
    }

    /// Returns an iterator over kernel symbols from kallsyms
    pub fn iter_kallsyms_symbols(&self) -> Result<KallsymsSymbolIterator> {
        self.iter_kallsyms_symbols_impl()
    }

    /// Returns the system boot time
    pub fn get_boot_time(&self) -> Result<BootTime> {
        self.get_boot_time_impl()
    }

    /// Returns an iterator over network connections filtered by protocol
    ///
    /// If `protocol_filter` is empty, all protocols are included.
    pub fn iter_network_connections(
        &self,
        protocol_filter: &[Protocol],
    ) -> Result<NetworkConnectionIterator<'_>> {
        self.iter_network_connections_impl(protocol_filter)
    }

    /// Returns a kernel module at the given virtual address
    pub fn kernel_module_at(&self, vaddr: VirtualAddress) -> Result<KernelModule> {
        self.kernel_module_at_impl(vaddr)
    }

    /// Returns an iterator over loaded kernel modules starting from the default list head
    pub fn iter_kernel_modules(&self) -> Result<KernelModuleIterator> {
        self.iter_kernel_modules_impl()
    }

    /// Returns an iterator over loaded kernel modules starting from the given list head
    pub fn iter_kernel_modules_from(
        &self,
        list_head_vaddr: VirtualAddress,
    ) -> Result<KernelModuleIterator> {
        self.iter_kernel_modules_from_impl(list_head_vaddr)
    }

    /// Returns a network interface at the given virtual address
    pub fn network_interface_at(&self, vaddr: VirtualAddress) -> Result<NetworkInterface> {
        self.network_interface_at_impl(vaddr)
    }

    /// Returns an iterator over network interfaces starting from the kernel's net device list
    pub fn iter_network_interfaces(&self) -> Result<NetworkInterfaceIterator<'_>> {
        self.iter_network_interfaces_impl()
    }

    /// Returns an iterator over network interfaces starting from a custom list head
    pub fn iter_network_interfaces_from(
        &self,
        list_head_vaddr: VirtualAddress,
    ) -> Result<NetworkInterfaceIterator<'_>> {
        self.iter_network_interfaces_from_impl(list_head_vaddr)
    }

    /// Scans the given `Readable` object for the kernel BTF debug symbols
    fn get_kernel_type_info(readable: &dyn Readable) -> Result<TypeInformation> {
        let regions = readable.regions()?;

        regions
            .par_iter()
            .find_map_any(|region| {
                let mut read_buffer = vec![0u8; SCAN_BUFFER_SIZE];

                for range in generate_address_ranges!(
                    region.start,
                    region.end,
                    read_buffer.len(),
                    BTF_LITTLE_ENDIAN_SIGNATURE.len()
                ) {
                    let bytes_read =
                        if let Ok(bytes_read) = readable.read(&mut read_buffer, range.start) {
                            bytes_read
                        } else {
                            debug!("Failed to read buffer during BTF scan at {:?}", range.start);
                            continue;
                        };

                    for offset in read_buffer[..bytes_read]
                        .windows(BTF_LITTLE_ENDIAN_SIGNATURE.len())
                        .enumerate()
                        .filter_map(|(offset, window)| {
                            if window == BTF_LITTLE_ENDIAN_SIGNATURE {
                                Some(offset)
                            } else {
                                None
                            }
                        })
                    {
                        let btf_offset = range.start + (offset as u64);
                        let readable_adapter =
                            BtfparseReadableAdapter::new(readable, btf_offset.value());

                        let type_information =
                            if let Ok(type_information) = TypeInformation::new(&readable_adapter) {
                                type_information
                            } else {
                                debug!("Failed to parse BTF data at offset {}", btf_offset);
                                continue;
                            };

                        if type_information.id_of("task_struct").is_some() {
                            debug!("BTF data found at offset {btf_offset}");
                            return Some(type_information);
                        }
                    }
                }

                None
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "Failed to locate the BTF debug symbols",
                )
            })
    }

    /// Returns the location of the swapper task_struct
    fn iter_swapper_struct_locations(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kernel_type_info: &TypeInformation,
    ) -> Result<Box<dyn Iterator<Item = SwapperLocation>>> {
        // Propagate type errors to the caller, since there's nothing we can do about them
        let task_struct_tid = kernel_type_info.id_of("task_struct").ok_or(Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            "Failed to locate the task_struct type",
        ))?;

        let comm_offset = get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "comm")?;

        let parent_offset =
            get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "parent")?;

        let real_parent_offset =
            get_struct_member_byte_offset(kernel_type_info, task_struct_tid, "real_parent")?;

        let task_struct_size = kernel_type_info.size_of(task_struct_tid)?;
        let regions = readable.regions()?;

        let candidates: Vec<SwapperLocation> = regions
            .par_iter()
            .flat_map_iter(|region| {
                let reader = Reader::new(readable, architecture.endianness() == Endianness::Little);
                let mut read_buffer = vec![0u8; SCAN_BUFFER_SIZE];
                let mut matches = Vec::new();

                for range in generate_address_ranges!(
                    region.start,
                    region.end,
                    read_buffer.len(),
                    task_struct_size
                ) {
                    let read_size = if let Ok(read_size) = readable.read(&mut read_buffer, range.start) {
                        read_size
                    } else {
                        debug!("Failed to read buffer during swapper scan at {:?}", range.start);
                        continue;
                    };

                    if read_size < SWAPPER_PROCESS_COMM.len() {
                        debug!("Read size {} too small for swapper comm", read_size);
                        continue;
                    }

                    for offset in read_buffer[..read_size]
                        .windows(SWAPPER_PROCESS_COMM.len())
                        .enumerate()
                        .filter_map(|(offset, window)| {
                            if window == SWAPPER_PROCESS_COMM.as_bytes() {
                                Some(offset)
                            } else {
                                None
                            }
                        })
                    {
                        let swapper_comm_physical_address = range.start + (offset as u64);
                        let swapper_task_physical_address = swapper_comm_physical_address - comm_offset;

                        let swapper_struct_parent_field =
                            match reader.read_u64(swapper_task_physical_address + parent_offset) {
                                Ok(value) => value,
                                Err(e) => {
                                    debug!("Failed to read parent field: {:?}", e);
                                    continue;
                                }
                            };

                        let swapper_struct_real_parent_field =
                            match reader.read_u64(swapper_task_physical_address + real_parent_offset) {
                                Ok(value) => value,
                                Err(e) => {
                                    debug!("Failed to read real_parent field: {:?}", e);
                                    continue;
                                }
                            };

                        let swapper_struct_raw_vaddr =
                            if swapper_struct_parent_field == swapper_struct_real_parent_field {
                                RawVirtualAddress::new(swapper_struct_parent_field)
                            } else {
                                debug!(
                                    "Parent fields mismatch: {} != {}",
                                    swapper_struct_parent_field, swapper_struct_real_parent_field
                                );
                                continue;
                            };

                        debug!("Swapper struct located: {swapper_task_physical_address} => {swapper_struct_raw_vaddr}");
                        matches.push(SwapperLocation {
                            physical_address: swapper_task_physical_address,
                            raw_virtual_address: swapper_struct_raw_vaddr,
                        });
                    }
                }

                matches
            })
            .collect();

        debug!("Found {} swapper candidate(s)", candidates.len());
        Ok(Box::new(candidates.into_iter()))
    }

    /// Attempts to resolve the init task virtual address using a specific page table candidate
    fn try_resolve_init_task(
        memory_dump: &Arc<dyn Readable>,
        architecture: &Arc<dyn Architecture>,
        kernel_type_info: &TypeInformation,
        discovered_page_table: PhysicalAddress,
        swapper_raw_vaddr: RawVirtualAddress,
    ) -> Result<VirtualAddress> {
        let vmem_reader = VirtualMemoryReader::new(memory_dump.as_ref(), architecture.as_ref());

        let swapper_vaddr = VirtualAddress::new(discovered_page_table, swapper_raw_vaddr);

        let swapper_struct = VirtualStruct::from_name(
            &vmem_reader,
            kernel_type_info,
            "task_struct",
            &swapper_vaddr,
        )?;

        // The page table we have now might not be accurate. Before we start scanning for the
        // init task, let's move to the page table in active_mm object of the swapper task_struct.
        let swapper_pgd_vaddr = swapper_struct
            .traverse("active_mm")?
            .dereference()?
            .traverse("pgd")?
            .read_vaddr()?;

        let swapper_pgd_phys =
            architecture.translate_virtual_address(memory_dump.as_ref(), swapper_pgd_vaddr)?;

        let swapper_page_table = swapper_pgd_phys.address();

        // Attempt to look for the init task now, using the new root page table
        let mut task_iter = TaskStructIterator::new(
            memory_dump.clone(),
            architecture.clone(),
            kernel_type_info,
            VirtualAddress::new(swapper_page_table, swapper_raw_vaddr),
        )?;

        task_iter
            .find_map(|task_vaddr| {
                let task_struct = VirtualStruct::from_name(
                    &vmem_reader,
                    kernel_type_info,
                    "task_struct",
                    &task_vaddr,
                )
                .ok()?;

                if let Ok(pid) = try_chain!(task_struct.traverse("tgid")?.read_u32()) {
                    if pid == 1 { Some(task_vaddr) } else { None }
                } else {
                    None
                }
            })
            .ok_or(Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Failed to locate the init task struct",
            ))
    }

    /// Returns the virtual address of the swapper task_struct
    fn get_init_task_vaddr(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        kernel_type_info: &TypeInformation,
    ) -> Result<VirtualAddress> {
        let swapper_candidates = Self::iter_swapper_struct_locations(
            memory_dump.as_ref(),
            architecture.as_ref(),
            kernel_type_info,
        )?;

        for swapper in swapper_candidates {
            let page_table_candidates = match architecture.iter_page_table_candidates(
                memory_dump.as_ref(),
                swapper.physical_address,
                swapper.raw_virtual_address,
            ) {
                Ok(candidates) => candidates,

                Err(e) => {
                    debug!(
                        "Failed to scan page tables for swapper at {} => {}: {e:?}",
                        swapper.physical_address, swapper.raw_virtual_address,
                    );

                    continue;
                }
            };

            for discovered_page_table in page_table_candidates {
                debug!("Trying page table candidate: {discovered_page_table}");

                match Self::try_resolve_init_task(
                    &memory_dump,
                    &architecture,
                    kernel_type_info,
                    discovered_page_table,
                    swapper.raw_virtual_address,
                ) {
                    Ok(init_task_vaddr) => return Ok(init_task_vaddr),

                    Err(e) => {
                        debug!("Page table candidate {discovered_page_table} failed: {e:?}");
                        continue;
                    }
                }
            }
        }

        Err(Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            "Failed to locate the init task struct",
        ))
    }
}

impl OperatingSystem for LinuxOperatingSystem {
    fn get_os_version(&self) -> Result<SystemVersion> {
        Self::get_system_version(
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            &self.kernel_type_info,
            &self.init_task_vaddr,
        )
    }

    fn get_system_information(&self) -> Result<SystemInformation> {
        self.get_system_information_impl()
    }

    fn iter_network_interfaces(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<NetworkInterface>> + '_>> {
        Ok(Box::new(self.iter_network_interfaces_impl()?))
    }

    fn get_file_reader(&self, file: VirtualAddress) -> Result<Arc<dyn Readable>> {
        let kallsyms = match self.kallsyms {
            Some(ref kallsyms) => kallsyms,
            None => {
                return Err(Error::new(
                    ErrorKind::OperatingSystemInitializationFailed,
                    "Kallsyms not initialized",
                ));
            }
        };

        ReadableLinuxFileObject::from_file_vaddr(
            self.memory_dump.clone(),
            self.architecture.clone(),
            &self.kernel_type_info,
            kallsyms,
            file,
        )
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
}

impl From<BtfparseError> for Error {
    /// Converts a btfparse error into a System error
    fn from(error: BtfparseError) -> Self {
        Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            &format!("btfparse has returned the following error: {error:?}"),
        )
    }
}
