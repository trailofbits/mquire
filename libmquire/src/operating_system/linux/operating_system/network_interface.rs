//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::{
        entities::{
            ip_address::IPAddress,
            network_interface::{IPAddressAndMask, NetworkInterface, NetworkMask},
        },
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        virtual_address::VirtualAddress,
    },
    operating_system::linux::{
        operating_system::{utils::get_struct_member_byte_offset, LinuxOperatingSystem},
        virtual_struct::VirtualStruct,
    },
    utils::ip_address::{ipv4_to_string, ipv6_to_string},
};

use {btfparse::TypeInformation, log::debug};

use std::collections::BTreeSet;

/// A reasonable max interface limit to avoid infinite loops
const MAX_INTERFACES: usize = 32;

/// Maximum hardware address length in bytes (MAX_ADDR_LEN)
const MAX_HARDWARE_ADDRESS_LEN: u8 = 32;

impl LinuxOperatingSystem {
    /// Get the list of network interfaces from the kernel
    pub(super) fn get_network_interface_list_impl(&self) -> Result<Vec<NetworkInterface>> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })?;

        let init_net_raw_vaddr = kallsyms.get("init_net").ok_or_else(|| {
            Error::new(
                ErrorKind::EntityNotFound,
                "Failed to find 'init_net' symbol in kallsyms",
            )
        })?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let init_net = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "net",
            &VirtualAddress::new(
                self.init_task_vaddr.root_page_table(),
                init_net_raw_vaddr.value(),
            ),
        )?;

        let dev_base_head = init_net.traverse("dev_base_head")?;

        let dev_base_head_start_vaddr = dev_base_head.traverse("next")?.read_vaddr()?;
        if dev_base_head_start_vaddr.is_null() {
            return Ok(vec![]);
        }

        let net_device_tid = self.kernel_type_info.id_of("net_device").ok_or(Error::new(
            ErrorKind::TypeInformationError,
            "Failed to locate the net_device type",
        ))?;

        // This is a list_head structure, so we need its own offset to navigate the list
        let dev_list_offset =
            get_struct_member_byte_offset(&self.kernel_type_info, net_device_tid, "dev_list")?;

        let netdev_hw_addr_tid =
            self.kernel_type_info
                .id_of("netdev_hw_addr")
                .ok_or(Error::new(
                    ErrorKind::TypeInformationError,
                    "Failed to locate the netdev_hw_addr type",
                ))?;

        let hw_addr_list_offset =
            get_struct_member_byte_offset(&self.kernel_type_info, netdev_hw_addr_tid, "list")?;

        let mut interface_list = Vec::new();
        let mut visited_raw_addresses = BTreeSet::new();
        let mut current_list_entry_vaddr = dev_base_head_start_vaddr;

        while current_list_entry_vaddr != dev_base_head.virtual_address() {
            if interface_list.len() >= MAX_INTERFACES {
                debug!("Reached maximum interface limit of {}", MAX_INTERFACES);
                break;
            }

            if !visited_raw_addresses.insert(current_list_entry_vaddr.value()) {
                debug!("Detected cycle in dev_base_head list");
                break;
            }

            let net_device_vaddr = current_list_entry_vaddr - dev_list_offset;
            let (interface, next_ptr) = match self.read_single_network_interface(
                &vmem_reader,
                &net_device_vaddr,
                hw_addr_list_offset,
            ) {
                Some(result) => result,
                None => {
                    debug!("Failed to read net_device at {:?}", net_device_vaddr);
                    break;
                }
            };

            interface_list.push(interface);
            current_list_entry_vaddr = next_ptr;
        }

        Ok(interface_list)
    }

    /// Returns the interface data and a pointer to the next device in the list
    fn read_single_network_interface(
        &self,
        vmem_reader: &VirtualMemoryReader,
        net_device_vaddr: &VirtualAddress,
        hw_addr_list_offset: u64,
    ) -> Option<(NetworkInterface, VirtualAddress)> {
        let net_device = VirtualStruct::from_name(
            vmem_reader,
            &self.kernel_type_info,
            "net_device",
            net_device_vaddr,
        )
        .ok()?;

        let name = net_device
            .traverse("name")
            .and_then(|field| field.read_string_lossy(Some(16)))
            .ok()
            .filter(|n| !n.is_empty());

        let addr_len = net_device
            .traverse("addr_len")
            .and_then(|field| field.read_u8())
            .unwrap_or(6);

        let active_mac_address =
            read_mac_address_from_pointer(vmem_reader, &net_device, "dev_addr", addr_len);

        let physical_mac_address = read_mac_address_from_array(&net_device, "perm_addr", addr_len);

        let mut additional_mac_addresses = collect_additional_mac_addresses(
            &self.kernel_type_info,
            self.init_task_vaddr.root_page_table(),
            vmem_reader,
            &net_device,
            hw_addr_list_offset,
            addr_len,
        );

        if let Some(ref active_mac) = active_mac_address {
            additional_mac_addresses.retain(|mac| mac != active_mac);
        }

        let state = read_interface_state(&net_device);

        let kernel_page_table = self.init_task_vaddr.root_page_table();

        let mut ip_addresses = collect_ipv4_addresses(
            &self.kernel_type_info,
            kernel_page_table,
            vmem_reader,
            &net_device,
        );

        ip_addresses.extend(collect_ipv6_addresses(
            &self.kernel_type_info,
            kernel_page_table,
            vmem_reader,
            &net_device,
        ));

        let next_entry_vaddr = net_device
            .traverse("dev_list")
            .and_then(|field| field.traverse("next"))
            .and_then(|field| field.read_vaddr())
            .ok()?;

        let interface = NetworkInterface {
            virtual_address: *net_device_vaddr,
            name,
            active_mac_address,
            physical_mac_address,
            additional_mac_addresses,
            ip_addresses,
            state,
        };

        Some((interface, next_entry_vaddr))
    }
}

/// Formats the MAC address bytes as a colon-separated hex string
fn format_mac_address(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > MAX_HARDWARE_ADDRESS_LEN as usize {
        return None;
    }

    if !bytes.iter().any(|&b| b != 0) {
        return None;
    }

    Some(
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Reads a MAC address from a byte pointer field
fn read_mac_address_from_pointer(
    vmem_reader: &VirtualMemoryReader,
    net_device: &VirtualStruct,
    field_name: &str,
    addr_len: u8,
) -> Option<String> {
    if addr_len == 0 || addr_len > MAX_HARDWARE_ADDRESS_LEN {
        return None;
    }

    let ptr = net_device.traverse(field_name).ok()?.read_vaddr().ok()?;
    if ptr.is_null() {
        return None;
    }

    let mut bytes = vec![0u8; addr_len as usize];
    let bytes_read = vmem_reader.read(&mut bytes, ptr).ok()?;
    if bytes_read != addr_len as usize {
        return None;
    }

    format_mac_address(&bytes)
}

/// Read a MAC address from a byte array field
fn read_mac_address_from_array(
    net_device: &VirtualStruct,
    field_name: &str,
    addr_len: u8,
) -> Option<String> {
    if addr_len == 0 || addr_len > MAX_HARDWARE_ADDRESS_LEN {
        return None;
    }

    let field = net_device.traverse(field_name).ok()?;
    let bytes = field.read_bytes(addr_len as usize).ok()?;
    if bytes.len() != addr_len as usize {
        return None;
    }

    format_mac_address(&bytes)
}

/// Reads the interface state from the flags and operstate fields
fn read_interface_state(net_device: &VirtualStruct) -> Option<String> {
    let flags = net_device
        .traverse("flags")
        .and_then(|f| f.read_u32())
        .ok()?;

    let operstate = net_device
        .traverse("operstate")
        .and_then(|f| f.read_u8())
        .ok()?;

    let iff_up = 1u32 << 0;
    let iff_running = 1u32 << 6;
    let if_oper_up = 6u8;

    if (flags & iff_up) != 0 && (flags & iff_running) != 0 && operstate == if_oper_up {
        Some("up".to_string())
    } else {
        Some("down".to_string())
    }
}

/// Returns all the IPv4 addresses and masks of a net_device object
fn collect_ipv4_addresses(
    kernel_type_info: &TypeInformation,
    kernel_page_table: PhysicalAddress,
    vmem_reader: &VirtualMemoryReader,
    net_device: &VirtualStruct,
) -> Vec<IPAddressAndMask> {
    let mut result = Vec::new();

    let ip_ptr_vaddr = match net_device.traverse("ip_ptr").and_then(|f| f.read_vaddr()) {
        Ok(ptr) if !ptr.is_null() => ptr,
        _ => return result,
    };

    let in_device =
        match VirtualStruct::from_name(vmem_reader, kernel_type_info, "in_device", &ip_ptr_vaddr) {
            Ok(dev) => dev,
            Err(_) => return result,
        };

    let mut ifa_ptr = match in_device.traverse("ifa_list").and_then(|f| f.read_vaddr()) {
        Ok(ptr) => ptr,
        Err(_) => return result,
    };

    let mut visited = BTreeSet::new();

    while !ifa_ptr.is_null() && visited.insert(ifa_ptr.value()) {
        let in_ifaddr =
            match VirtualStruct::from_name(vmem_reader, kernel_type_info, "in_ifaddr", &ifa_ptr) {
                Ok(ifa) => ifa,
                Err(err) => {
                    debug!("Failed to read in_ifaddr at {:?}: {err:?}", ifa_ptr);
                    break;
                }
            };

        let address = in_ifaddr
            .traverse("ifa_local")
            .and_then(|f| f.read_u32())
            .ok()
            .and_then(|addr| {
                ipv4_to_string(u32::from_be(addr)).or_else(|| {
                    debug!("Failed to convert IPv4 address to string");
                    None
                })
            });

        let mask = in_ifaddr
            .traverse("ifa_mask")
            .and_then(|f| f.read_u32())
            .ok()
            .and_then(|mask| {
                ipv4_to_string(u32::from_be(mask)).or_else(|| {
                    debug!("Failed to convert IPv4 mask to string");
                    None
                })
            });

        if let (Some(addr), Some(msk)) = (address, mask) {
            result.push(IPAddressAndMask {
                ip_address: IPAddress::IPv4(addr),
                mask: NetworkMask::DottedDecimal(msk),
            });
        }

        ifa_ptr = in_ifaddr
            .traverse("ifa_next")
            .and_then(|f| f.read_vaddr())
            .unwrap_or_else(|_| VirtualAddress::new(kernel_page_table, RawVirtualAddress::new(0)));
    }

    result
}

/// Returns all the IPv6 addresses and prefix lengths of a net_device object
fn collect_ipv6_addresses(
    kernel_type_info: &TypeInformation,
    kernel_page_table: PhysicalAddress,
    vmem_reader: &VirtualMemoryReader,
    net_device: &VirtualStruct,
) -> Vec<IPAddressAndMask> {
    let mut result = Vec::new();

    let ip6_ptr_vaddr = match net_device.traverse("ip6_ptr").and_then(|f| f.read_vaddr()) {
        Ok(ptr) if !ptr.is_null() => ptr,
        _ => return result,
    };

    let inet6_dev = match VirtualStruct::from_name(
        vmem_reader,
        kernel_type_info,
        "inet6_dev",
        &ip6_ptr_vaddr,
    ) {
        Ok(dev) => dev,
        Err(_) => return result,
    };

    let addr_list = match inet6_dev.traverse("addr_list") {
        Ok(al) => al,
        Err(_) => return result,
    };

    let list_head_addr = addr_list.virtual_address().value();
    let start_vaddr = match addr_list.traverse("next").and_then(|f| f.read_vaddr()) {
        Ok(ptr) => ptr,
        Err(_) => return result,
    };

    let inet6_ifaddr_tid = match kernel_type_info.id_of("inet6_ifaddr") {
        Some(tid) => tid,
        None => return result,
    };

    let if_list_offset =
        match get_struct_member_byte_offset(kernel_type_info, inet6_ifaddr_tid, "if_list") {
            Ok(offset) => offset,
            Err(_) => return result,
        };

    let mut current_entry_vaddr = start_vaddr;
    let mut visited_raw_address_set = BTreeSet::new();

    while !current_entry_vaddr.is_null()
        && current_entry_vaddr.value() != list_head_addr
        && visited_raw_address_set.insert(current_entry_vaddr.value())
    {
        let inet6_ifaddr_vaddr = current_entry_vaddr - if_list_offset;

        let inet6_ifaddr = match VirtualStruct::from_name(
            vmem_reader,
            kernel_type_info,
            "inet6_ifaddr",
            &inet6_ifaddr_vaddr,
        ) {
            Ok(ifa) => ifa,
            Err(_) => break,
        };

        let address = inet6_ifaddr
            .traverse("addr")
            .and_then(|addr_struct| addr_struct.read_bytes(16))
            .ok()
            .and_then(|bytes| {
                ipv6_to_string(&bytes).or_else(|| {
                    debug!("Failed to convert IPv6 address to string");
                    None
                })
            });

        let prefix_length = inet6_ifaddr
            .traverse("prefix_len")
            .and_then(|f| f.read_u32())
            .ok();

        if let (Some(addr), Some(prefix_len)) = (address, prefix_length) {
            result.push(IPAddressAndMask {
                ip_address: IPAddress::IPv6(addr),
                mask: NetworkMask::PrefixLength(prefix_len as usize),
            });
        }

        current_entry_vaddr = inet6_ifaddr
            .traverse("if_list")
            .and_then(|f| f.traverse("next"))
            .and_then(|f| f.read_vaddr())
            .unwrap_or_else(|_| VirtualAddress::new(kernel_page_table, RawVirtualAddress::new(0)));
    }

    result
}

/// Collects all the additional MAC addresses from a dev_addrs list
fn collect_additional_mac_addresses(
    kernel_type_info: &TypeInformation,
    kernel_page_table: PhysicalAddress,
    vmem_reader: &VirtualMemoryReader,
    net_device: &VirtualStruct,
    hw_addr_list_offset: u64,
    addr_len: u8,
) -> Vec<String> {
    let mut result = Vec::new();

    let dev_addrs = match net_device.traverse("dev_addrs") {
        Ok(dev_addrs) => dev_addrs,
        Err(_) => return result,
    };

    let list_head = match dev_addrs.traverse("list") {
        Ok(list_head) => list_head,
        Err(_) => return result,
    };

    let list_head_addr = list_head.virtual_address().value();
    let start_vaddr = match list_head.traverse("next").and_then(|f| f.read_vaddr()) {
        Ok(start_vaddr) => start_vaddr,
        Err(_) => return result,
    };

    let mut current_entry_vaddr = start_vaddr;
    let mut visited_raw_address_set = BTreeSet::new();

    while !current_entry_vaddr.is_null()
        && current_entry_vaddr.value() != list_head_addr
        && visited_raw_address_set.insert(current_entry_vaddr.value())
    {
        let hw_addr_vaddr = current_entry_vaddr - hw_addr_list_offset;

        let hw_addr = match VirtualStruct::from_name(
            vmem_reader,
            kernel_type_info,
            "netdev_hw_addr",
            &hw_addr_vaddr,
        ) {
            Ok(ha) => ha,
            Err(_) => break,
        };

        if let Some(mac) = read_mac_address_from_array(&hw_addr, "addr", addr_len) {
            result.push(mac);
        }

        current_entry_vaddr = hw_addr
            .traverse("list")
            .and_then(|f| f.traverse("next"))
            .and_then(|f| f.read_vaddr())
            .unwrap_or_else(|_| VirtualAddress::new(kernel_page_table, RawVirtualAddress::new(0)));
    }

    result
}
