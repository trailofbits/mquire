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
        entities::{
            ip_address::IPAddress,
            network_interface::{IPAddressAndMask, NetworkInterface, NetworkMask},
        },
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{
        primitives::{PhysicalAddress, RawVirtualAddress},
        readable::Readable,
        virtual_address::VirtualAddress,
    },
    operating_system::linux::{
        operating_system::LinuxOperatingSystem, utils::get_struct_member_byte_offset,
        virtual_struct::VirtualStruct,
    },
    utils::ip_address::{ipv4_to_string, ipv6_to_string},
};

use {btfparse::TypeInformation, log::debug, std::sync::Arc};

use std::collections::BTreeSet;

/// A reasonable max interface limit to avoid infinite loops
const MAX_INTERFACES: usize = 32;

/// Maximum hardware address length in bytes (MAX_ADDR_LEN)
const MAX_HARDWARE_ADDRESS_LEN: u8 = 32;

/// Maximum interface name length (IFNAMSIZ)
const MAX_INTERFACE_NAME_LEN: usize = 16;

/// Default hardware address length for Ethernet (ETH_ALEN)
const DEFAULT_HARDWARE_ADDRESS_LEN: u8 = 6;

/// Size of an IPv6 address in bytes
const IPV6_ADDRESS_SIZE: usize = 16;

/// Interface flag: interface is up (IFF_UP)
const IFF_UP: u32 = 1 << 0;

/// Interface flag: interface is running (IFF_RUNNING)
const IFF_RUNNING: u32 = 1 << 6;

/// Interface operational state: up (IF_OPER_UP)
const IF_OPER_UP: u8 = 6;

/// Lazy iterator over network interfaces
pub struct NetworkInterfaceIterator<'a> {
    /// The memory dump
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel debug symbols
    kernel_type_info: &'a TypeInformation,

    /// The kernel page table
    kernel_page_table: PhysicalAddress,

    /// The list head virtual address
    list_head_vaddr: VirtualAddress,

    /// Current list entry virtual address
    current_entry_vaddr: VirtualAddress,

    /// Offset of dev_list within net_device struct
    dev_list_offset: u64,

    /// Offset of list within netdev_hw_addr struct
    hw_addr_list_offset: u64,

    /// Visited addresses to detect cycles
    visited: BTreeSet<RawVirtualAddress>,

    /// Number of interfaces iterated so far
    iteration_count: usize,
}

impl<'a> NetworkInterfaceIterator<'a> {
    /// Returns the virtual address of the list head used for iteration
    pub fn list_head(&self) -> VirtualAddress {
        self.list_head_vaddr
    }
}

impl Iterator for NetworkInterfaceIterator<'_> {
    type Item = Result<NetworkInterface>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_entry_vaddr == self.list_head_vaddr {
            return None;
        }

        if self.iteration_count >= MAX_INTERFACES {
            debug!("Reached maximum interface limit of {}", MAX_INTERFACES);
            return None;
        }

        if !self.visited.insert(self.current_entry_vaddr.value()) {
            debug!("Detected cycle in dev_base_head list");
            return None;
        }

        self.iteration_count += 1;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let net_device_vaddr = self.current_entry_vaddr - self.dev_list_offset;

        let result = parse_network_interface(
            &vmem_reader,
            self.kernel_type_info,
            self.kernel_page_table,
            &net_device_vaddr,
            self.hw_addr_list_offset,
        );

        match result {
            Ok(parsed) => {
                self.current_entry_vaddr = parsed.next_entry_vaddr;
                Some(Ok(parsed.interface))
            }

            Err(err) => Some(Err(err)),
        }
    }
}

impl LinuxOperatingSystem {
    /// Returns a network interface at the given virtual address
    pub(super) fn network_interface_at_impl(
        &self,
        vaddr: VirtualAddress,
    ) -> Result<NetworkInterface> {
        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let netdev_hw_addr_tid =
            self.kernel_type_info
                .id_of("netdev_hw_addr")
                .ok_or(Error::new(
                    ErrorKind::TypeInformationError,
                    "Failed to locate the netdev_hw_addr type",
                ))?;

        let hw_addr_list_offset =
            get_struct_member_byte_offset(&self.kernel_type_info, netdev_hw_addr_tid, "list")?;

        let parsed = parse_network_interface(
            &vmem_reader,
            &self.kernel_type_info,
            self.init_task_vaddr.root_page_table(),
            &vaddr,
            hw_addr_list_offset,
        )?;

        Ok(parsed.interface)
    }

    /// Returns an iterator over network interfaces
    pub(super) fn iter_network_interfaces_impl(&self) -> Result<NetworkInterfaceIterator<'_>> {
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

        let kernel_page_table = self.init_task_vaddr.root_page_table();

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let init_net = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "net",
            &VirtualAddress::new(kernel_page_table, init_net_raw_vaddr.value()),
        )?;

        let dev_base_head_vaddr = init_net.traverse("dev_base_head")?.virtual_address();
        self.iter_network_interfaces_from_impl(dev_base_head_vaddr)
    }

    /// Returns an iterator over network interfaces starting from a custom list head
    pub(super) fn iter_network_interfaces_from_impl(
        &self,
        list_head_vaddr: VirtualAddress,
    ) -> Result<NetworkInterfaceIterator<'_>> {
        let kernel_page_table = self.init_task_vaddr.root_page_table();

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let list_head = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "list_head",
            &list_head_vaddr,
        )?;

        let first_entry_vaddr = list_head.traverse("next")?.read_vaddr()?;

        let net_device_tid = self.kernel_type_info.id_of("net_device").ok_or(Error::new(
            ErrorKind::TypeInformationError,
            "Failed to locate the net_device type",
        ))?;

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

        Ok(NetworkInterfaceIterator {
            memory_dump: self.memory_dump.clone(),
            architecture: self.architecture.clone(),
            kernel_type_info: &self.kernel_type_info,
            kernel_page_table,
            list_head_vaddr,
            current_entry_vaddr: first_entry_vaddr,
            dev_list_offset,
            hw_addr_list_offset,
            visited: BTreeSet::new(),
            iteration_count: 0,
        })
    }
}

/// Result of parsing a single network interface
struct ParsedNetworkInterface {
    /// The parsed network interface
    interface: NetworkInterface,

    /// Virtual address of the next entry in the list
    next_entry_vaddr: VirtualAddress,
}

/// Parses a single network interface from a net_device virtual address
fn parse_network_interface(
    vmem_reader: &VirtualMemoryReader,
    kernel_type_info: &TypeInformation,
    kernel_page_table: PhysicalAddress,
    net_device_vaddr: &VirtualAddress,
    hw_addr_list_offset: u64,
) -> Result<ParsedNetworkInterface> {
    let net_device = VirtualStruct::from_name(
        vmem_reader,
        kernel_type_info,
        "net_device",
        net_device_vaddr,
    )?;

    let name = net_device
        .traverse("name")
        .and_then(|field| field.read_string_lossy(Some(MAX_INTERFACE_NAME_LEN)))
        .ok()
        .filter(|n| !n.is_empty());

    let addr_len = net_device
        .traverse("addr_len")
        .and_then(|field| field.read_u8())
        .unwrap_or(DEFAULT_HARDWARE_ADDRESS_LEN);

    let active_mac_address =
        read_mac_address_from_pointer(vmem_reader, &net_device, "dev_addr", addr_len);

    let physical_mac_address = read_mac_address_from_array(&net_device, "perm_addr", addr_len);

    let mut additional_mac_addresses = collect_additional_mac_addresses(
        kernel_type_info,
        kernel_page_table,
        vmem_reader,
        &net_device,
        hw_addr_list_offset,
        addr_len,
    );

    if let Some(ref active_mac) = active_mac_address {
        additional_mac_addresses.retain(|mac| mac != active_mac);
    }

    let state = read_interface_state(&net_device);

    let mut ip_addresses = collect_ipv4_addresses(
        kernel_type_info,
        kernel_page_table,
        vmem_reader,
        &net_device,
    );

    ip_addresses.extend(collect_ipv6_addresses(
        kernel_type_info,
        kernel_page_table,
        vmem_reader,
        &net_device,
    ));

    let next_entry_vaddr = net_device
        .traverse("dev_list")
        .and_then(|field| field.traverse("next"))
        .and_then(|field| field.read_vaddr())?;

    Ok(ParsedNetworkInterface {
        interface: NetworkInterface {
            virtual_address: *net_device_vaddr,
            name,
            active_mac_address,
            physical_mac_address,
            additional_mac_addresses,
            ip_addresses,
            state,
        },
        next_entry_vaddr,
    })
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

    if (flags & IFF_UP) != 0 && (flags & IFF_RUNNING) != 0 && operstate == IF_OPER_UP {
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
    let mut address_list = Vec::new();

    let ip_ptr_vaddr = match net_device.traverse("ip_ptr").and_then(|f| f.read_vaddr()) {
        Ok(ptr) if !ptr.is_null() => ptr,
        _ => return address_list,
    };

    let in_device =
        match VirtualStruct::from_name(vmem_reader, kernel_type_info, "in_device", &ip_ptr_vaddr) {
            Ok(in_device) => in_device,

            Err(err) => {
                log::error!(
                    "Failed to read in_device at {:?}: {err:?}. \
                     This may indicate an unsupported kernel version.",
                    ip_ptr_vaddr
                );

                return address_list;
            }
        };

    let mut ifa_ptr = match in_device.traverse("ifa_list").and_then(|f| f.read_vaddr()) {
        Ok(ptr) => ptr,
        Err(_) => return address_list,
    };

    let mut visited = BTreeSet::new();

    while !ifa_ptr.is_null() && visited.insert(ifa_ptr.value()) {
        let in_ifaddr =
            match VirtualStruct::from_name(vmem_reader, kernel_type_info, "in_ifaddr", &ifa_ptr) {
                Ok(in_ifaddr) => in_ifaddr,

                Err(err) => {
                    log::error!(
                        "Failed to read in_ifaddr at {:?}: {err:?}. \
                         This may indicate an unsupported kernel version.",
                        ifa_ptr
                    );

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
            address_list.push(IPAddressAndMask {
                ip_address: IPAddress::IPv4(addr),
                mask: NetworkMask::DottedDecimal(msk),
            });
        }

        ifa_ptr = in_ifaddr
            .traverse("ifa_next")
            .and_then(|f| f.read_vaddr())
            .unwrap_or_else(|_| VirtualAddress::new(kernel_page_table, RawVirtualAddress::new(0)));
    }

    address_list
}

/// Returns all the IPv6 addresses and prefix lengths of a net_device object
fn collect_ipv6_addresses(
    kernel_type_info: &TypeInformation,
    kernel_page_table: PhysicalAddress,
    vmem_reader: &VirtualMemoryReader,
    net_device: &VirtualStruct,
) -> Vec<IPAddressAndMask> {
    let mut address_list = Vec::new();

    let ip6_ptr_vaddr = match net_device.traverse("ip6_ptr").and_then(|f| f.read_vaddr()) {
        Ok(ptr) if !ptr.is_null() => ptr,
        _ => return address_list,
    };

    let inet6_dev = match VirtualStruct::from_name(
        vmem_reader,
        kernel_type_info,
        "inet6_dev",
        &ip6_ptr_vaddr,
    ) {
        Ok(inet6_dev) => inet6_dev,

        Err(err) => {
            log::error!(
                "Failed to read inet6_dev at {:?}: {err:?}. \
                 This may indicate an unsupported kernel version.",
                ip6_ptr_vaddr
            );

            return address_list;
        }
    };

    let addr_list = match inet6_dev.traverse("addr_list") {
        Ok(al) => al,
        Err(_) => return address_list,
    };

    let list_head_addr = addr_list.virtual_address().value();
    let start_vaddr = match addr_list.traverse("next").and_then(|f| f.read_vaddr()) {
        Ok(ptr) => ptr,
        Err(_) => return address_list,
    };

    let inet6_ifaddr_tid = match kernel_type_info.id_of("inet6_ifaddr") {
        Some(tid) => tid,
        None => return address_list,
    };

    let if_list_offset =
        match get_struct_member_byte_offset(kernel_type_info, inet6_ifaddr_tid, "if_list") {
            Ok(offset) => offset,
            Err(_) => return address_list,
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
            Ok(inet6_ifaddr) => inet6_ifaddr,

            Err(err) => {
                log::error!(
                    "Failed to read inet6_ifaddr at {:?}: {err:?}. \
                     This may indicate an unsupported kernel version.",
                    inet6_ifaddr_vaddr
                );

                break;
            }
        };

        let address = inet6_ifaddr
            .traverse("addr")
            .and_then(|addr_struct| addr_struct.read_bytes(IPV6_ADDRESS_SIZE))
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
            address_list.push(IPAddressAndMask {
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

    address_list
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
            Ok(hw_addr) => hw_addr,

            Err(err) => {
                log::error!(
                    "Failed to read netdev_hw_addr at {:?}: {err:?}. \
                     This may indicate an unsupported kernel version.",
                    hw_addr_vaddr
                );

                break;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet interfaces (eth0, enp0s3, etc.) use 6-byte MAC addresses (ETH_ALEN).
    #[test]
    fn test_format_mac_address_ethernet_6_bytes() {
        let bytes = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        assert_eq!(
            format_mac_address(&bytes),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    /// Ethernet addresses with leading zero bytes should preserve the zeros.
    #[test]
    fn test_format_mac_address_with_leading_zeros() {
        let bytes = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

        assert_eq!(
            format_mac_address(&bytes),
            Some("00:1a:2b:3c:4d:5e".to_string())
        );
    }

    /// InfiniBand interfaces (ib0, etc.) use 20-byte hardware addresses (INFINIBAND_ALEN).
    #[test]
    fn test_format_mac_address_infiniband_20_bytes() {
        let bytes = [
            0x80, 0x00, 0x00, 0x48, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0xc9, 0x03, 0x00, 0x17, 0x75, 0x77,
        ];

        assert_eq!(
            format_mac_address(&bytes),
            Some("80:00:00:48:fe:80:00:00:00:00:00:00:00:02:c9:03:00:17:75:77".to_string())
        );
    }

    /// Uninitialized or invalid interfaces may have all-zero addresses.
    #[test]
    fn test_format_mac_address_all_zeros_returns_none() {
        assert_eq!(format_mac_address(&[0x00; 6]), None);
        assert_eq!(format_mac_address(&[0x00; 20]), None);
        assert_eq!(format_mac_address(&[0x00; 32]), None);
    }

    /// Virtual interfaces (vxlan, wireguard, CAN, tun/tap in some modes) have addr_len=0.
    #[test]
    fn test_format_mac_address_empty_returns_none() {
        let bytes: [u8; 0] = [];
        assert_eq!(format_mac_address(&bytes), None);
    }

    /// Addresses exceeding MAX_ADDR_LEN (32 bytes) are invalid.
    #[test]
    fn test_format_mac_address_exceeds_max_addr_len_returns_none() {
        let bytes = [0xaa; 33];
        assert_eq!(format_mac_address(&bytes), None);
    }
}
