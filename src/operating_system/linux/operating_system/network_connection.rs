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
            network_connection::{IPAddressType, NetworkConnection, Protocol},
        },
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{primitives::PhysicalAddress, readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        list::{List, ListValue},
        operating_system::LinuxOperatingSystem,
        utils::get_struct_size,
        virtual_struct::VirtualStruct,
    },
    try_chain,
    utils::ip_address::{ipv4_to_string, ipv6_to_string},
};

use {
    btfparse::TypeInformation,
    log::{debug, error},
};

/// Maximum hash buckets to iterate
const MAX_HASH_BUCKETS: usize = 524288;

/// Connection information extracted from a socket
struct ConnectionInfo {
    /// Local IP address
    local_address: Option<IPAddress>,

    /// Remote IP address
    remote_address: Option<IPAddress>,

    /// Local port number
    local_port: Option<u16>,

    /// Remote port number
    remote_port: Option<u16>,
}

/// Trait for reading different types of socket connections
trait SocketReader {
    fn read_socket(
        vmem_reader: &VirtualMemoryReader,
        type_info: &TypeInformation,
        sock_vaddr: &VirtualAddress,
    ) -> Option<NetworkConnection>;
}

/// Marker type for listening TCP sockets
struct ListeningTcpSocket;

impl SocketReader for ListeningTcpSocket {
    fn read_socket(
        vmem_reader: &VirtualMemoryReader,
        type_info: &TypeInformation,
        sock_vaddr: &VirtualAddress,
    ) -> Option<NetworkConnection> {
        read_tcp_sock_object(vmem_reader, type_info, sock_vaddr, true)
    }
}

/// Marker type for established TCP sockets
struct EstablishedTcpSocket;

impl SocketReader for EstablishedTcpSocket {
    fn read_socket(
        vmem_reader: &VirtualMemoryReader,
        type_info: &TypeInformation,
        sock_vaddr: &VirtualAddress,
    ) -> Option<NetworkConnection> {
        read_tcp_sock_object(vmem_reader, type_info, sock_vaddr, false)
    }
}

/// Marker type for UDP sockets
struct UdpSocket;

impl SocketReader for UdpSocket {
    fn read_socket(
        vmem_reader: &VirtualMemoryReader,
        type_info: &TypeInformation,
        sock_vaddr: &VirtualAddress,
    ) -> Option<NetworkConnection> {
        read_udp_sock_object(vmem_reader, type_info, sock_vaddr)
    }
}

/// Generic socket value wrapper that uses marker types to differentiate socket types
struct SocketValue<T: SocketReader> {
    /// Connection details
    connection: NetworkConnection,

    /// Phantom data to mark T as used
    _phantom: std::marker::PhantomData<T>,
}

impl<T: SocketReader> ListValue for SocketValue<T> {
    fn from_vaddr(
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        type_information: &TypeInformation,
        virtual_address: VirtualAddress,
    ) -> Result<Self> {
        let vmem_reader = VirtualMemoryReader::new(readable, architecture);

        if let Some(connection) = T::read_socket(&vmem_reader, type_information, &virtual_address) {
            Ok(Self {
                connection,
                _phantom: std::marker::PhantomData,
            })
        } else {
            Err(Error::new(
                ErrorKind::EntityNotFound,
                "Failed to read socket object",
            ))
        }
    }
}

impl LinuxOperatingSystem {
    /// Get the list of network connections from the kernel
    pub(super) fn get_network_connection_list_impl(&self) -> Result<Vec<NetworkConnection>> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })?;

        let tcp_hashinfo_vaddr = kallsyms
            .get("tcp_hashinfo")
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::EntityNotFound,
                    "Failed to find 'tcp_hashinfo' symbol in kallsyms",
                )
            })
            .inspect_err(|error| error!("{error:?}"))?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let tcp_hashinfo = VirtualStruct::from_name(
            &vmem_reader,
            &self.kernel_type_info,
            "inet_hashinfo",
            &VirtualAddress::new(
                self.init_task_vaddr.root_page_table(),
                tcp_hashinfo_vaddr.value(),
            ),
        )?;

        let mut connection_list = Vec::new();

        Self::collect_listening_tcp_sockets(
            &self.kernel_type_info,
            self.init_task_vaddr.root_page_table(),
            &vmem_reader,
            &tcp_hashinfo,
            &mut connection_list,
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
        )?;

        Self::collect_established_tcp_sockets(
            &self.kernel_type_info,
            self.init_task_vaddr.root_page_table(),
            &vmem_reader,
            &tcp_hashinfo,
            &mut connection_list,
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
        )?;

        if let Err(error) = Self::collect_udp_sockets(
            &self.kernel_type_info,
            self.init_task_vaddr.root_page_table(),
            &vmem_reader,
            &mut connection_list,
            self.memory_dump.as_ref(),
            self.architecture.as_ref(),
            kallsyms,
        ) {
            debug!("Failed to collect UDP sockets: {:?}", error);
        }

        Ok(connection_list)
    }

    /// Collect listening tcp sockets
    fn collect_listening_tcp_sockets(
        kernel_type_info: &TypeInformation,
        kernel_page_table: PhysicalAddress,
        vmem_reader: &VirtualMemoryReader,
        tcp_hashinfo: &VirtualStruct,
        connection_list: &mut Vec<NetworkConnection>,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
    ) -> Result<()> {
        let lhash2_mask = tcp_hashinfo
            .traverse("lhash2_mask")
            .and_then(|f| f.read_u32())
            .inspect_err(|e| error!("Failed to read lhash2_mask: {:?}", e))?;

        let bucket_count = (lhash2_mask + 1) as usize;
        let bucket_count = if bucket_count > MAX_HASH_BUCKETS {
            error!("Too many lhash2 buckets: {}", bucket_count);
            MAX_HASH_BUCKETS
        } else {
            bucket_count
        };

        let lhash2_vaddr = tcp_hashinfo
            .traverse("lhash2")
            .and_then(|f| f.read_vaddr())
            .inspect_err(|e| debug!("Failed to read lhash2 pointer: {:?}", e))?;

        if lhash2_vaddr.is_null() {
            debug!("lhash2 pointer is null");
            return Ok(());
        }

        let bucket_size = get_struct_size(kernel_type_info, "inet_listen_hashbucket")
            .inspect_err(|e| error!("Failed to get size of inet_listen_hashbucket: {:?}", e))?;

        for bucket_index in 0..bucket_count {
            let bucket_vaddr = lhash2_vaddr + (bucket_index as u64 * bucket_size);

            let bucket = VirtualStruct::from_name(
                vmem_reader,
                kernel_type_info,
                "inet_listen_hashbucket",
                &bucket_vaddr,
            )
            .inspect_err(|error| {
                error!("Type `inet_listen_hashbucket` was not found: {error:?}")
            })?;

            if let Err(error) = Self::enumerate_listening_tcp_socket_bucket(
                kernel_type_info,
                kernel_page_table,
                &bucket,
                connection_list,
                readable,
                architecture,
            ) {
                debug!(
                    "Error iterating hlist for bucket {}: {:?}",
                    bucket_index, error
                );
            }
        }

        Ok(())
    }

    /// Enumerates the TCP sockets in a listening socket bucket
    fn enumerate_listening_tcp_socket_bucket(
        kernel_type_info: &TypeInformation,
        kernel_page_table: PhysicalAddress,
        bucket: &VirtualStruct,
        connection_list: &mut Vec<NetworkConnection>,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
    ) -> Result<()> {
        let first_node_vaddr = bucket.traverse("nulls_head.first")?.read_vaddr()?;
        if first_node_vaddr.is_null() || (first_node_vaddr.value().value() & 1 != 0) {
            return Ok(());
        }

        let list = List::<SocketValue<ListeningTcpSocket>>::builder()
            .hlist()
            .container("sock_common")
            .node_path(&["skc_node"])
            .parse(
                readable,
                architecture,
                kernel_type_info,
                first_node_vaddr,
                kernel_page_table,
            )?;

        connection_list.extend(list.into_iter().map(|list_value| list_value.connection));

        Ok(())
    }

    /// Collect established TCP sockets from ehash hash table
    fn collect_established_tcp_sockets(
        kernel_type_info: &TypeInformation,
        kernel_page_table: PhysicalAddress,
        vmem_reader: &VirtualMemoryReader,
        tcp_hashinfo: &VirtualStruct,
        connection_list: &mut Vec<NetworkConnection>,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
    ) -> Result<()> {
        let ehash_mask = tcp_hashinfo
            .traverse("ehash_mask")
            .and_then(|f| f.read_u32())
            .inspect_err(|e| debug!("Failed to read ehash_mask: {:?}", e))?;

        let bucket_count = (ehash_mask + 1) as usize;
        let bucket_count = if bucket_count > MAX_HASH_BUCKETS {
            error!("Too many ehash buckets: {}", bucket_count);
            MAX_HASH_BUCKETS
        } else {
            bucket_count
        };

        let ehash_vaddr = tcp_hashinfo
            .traverse("ehash")
            .and_then(|f| f.read_vaddr())
            .inspect_err(|e| debug!("Failed to read ehash pointer: {:?}", e))?;

        if ehash_vaddr.is_null() {
            debug!("ehash pointer is null");
            return Ok(());
        }

        let bucket_size = get_struct_size(kernel_type_info, "inet_ehash_bucket")
            .inspect_err(|e| debug!("Failed to get size of inet_ehash_bucket: {:?}", e))?;

        for bucket_idx in 0..bucket_count {
            let bucket_vaddr = ehash_vaddr + (bucket_idx as u64 * bucket_size);

            let bucket = match VirtualStruct::from_name(
                vmem_reader,
                kernel_type_info,
                "inet_ehash_bucket",
                &bucket_vaddr,
            ) {
                Ok(b) => b,
                Err(_) => {
                    debug!("Failed to read ehash bucket at index {}", bucket_idx);
                    continue;
                }
            };

            if let Err(error) = Self::enumerate_established_tcp_socket_bucket(
                kernel_type_info,
                kernel_page_table,
                &bucket,
                connection_list,
                readable,
                architecture,
            ) {
                debug!(
                    "Error iterating hlist for bucket {}: {:?}",
                    bucket_idx, error
                );
            }
        }

        Ok(())
    }

    /// Enumerates the sockets in an established socket bucket
    fn enumerate_established_tcp_socket_bucket(
        kernel_type_info: &TypeInformation,
        kernel_page_table: PhysicalAddress,
        bucket: &VirtualStruct,
        connection_list: &mut Vec<NetworkConnection>,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
    ) -> Result<()> {
        let first_node_vaddr = bucket.traverse("chain.first")?.read_vaddr()?;
        if first_node_vaddr.is_null() || (first_node_vaddr.value().value() & 1) != 0 {
            return Ok(());
        }

        let list = List::<SocketValue<EstablishedTcpSocket>>::builder()
            .hlist()
            .container("sock")
            .node_path(&["__sk_common", "skc_node"])
            .parse(
                readable,
                architecture,
                kernel_type_info,
                first_node_vaddr,
                kernel_page_table,
            )?;

        connection_list.extend(list.into_iter().map(|list_value| list_value.connection));

        Ok(())
    }

    /// Collects UDP sockets from the kernel
    fn collect_udp_sockets(
        kernel_type_info: &TypeInformation,
        kernel_page_table: PhysicalAddress,
        vmem_reader: &VirtualMemoryReader,
        connection_list: &mut Vec<NetworkConnection>,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
        kallsyms: &crate::operating_system::linux::kallsyms::Kallsyms,
    ) -> Result<()> {
        let udp_table_vaddr = kallsyms
            .get("udp_table")
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::EntityNotFound,
                    "Failed to find 'udp_table' symbol in kallsyms",
                )
            })
            .inspect_err(|error| debug!("{error:?}"))?;

        let udp_table = VirtualStruct::from_name(
            vmem_reader,
            kernel_type_info,
            "udp_table",
            &VirtualAddress::new(kernel_page_table, udp_table_vaddr.value()),
        )
        .inspect_err(|error| debug!("Failed to read udp_table: {error:?}"))?;

        let mask = udp_table
            .traverse("mask")
            .and_then(|f| f.read_u32())
            .inspect_err(|e| debug!("Failed to read udp_table mask: {:?}", e))?;

        let bucket_count = (mask + 1) as usize;
        let bucket_count = if bucket_count > MAX_HASH_BUCKETS {
            debug!("Too many UDP hash2 buckets: {}", bucket_count);
            MAX_HASH_BUCKETS
        } else {
            bucket_count
        };

        let hash2_vaddr = udp_table
            .traverse("hash2")
            .and_then(|f| f.read_vaddr())
            .inspect_err(|e| debug!("Failed to read udp hash2 pointer: {:?}", e))?;

        if hash2_vaddr.is_null() {
            debug!("udp hash2 pointer is null");
            return Ok(());
        }

        let bucket_size = get_struct_size(kernel_type_info, "udp_hslot")
            .inspect_err(|e| debug!("Failed to get size of udp_hslot: {:?}", e))?;

        for bucket_idx in 0..bucket_count {
            let bucket_vaddr = hash2_vaddr + (bucket_idx as u64 * bucket_size);

            let bucket = match VirtualStruct::from_name(
                vmem_reader,
                kernel_type_info,
                "udp_hslot",
                &bucket_vaddr,
            ) {
                Ok(b) => b,
                Err(_) => {
                    debug!("Failed to read UDP hash2 bucket at index {}", bucket_idx);
                    continue;
                }
            };

            if let Err(error) = Self::enumerate_udp_socket_bucket(
                kernel_type_info,
                kernel_page_table,
                &bucket,
                connection_list,
                readable,
                architecture,
            ) {
                debug!(
                    "Error iterating UDP hash2 for bucket {}: {:?}",
                    bucket_idx, error
                );
            }
        }

        Ok(())
    }

    /// Enumerates the UDP sockets in a hash bucket
    fn enumerate_udp_socket_bucket(
        kernel_type_info: &TypeInformation,
        kernel_page_table: PhysicalAddress,
        bucket: &VirtualStruct,
        connection_list: &mut Vec<NetworkConnection>,
        readable: &dyn Readable,
        architecture: &dyn Architecture,
    ) -> Result<()> {
        let first_node_vaddr = bucket.traverse("head.first")?.read_vaddr()?;
        if first_node_vaddr.is_null() {
            return Ok(());
        }

        let list = List::<SocketValue<UdpSocket>>::builder()
            .hlist()
            .container("sock_common")
            .node_path(&["skc_portaddr_node"])
            .parse(
                readable,
                architecture,
                kernel_type_info,
                first_node_vaddr,
                kernel_page_table,
            )?;

        connection_list.extend(list.into_iter().map(|list_value| list_value.connection));

        Ok(())
    }
}

/// Extract the inode number from a socket
fn get_sock_struct_inode(
    vmem_reader: &VirtualMemoryReader,
    type_info: &TypeInformation,
    sock_vaddr: &VirtualAddress,
) -> Option<u64> {
    let sock = match VirtualStruct::from_name(vmem_reader, type_info, "sock", sock_vaddr) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to create sock VirtualStruct: {:?}", e);
            return None;
        }
    };

    let sk_socket_ptr = match sock.traverse("sk_socket").and_then(|f| f.read_vaddr()) {
        Ok(ptr) => ptr,
        Err(e) => {
            debug!("Failed to read sk_socket: {:?}", e);
            return None;
        }
    };

    if sk_socket_ptr.is_null() {
        debug!("sk_socket pointer is null");
        return None;
    }

    let socket = match VirtualStruct::from_name(vmem_reader, type_info, "socket", &sk_socket_ptr) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to create socket VirtualStruct: {:?}", e);
            return None;
        }
    };

    let file_ptr = match socket.traverse("file").and_then(|f| f.read_vaddr()) {
        Ok(ptr) => ptr,
        Err(e) => {
            debug!("Failed to read file pointer: {:?}", e);
            return None;
        }
    };

    if file_ptr.is_null() {
        debug!("file pointer is null");
        return None;
    }

    let file = match VirtualStruct::from_name(vmem_reader, type_info, "file", &file_ptr) {
        Ok(f) => f,
        Err(e) => {
            debug!("Failed to create file VirtualStruct: {:?}", e);
            return None;
        }
    };

    let f_inode_ptr = match file.traverse("f_inode").and_then(|f| f.read_vaddr()) {
        Ok(ptr) => ptr,
        Err(e) => {
            debug!("Failed to read f_inode pointer: {:?}", e);
            return None;
        }
    };

    if f_inode_ptr.is_null() {
        debug!("f_inode pointer is null");
        return None;
    }

    let inode_struct = match VirtualStruct::from_name(vmem_reader, type_info, "inode", &f_inode_ptr)
    {
        Ok(i) => i,
        Err(e) => {
            debug!("Failed to create inode VirtualStruct: {:?}", e);
            return None;
        }
    };

    let ino = match inode_struct.traverse("i_ino").and_then(|f| f.read_u64()) {
        Ok(i) => i,
        Err(e) => {
            debug!("Failed to read i_ino: {:?}", e);
            return None;
        }
    };

    Some(ino)
}

/// Common socket information extracted from sock_common
struct CommonSocketInfo {
    /// The socket state (established, listening, etc)
    state_u8: u8,

    /// The local and remote IP pairs
    connection_info: ConnectionInfo,

    /// Whether it is IPv4 or IPv6
    ip_address_type: Option<IPAddressType>,

    /// Socket inode, used for attribution
    inode: Option<u64>,
}

/// Reads common socket information shared by all socket types
fn read_common_socket_info(
    vmem_reader: &VirtualMemoryReader,
    type_info: &TypeInformation,
    sock_vaddr: &VirtualAddress,
) -> Option<CommonSocketInfo> {
    let sock_common =
        VirtualStruct::from_name(vmem_reader, type_info, "sock_common", sock_vaddr).ok()?;

    let state_u8 = sock_common
        .traverse("skc_state")
        .and_then(|f| f.read_u8())
        .ok()?;

    let family = sock_common
        .traverse("skc_family")
        .and_then(|f| f.read_u16())
        .ok()?;

    let ip_address_type = match family {
        2 => Some(IPAddressType::IPv4),
        10 => Some(IPAddressType::IPv6),

        _ => None,
    };

    let connection_info = match family {
        2 => extract_ipv4_connection_info(&sock_common)?,
        10 => extract_ipv6_connection_info(&sock_common)?,

        _ => ConnectionInfo {
            local_address: None,
            remote_address: None,
            local_port: None,
            remote_port: None,
        },
    };

    let inode = get_sock_struct_inode(vmem_reader, type_info, sock_vaddr);

    Some(CommonSocketInfo {
        state_u8,
        connection_info,
        ip_address_type,
        inode,
    })
}

/// Reads a single network connection from a TCP sock structure
fn read_tcp_sock_object(
    vmem_reader: &VirtualMemoryReader,
    type_info: &TypeInformation,
    sock_vaddr: &VirtualAddress,
    is_listening: bool,
) -> Option<NetworkConnection> {
    let socket_info = read_common_socket_info(vmem_reader, type_info, sock_vaddr)?;

    Some(NetworkConnection {
        virtual_address: *sock_vaddr,
        protocol: Some(Protocol::TCP),
        state: tcp_state_to_string(socket_info.state_u8),
        local_address: socket_info.connection_info.local_address,
        local_port: socket_info.connection_info.local_port,
        remote_address: if is_listening {
            None
        } else {
            socket_info.connection_info.remote_address
        },
        remote_port: if is_listening {
            None
        } else {
            socket_info.connection_info.remote_port
        },
        ip_address_type: socket_info.ip_address_type,
        inode: socket_info.inode,
    })
}

/// Reads a single UDP network connection from a sock structure
fn read_udp_sock_object(
    vmem_reader: &VirtualMemoryReader,
    type_info: &TypeInformation,
    sock_vaddr: &VirtualAddress,
) -> Option<NetworkConnection> {
    let socket_info = read_common_socket_info(vmem_reader, type_info, sock_vaddr)?;

    Some(NetworkConnection {
        virtual_address: *sock_vaddr,
        protocol: Some(Protocol::UDP),
        state: udp_state_to_string(socket_info.state_u8),
        local_address: socket_info.connection_info.local_address,
        local_port: socket_info.connection_info.local_port,
        remote_address: socket_info.connection_info.remote_address,
        remote_port: socket_info.connection_info.remote_port,
        ip_address_type: socket_info.ip_address_type,
        inode: socket_info.inode,
    })
}

/// Extracts IPv4 connection information from a sock_common object
fn extract_ipv4_connection_info(sock_common: &VirtualStruct) -> Option<ConnectionInfo> {
    let local_address = try_chain! {
        sock_common
            .traverse("skc_rcv_saddr")
            .ok()?
            .read_u32()
            .ok()
            .and_then(|addr| ipv4_to_string(u32::from_be(addr)))
            .map(IPAddress::IPv4)
    };

    let remote_address = try_chain! {
        sock_common
            .traverse("skc_daddr")
            .ok()?
            .read_u32()
            .ok()
            .and_then(|addr| {
                if addr == 0 {
                    None
                } else {
                    ipv4_to_string(u32::from_be(addr)).map(IPAddress::IPv4)
                }
            })
    };

    let local_port = try_chain! {
        sock_common.traverse("skc_num").ok()?.read_u16().ok()
    };

    let remote_port = try_chain! {
        sock_common
            .traverse("skc_dport")
            .ok()?
            .read_u16()
            .ok()
            .map(u16::from_be)
            .filter(|&port| port != 0)
    };

    Some(ConnectionInfo {
        local_address,
        remote_address,
        local_port,
        remote_port,
    })
}

/// Extracts IPv6 connection information from a sock_common object
fn extract_ipv6_connection_info(sock_common: &VirtualStruct) -> Option<ConnectionInfo> {
    let local_address = try_chain! {
        sock_common
            .traverse("skc_v6_rcv_saddr.in6_u.u6_addr8")
            .ok()?
            .read_bytes(16)
            .ok()
            .and_then(|bytes| ipv6_to_string(&bytes))
            .map(IPAddress::IPv6)
    };

    let remote_address = try_chain! {
        sock_common
            .traverse("skc_v6_daddr.in6_u.u6_addr8")
            .ok()?
            .read_bytes(16)
            .ok()
            .and_then(|bytes| {
                if bytes.iter().all(|&b| b == 0) {
                    None
                } else {
                    ipv6_to_string(&bytes).map(IPAddress::IPv6)
                }
            })
    };

    let local_port = try_chain! {
        sock_common.traverse("skc_num").ok()?.read_u16().ok()
    };

    let remote_port = try_chain! {
        sock_common
            .traverse("skc_dport")
            .ok()?
            .read_u16()
            .ok()
            .map(u16::from_be)
            .filter(|&port| port != 0)
    };

    Some(ConnectionInfo {
        local_address,
        remote_address,
        local_port,
        remote_port,
    })
}

/// Maps a TCP state enum value to a string
fn tcp_state_to_string(state: u8) -> Option<String> {
    match state {
        1 => Some("established".to_string()),
        2 => Some("syn_sent".to_string()),
        3 => Some("syn_recv".to_string()),
        4 => Some("fin_wait1".to_string()),
        5 => Some("fin_wait2".to_string()),
        6 => Some("time_wait".to_string()),
        7 => Some("close".to_string()),
        8 => Some("close_wait".to_string()),
        9 => Some("last_ack".to_string()),
        10 => Some("listen".to_string()),
        11 => Some("closing".to_string()),
        12 => Some("new_syn_recv".to_string()),
        _ => None,
    }
}

/// Mapa a UDP state enum value to a string
fn udp_state_to_string(state: u8) -> Option<String> {
    match state {
        1 => Some("established".to_string()),
        7 => Some("close".to_string()),
        _ => None,
    }
}
