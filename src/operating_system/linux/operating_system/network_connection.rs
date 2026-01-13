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
        entities::ip_address::IPAddress,
        error::{Error, ErrorKind, Result},
        virtual_memory_reader::VirtualMemoryReader,
    },
    memory::{primitives::PhysicalAddress, readable::Readable, virtual_address::VirtualAddress},
    operating_system::linux::{
        entities::network_connection::{IPAddressType, NetworkConnection, Protocol},
        kallsyms::Kallsyms,
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
    std::sync::Arc,
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

/// Hash table information for either TCP or UDP connections
#[derive(Clone)]
struct HashTableInfo {
    /// Hash table virtual address
    vaddr: VirtualAddress,

    /// Number of buckets
    bucket_count: usize,

    /// Size of each bucket struct
    bucket_size: u64,
}

/// Stages for the network connection iterator
enum IterationStage {
    /// Iterating listening TCP sockets
    ListeningTcp {
        bucket_index: usize,
        current_bucket_iter: Option<std::vec::IntoIter<SocketValue<ListeningTcpSocket>>>,
    },

    /// Iterating established TCP sockets
    EstablishedTcp {
        bucket_index: usize,
        current_bucket_iter: Option<std::vec::IntoIter<SocketValue<EstablishedTcpSocket>>>,
    },

    /// Iterating UDP sockets
    Udp {
        bucket_index: usize,
        current_bucket_iter: Option<std::vec::IntoIter<SocketValue<UdpSocket>>>,
    },

    /// Iteration complete
    Done,
}

/// Iterator over network connections
pub struct NetworkConnectionIterator<'a> {
    /// The memory dump
    memory_dump: Arc<dyn Readable>,

    /// The target architecture
    architecture: Arc<dyn Architecture>,

    /// Kernel debug symbols
    kernel_type_info: &'a TypeInformation,

    /// The kernel page table
    kernel_page_table: PhysicalAddress,

    /// Listening TCP hash table info (None if not available or not requested)
    listening_tcp: Option<HashTableInfo>,

    /// Established TCP hash table info (None if not available or not requested)
    established_tcp: Option<HashTableInfo>,

    /// UDP hash table info (None if not available or not requested)
    udp: Option<HashTableInfo>,

    /// Current iteration stage
    stage: IterationStage,
}

impl<'a> NetworkConnectionIterator<'a> {
    /// Creates a new NetworkConnectionIterator
    fn new(
        memory_dump: Arc<dyn Readable>,
        architecture: Arc<dyn Architecture>,
        kernel_type_info: &'a TypeInformation,
        kernel_page_table: PhysicalAddress,
        listening_tcp: Option<HashTableInfo>,
        established_tcp: Option<HashTableInfo>,
        udp: Option<HashTableInfo>,
    ) -> Self {
        // Determine the initial stage based on what's available
        let stage = if listening_tcp.is_some() {
            IterationStage::ListeningTcp {
                bucket_index: 0,
                current_bucket_iter: None,
            }
        } else if established_tcp.is_some() {
            IterationStage::EstablishedTcp {
                bucket_index: 0,
                current_bucket_iter: None,
            }
        } else if udp.is_some() {
            IterationStage::Udp {
                bucket_index: 0,
                current_bucket_iter: None,
            }
        } else {
            IterationStage::Done
        };

        Self {
            memory_dump,
            architecture,
            kernel_type_info,
            kernel_page_table,
            listening_tcp,
            established_tcp,
            udp,
            stage,
        }
    }

    /// Transitions to the next available stage after iterating over listening TCP connections
    fn transition_from_listening_tcp(&mut self) {
        if self.established_tcp.is_some() {
            self.stage = IterationStage::EstablishedTcp {
                bucket_index: 0,
                current_bucket_iter: None,
            };
        } else if self.udp.is_some() {
            self.stage = IterationStage::Udp {
                bucket_index: 0,
                current_bucket_iter: None,
            };
        } else {
            self.stage = IterationStage::Done;
        }
    }

    /// Transitions to the next available stage after established TCP
    fn transition_from_established_tcp(&mut self) {
        if self.udp.is_some() {
            self.stage = IterationStage::Udp {
                bucket_index: 0,
                current_bucket_iter: None,
            };
        } else {
            self.stage = IterationStage::Done;
        }
    }

    /// Steps through the listening TCP iteration stage
    fn step_listening_tcp(&mut self) -> Option<Result<NetworkConnection>> {
        let hash_info = self.listening_tcp.as_ref()?;

        let (bucket_index, current_bucket_iter) = match &mut self.stage {
            IterationStage::ListeningTcp {
                bucket_index,
                current_bucket_iter,
            } => (bucket_index, current_bucket_iter),

            _ => return None,
        };

        loop {
            if let Some(iter) = current_bucket_iter
                && let Some(socket_value) = iter.next()
            {
                return Some(Ok(socket_value.connection));
            }

            if *bucket_index >= hash_info.bucket_count {
                self.transition_from_listening_tcp();
                return None;
            }

            let vmem_reader =
                VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

            let bucket_vaddr = hash_info.vaddr + (*bucket_index as u64 * hash_info.bucket_size);
            *bucket_index += 1;

            let bucket = match VirtualStruct::from_name(
                &vmem_reader,
                self.kernel_type_info,
                "inet_listen_hashbucket",
                &bucket_vaddr,
            ) {
                Ok(b) => b,
                Err(error) => {
                    error!("Type `inet_listen_hashbucket` was not found: {error:?}");
                    continue;
                }
            };

            let first_node_vaddr = match bucket.traverse("nulls_head.first") {
                Ok(f) => match f.read_vaddr() {
                    Ok(v) => v,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };

            if first_node_vaddr.is_null() || (first_node_vaddr.value().value() & 1 != 0) {
                continue;
            }

            let list = match List::<SocketValue<ListeningTcpSocket>>::builder()
                .hlist()
                .container("sock_common")
                .node_path(&["skc_node"])
                .parse(
                    self.memory_dump.as_ref(),
                    self.architecture.as_ref(),
                    self.kernel_type_info,
                    first_node_vaddr,
                    self.kernel_page_table,
                ) {
                Ok(list) => list,

                Err(error) => {
                    debug!("Error parsing listening TCP hlist: {:?}", error);
                    continue;
                }
            };

            *current_bucket_iter = Some(list.into_iter());
        }
    }

    /// Steps through the established TCP iteration stage
    fn step_established_tcp(&mut self) -> Option<Result<NetworkConnection>> {
        let hash_info = self.established_tcp.as_ref()?;

        let (bucket_index, current_bucket_iter) = match &mut self.stage {
            IterationStage::EstablishedTcp {
                bucket_index,
                current_bucket_iter,
            } => (bucket_index, current_bucket_iter),

            _ => return None,
        };

        loop {
            if let Some(iter) = current_bucket_iter
                && let Some(socket_value) = iter.next()
            {
                return Some(Ok(socket_value.connection));
            }

            if *bucket_index >= hash_info.bucket_count {
                self.transition_from_established_tcp();
                return None;
            }

            let vmem_reader =
                VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

            let bucket_vaddr = hash_info.vaddr + (*bucket_index as u64 * hash_info.bucket_size);
            *bucket_index += 1;

            let bucket = match VirtualStruct::from_name(
                &vmem_reader,
                self.kernel_type_info,
                "inet_ehash_bucket",
                &bucket_vaddr,
            ) {
                Ok(b) => b,

                Err(_) => {
                    debug!("Failed to read ehash bucket");
                    continue;
                }
            };

            let first_node_vaddr = match bucket.traverse("chain.first") {
                Ok(f) => match f.read_vaddr() {
                    Ok(v) => v,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };

            if first_node_vaddr.is_null() || (first_node_vaddr.value().value() & 1) != 0 {
                continue;
            }

            let list = match List::<SocketValue<EstablishedTcpSocket>>::builder()
                .hlist()
                .container("sock")
                .node_path(&["__sk_common", "skc_node"])
                .parse(
                    self.memory_dump.as_ref(),
                    self.architecture.as_ref(),
                    self.kernel_type_info,
                    first_node_vaddr,
                    self.kernel_page_table,
                ) {
                Ok(list) => list,

                Err(error) => {
                    debug!("Error parsing established TCP hlist: {:?}", error);
                    continue;
                }
            };

            *current_bucket_iter = Some(list.into_iter());
        }
    }

    /// Steps through the UDP iteration stage
    fn step_udp(&mut self) -> Option<Result<NetworkConnection>> {
        let hash_info = self.udp.as_ref()?;

        let (bucket_index, current_bucket_iter) = match &mut self.stage {
            IterationStage::Udp {
                bucket_index,
                current_bucket_iter,
            } => (bucket_index, current_bucket_iter),

            _ => return None,
        };

        loop {
            if let Some(iter) = current_bucket_iter
                && let Some(socket_value) = iter.next()
            {
                return Some(Ok(socket_value.connection));
            }

            if *bucket_index >= hash_info.bucket_count {
                self.stage = IterationStage::Done;
                return None;
            }

            let vmem_reader =
                VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

            let bucket_vaddr = hash_info.vaddr + (*bucket_index as u64 * hash_info.bucket_size);
            *bucket_index += 1;

            let bucket = match VirtualStruct::from_name(
                &vmem_reader,
                self.kernel_type_info,
                "udp_hslot",
                &bucket_vaddr,
            ) {
                Ok(bucket) => bucket,

                Err(error) => {
                    error!("Failed to read UDP hash2 bucket: {error:?}");
                    continue;
                }
            };

            let first_node_vaddr = match bucket.traverse("head.first") {
                Ok(head_first) => match head_first.read_vaddr() {
                    Ok(virtual_address) => virtual_address,

                    Err(err) => {
                        debug!("Failed to read UDP head.first vaddr: {err:?}");
                        continue;
                    }
                },

                Err(err) => {
                    debug!("Failed to traverse UDP head.first: {err:?}");
                    continue;
                }
            };

            if first_node_vaddr.is_null() {
                continue;
            }

            let list = match List::<SocketValue<UdpSocket>>::builder()
                .hlist()
                .container("sock_common")
                .node_path(&["skc_portaddr_node"])
                .parse(
                    self.memory_dump.as_ref(),
                    self.architecture.as_ref(),
                    self.kernel_type_info,
                    first_node_vaddr,
                    self.kernel_page_table,
                ) {
                Ok(list) => list,

                Err(error) => {
                    debug!("Error parsing UDP hlist: {:?}", error);
                    continue;
                }
            };

            *current_bucket_iter = Some(list.into_iter());
        }
    }
}

impl Iterator for NetworkConnectionIterator<'_> {
    type Item = Result<NetworkConnection>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &self.stage {
                IterationStage::ListeningTcp { .. } => {
                    if let Some(result) = self.step_listening_tcp() {
                        return Some(result);
                    }
                }

                IterationStage::EstablishedTcp { .. } => {
                    if let Some(result) = self.step_established_tcp() {
                        return Some(result);
                    }
                }

                IterationStage::Udp { .. } => {
                    if let Some(result) = self.step_udp() {
                        return Some(result);
                    }
                }
                IterationStage::Done => return None,
            }
        }
    }
}

/// Holds hash table information for TCP socket iteration
struct TCPHashTableInfo {
    /// Hash table for sockets in listening state
    listening_tcp: Option<HashTableInfo>,

    /// Hash table for established connections
    established_tcp: Option<HashTableInfo>,
}

impl LinuxOperatingSystem {
    /// Returns an iterator over network connections filtered by protocol
    pub(super) fn iter_network_connections_impl(
        &self,
        protocol_filter: &[Protocol],
    ) -> Result<NetworkConnectionIterator<'_>> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })?;

        let vmem_reader =
            VirtualMemoryReader::new(self.memory_dump.as_ref(), self.architecture.as_ref());

        let kernel_page_table = self.init_task_vaddr.root_page_table();
        let include_tcp = protocol_filter.is_empty() || protocol_filter.contains(&Protocol::TCP);
        let include_udp = protocol_filter.is_empty() || protocol_filter.contains(&Protocol::UDP);

        let (listening_tcp, established_tcp) = include_tcp
            .then(|| {
                self.get_tcp_hash_table_information(&vmem_reader, kallsyms, kernel_page_table)
                    .inspect_err(|error| {
                        debug!("Failed to get the TCP hash table information: {error:?}")
                    })
                    .ok()
            })
            .flatten()
            .map(|info| (info.listening_tcp, info.established_tcp))
            .unwrap_or((None, None));

        let udp = if include_udp {
            self.get_udp_hash_table_info(&vmem_reader, kallsyms, kernel_page_table)?
        } else {
            None
        };

        Ok(NetworkConnectionIterator::new(
            self.memory_dump.clone(),
            self.architecture.clone(),
            &self.kernel_type_info,
            kernel_page_table,
            listening_tcp,
            established_tcp,
            udp,
        ))
    }

    /// Returns the listening and established TCP hash table information from tcp_hashinfo
    fn get_tcp_hash_table_information(
        &self,
        vmem_reader: &VirtualMemoryReader,
        kallsyms: &Kallsyms,
        kernel_page_table: PhysicalAddress,
    ) -> Result<TCPHashTableInfo> {
        let tcp_hashinfo_vaddr = kallsyms
            .get("tcp_hashinfo")
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::EntityNotFound,
                    "Failed to find 'tcp_hashinfo' symbol in kallsyms",
                )
            })
            .inspect_err(|error| error!("{error:?}"))?;

        let tcp_hashinfo = VirtualStruct::from_name(
            vmem_reader,
            &self.kernel_type_info,
            "inet_hashinfo",
            &VirtualAddress::new(kernel_page_table, tcp_hashinfo_vaddr.value()),
        )?;

        let listening_tcp = self
            .get_listening_tcp_hash_info(&tcp_hashinfo)
            .inspect_err(|e| debug!("Failed to read listening TCP hash info: {:?}", e))
            .ok()
            .flatten();

        let established_tcp = self
            .get_established_tcp_hash_info(&tcp_hashinfo)
            .inspect_err(|e| debug!("Failed to read established TCP hash info: {:?}", e))
            .ok()
            .flatten();

        Ok(TCPHashTableInfo {
            listening_tcp,
            established_tcp,
        })
    }

    /// Returns the listening TCP hash table information from tcp_hashinfo
    fn get_listening_tcp_hash_info(
        &self,
        tcp_hashinfo: &VirtualStruct,
    ) -> Result<Option<HashTableInfo>> {
        let lhash2_mask = tcp_hashinfo
            .traverse("lhash2_mask")
            .and_then(|f| f.read_u32())
            .inspect_err(|e| error!("Failed to read lhash2_mask: {:?}", e))?;

        let bucket_count = ((lhash2_mask + 1) as usize).min(MAX_HASH_BUCKETS);
        if bucket_count == MAX_HASH_BUCKETS {
            error!("Too many lhash2 buckets, capping at {}", MAX_HASH_BUCKETS);
        }

        let vaddr = tcp_hashinfo
            .traverse("lhash2")
            .and_then(|f| f.read_vaddr())
            .inspect_err(|e| debug!("Failed to read lhash2 pointer: {:?}", e))?;

        if vaddr.is_null() {
            debug!("lhash2 pointer is null");
            return Ok(None);
        }

        let bucket_size = get_struct_size(&self.kernel_type_info, "inet_listen_hashbucket")
            .inspect_err(|e| error!("Failed to get size of inet_listen_hashbucket: {:?}", e))?;

        Ok(Some(HashTableInfo {
            vaddr,
            bucket_count,
            bucket_size,
        }))
    }

    /// Returns the established TCP hash table information from tcp_hashinfo
    fn get_established_tcp_hash_info(
        &self,
        tcp_hashinfo: &VirtualStruct,
    ) -> Result<Option<HashTableInfo>> {
        let ehash_mask = tcp_hashinfo
            .traverse("ehash_mask")
            .and_then(|f| f.read_u32())
            .inspect_err(|e| debug!("Failed to read ehash_mask: {:?}", e))?;

        let bucket_count = ((ehash_mask + 1) as usize).min(MAX_HASH_BUCKETS);
        if bucket_count == MAX_HASH_BUCKETS {
            error!("Too many ehash buckets, capping at {}", MAX_HASH_BUCKETS);
        }

        let vaddr = tcp_hashinfo
            .traverse("ehash")
            .and_then(|f| f.read_vaddr())
            .inspect_err(|e| debug!("Failed to read ehash pointer: {:?}", e))?;

        if vaddr.is_null() {
            debug!("ehash pointer is null");
            return Ok(None);
        }

        let bucket_size = get_struct_size(&self.kernel_type_info, "inet_ehash_bucket")
            .inspect_err(|e| debug!("Failed to get size of inet_ehash_bucket: {:?}", e))?;

        Ok(Some(HashTableInfo {
            vaddr,
            bucket_count,
            bucket_size,
        }))
    }

    /// Returns the UDP hash table information from udp_table
    fn get_udp_hash_table_info(
        &self,
        vmem_reader: &VirtualMemoryReader,
        kallsyms: &Kallsyms,
        kernel_page_table: PhysicalAddress,
    ) -> Result<Option<HashTableInfo>> {
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
            &self.kernel_type_info,
            "udp_table",
            &VirtualAddress::new(kernel_page_table, udp_table_vaddr.value()),
        )
        .inspect_err(|error| debug!("Failed to read udp_table: {error:?}"))?;

        let mask = udp_table
            .traverse("mask")
            .and_then(|f| f.read_u32())
            .inspect_err(|e| debug!("Failed to read udp_table mask: {:?}", e))?;

        let bucket_count = ((mask + 1) as usize).min(MAX_HASH_BUCKETS);
        if bucket_count == MAX_HASH_BUCKETS {
            debug!(
                "Too many UDP hash2 buckets, capping at {}",
                MAX_HASH_BUCKETS
            );
        }

        let vaddr = udp_table
            .traverse("hash2")
            .and_then(|f| f.read_vaddr())
            .inspect_err(|e| debug!("Failed to read udp hash2 pointer: {:?}", e))?;

        if vaddr.is_null() {
            debug!("udp hash2 pointer is null");
            return Ok(None);
        }

        let bucket_size = get_struct_size(&self.kernel_type_info, "udp_hslot")
            .inspect_err(|e| debug!("Failed to get size of udp_hslot: {:?}", e))?;

        Ok(Some(HashTableInfo {
            vaddr,
            bucket_count,
            bucket_size,
        }))
    }
}

/// Extract the inode number from a socket
fn get_sock_struct_inode(
    vmem_reader: &VirtualMemoryReader,
    type_info: &TypeInformation,
    sock_vaddr: &VirtualAddress,
) -> Option<u64> {
    let sock = match VirtualStruct::from_name(vmem_reader, type_info, "sock", sock_vaddr) {
        Ok(sock) => sock,

        Err(error) => {
            debug!("Failed to create sock VirtualStruct: {:?}", error);
            return None;
        }
    };

    let sk_socket_ptr = match sock.traverse("sk_socket").and_then(|f| f.read_vaddr()) {
        Ok(ptr) => ptr,

        Err(error) => {
            debug!("Failed to read sk_socket: {:?}", error);
            return None;
        }
    };

    if sk_socket_ptr.is_null() {
        debug!("sk_socket pointer is null");
        return None;
    }

    let socket = match VirtualStruct::from_name(vmem_reader, type_info, "socket", &sk_socket_ptr) {
        Ok(s) => s,

        Err(error) => {
            debug!("Failed to create socket VirtualStruct: {:?}", error);
            return None;
        }
    };

    let file_ptr = match socket.traverse("file").and_then(|f| f.read_vaddr()) {
        Ok(file_ptr) => file_ptr,

        Err(error) => {
            debug!("Failed to read file pointer: {:?}", error);
            return None;
        }
    };

    if file_ptr.is_null() {
        debug!("file pointer is null");
        return None;
    }

    let file = match VirtualStruct::from_name(vmem_reader, type_info, "file", &file_ptr) {
        Ok(file) => file,

        Err(error) => {
            debug!("Failed to create file VirtualStruct: {:?}", error);
            return None;
        }
    };

    let f_inode_ptr = match file.traverse("f_inode").and_then(|f| f.read_vaddr()) {
        Ok(f_inode_ptr) => f_inode_ptr,

        Err(error) => {
            debug!("Failed to read f_inode pointer: {:?}", error);
            return None;
        }
    };

    if f_inode_ptr.is_null() {
        debug!("f_inode pointer is null");
        return None;
    }

    let inode_struct = match VirtualStruct::from_name(vmem_reader, type_info, "inode", &f_inode_ptr)
    {
        Ok(inode_struct) => inode_struct,

        Err(error) => {
            debug!("Failed to create inode VirtualStruct: {:?}", error);
            return None;
        }
    };

    let ino = match inode_struct.traverse("i_ino").and_then(|f| f.read_u64()) {
        Ok(ino) => ino,

        Err(error) => {
            debug!("Failed to read i_ino: {:?}", error);
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
