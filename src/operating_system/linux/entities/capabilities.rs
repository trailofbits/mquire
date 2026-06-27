//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::define_bit_flags;
use crate::memory::virtual_address::VirtualAddress;

define_bit_flags! {
    /// A single Linux capability, corresponding to a `CAP_*` bit of a
    /// `kernel_cap_t` capability set (see `include/uapi/linux/capability.h`).
    pub enum Capability : u64 {
        Chown = ("CAP_CHOWN", 0x0000_0000_0000_0001),
        DacOverride = ("CAP_DAC_OVERRIDE", 0x0000_0000_0000_0002),
        DacReadSearch = ("CAP_DAC_READ_SEARCH", 0x0000_0000_0000_0004),
        Fowner = ("CAP_FOWNER", 0x0000_0000_0000_0008),
        Fsetid = ("CAP_FSETID", 0x0000_0000_0000_0010),
        Kill = ("CAP_KILL", 0x0000_0000_0000_0020),
        Setgid = ("CAP_SETGID", 0x0000_0000_0000_0040),
        Setuid = ("CAP_SETUID", 0x0000_0000_0000_0080),
        Setpcap = ("CAP_SETPCAP", 0x0000_0000_0000_0100),
        LinuxImmutable = ("CAP_LINUX_IMMUTABLE", 0x0000_0000_0000_0200),
        NetBindService = ("CAP_NET_BIND_SERVICE", 0x0000_0000_0000_0400),
        NetBroadcast = ("CAP_NET_BROADCAST", 0x0000_0000_0000_0800),
        NetAdmin = ("CAP_NET_ADMIN", 0x0000_0000_0000_1000),
        NetRaw = ("CAP_NET_RAW", 0x0000_0000_0000_2000),
        IpcLock = ("CAP_IPC_LOCK", 0x0000_0000_0000_4000),
        IpcOwner = ("CAP_IPC_OWNER", 0x0000_0000_0000_8000),
        SysModule = ("CAP_SYS_MODULE", 0x0000_0000_0001_0000),
        SysRawio = ("CAP_SYS_RAWIO", 0x0000_0000_0002_0000),
        SysChroot = ("CAP_SYS_CHROOT", 0x0000_0000_0004_0000),
        SysPtrace = ("CAP_SYS_PTRACE", 0x0000_0000_0008_0000),
        SysPacct = ("CAP_SYS_PACCT", 0x0000_0000_0010_0000),
        SysAdmin = ("CAP_SYS_ADMIN", 0x0000_0000_0020_0000),
        SysBoot = ("CAP_SYS_BOOT", 0x0000_0000_0040_0000),
        SysNice = ("CAP_SYS_NICE", 0x0000_0000_0080_0000),
        SysResource = ("CAP_SYS_RESOURCE", 0x0000_0000_0100_0000),
        SysTime = ("CAP_SYS_TIME", 0x0000_0000_0200_0000),
        SysTtyConfig = ("CAP_SYS_TTY_CONFIG", 0x0000_0000_0400_0000),
        Mknod = ("CAP_MKNOD", 0x0000_0000_0800_0000),
        Lease = ("CAP_LEASE", 0x0000_0000_1000_0000),
        AuditWrite = ("CAP_AUDIT_WRITE", 0x0000_0000_2000_0000),
        AuditControl = ("CAP_AUDIT_CONTROL", 0x0000_0000_4000_0000),
        Setfcap = ("CAP_SETFCAP", 0x0000_0000_8000_0000),
        MacOverride = ("CAP_MAC_OVERRIDE", 0x0000_0001_0000_0000),
        MacAdmin = ("CAP_MAC_ADMIN", 0x0000_0002_0000_0000),
        Syslog = ("CAP_SYSLOG", 0x0000_0004_0000_0000),
        WakeAlarm = ("CAP_WAKE_ALARM", 0x0000_0008_0000_0000),
        BlockSuspend = ("CAP_BLOCK_SUSPEND", 0x0000_0010_0000_0000),
        AuditRead = ("CAP_AUDIT_READ", 0x0000_0020_0000_0000),
        Perfmon = ("CAP_PERFMON", 0x0000_0040_0000_0000),
        Bpf = ("CAP_BPF", 0x0000_0080_0000_0000),
        CheckpointRestore = ("CAP_CHECKPOINT_RESTORE", 0x0000_0100_0000_0000),
    }

    /// A decoded `kernel_cap_t` capability set.
    pub struct CapabilitySet;
}

/// The Linux capability sets of a task
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// The kernel virtual address of the owning task_struct.
    pub task: VirtualAddress,

    /// Effective capability set (cred::cap_effective).
    pub effective: Option<u64>,

    /// Permitted capability set (cred::cap_permitted).
    pub permitted: Option<u64>,

    /// Inheritable capability set (cred::cap_inheritable).
    pub inheritable: Option<u64>,

    /// Bounding capability set (cred::cap_bset).
    pub bounding: Option<u64>,

    /// Ambient capability set (cred::cap_ambient).
    pub ambient: Option<u64>,
}
