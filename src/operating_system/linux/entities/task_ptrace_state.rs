//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::define_bit_flags;

define_bit_flags! {
    /// A single ptrace flag, corresponding to a `PT_*` bit of `task_struct::ptrace`
    /// (see `include/linux/ptrace.h`).
    pub enum PtraceFlag : u32 {
        /// PT_PTRACED (0x1): the task is being traced.
        Ptraced = ("PT_PTRACED", 0x00000001),

        /// PT_TRACESYSGOOD (0x8)
        TraceSysGood = ("PT_TRACESYSGOOD", 0x00000008),

        /// PT_TRACE_FORK (0x10)
        TraceFork = ("PT_TRACE_FORK", 0x00000010),

        /// PT_TRACE_VFORK (0x20)
        TraceVfork = ("PT_TRACE_VFORK", 0x00000020),

        /// PT_TRACE_CLONE (0x40)
        TraceClone = ("PT_TRACE_CLONE", 0x00000040),

        /// PT_TRACE_EXEC (0x80)
        TraceExec = ("PT_TRACE_EXEC", 0x00000080),

        /// PT_TRACE_VFORK_DONE (0x100)
        TraceVforkDone = ("PT_TRACE_VFORK_DONE", 0x00000100),

        /// PT_TRACE_EXIT (0x200)
        TraceExit = ("PT_TRACE_EXIT", 0x00000200),

        /// PT_TRACE_SECCOMP (0x400)
        TraceSeccomp = ("PT_TRACE_SECCOMP", 0x00000400),

        /// PT_SEIZED (0x10000): attached via PTRACE_SEIZE.
        Seized = ("PT_SEIZED", 0x00010000),

        /// PT_EXITKILL (0x800000)
        ExitKill = ("PT_EXITKILL", 0x00800000),

        /// PT_SUSPEND_SECCOMP (0x1000000)
        SuspendSeccomp = ("PT_SUSPEND_SECCOMP", 0x01000000),
    }

    /// The decoded `task_struct::ptrace` field of a task.
    pub struct TaskPtraceState;
}
