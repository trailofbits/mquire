//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

/// Represents the source of dmesg/kernel log data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmesgDataSource {
    /// Data read from the kernel's printk ringbuffer
    PrintkRingbuffer,
}

impl DmesgDataSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            DmesgDataSource::PrintkRingbuffer => "printk_ringbuffer",
        }
    }
}

/// Represents a single kernel log message from dmesg
#[derive(Debug, Clone)]
pub struct DmesgEntry {
    /// The source of this log entry
    pub data_source: DmesgDataSource,

    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,

    /// Log level (0-7, where 0=emergency, 7=debug)
    pub level: u8,

    /// Facility code
    pub facility: u8,

    /// The sequence number of this message
    pub sequence: u64,

    /// The log message text
    pub message: String,

    /// Caller information (if available)
    pub caller_id: Option<u32>,
}
