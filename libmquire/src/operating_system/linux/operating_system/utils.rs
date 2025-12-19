//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::core::error::{Error, ErrorKind, Result};

use btfparse::{Offset, TypeInformation};

/// Returns a byte member offset
pub fn get_struct_member_byte_offset(
    type_information: &TypeInformation,
    tid: u32,
    member_name: &str,
) -> Result<u64> {
    if let (_, Offset::ByteOffset(byte_offset)) = type_information.offset_of(tid, member_name)? {
        Ok(byte_offset as u64)
    } else {
        Err(Error::new(
            ErrorKind::OperatingSystemInitializationFailed,
            "Unexpected bitfield offset found when retrieving the task_struct::comm offset",
        ))
    }
}
