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

/// Get the size of a struct type
pub fn get_struct_size(type_info: &TypeInformation, struct_name: &str) -> Result<u64> {
    let tid = type_info.id_of(struct_name).ok_or(Error::new(
        ErrorKind::TypeInformationError,
        &format!("Failed to locate type: {}", struct_name),
    ))?;

    type_info.size_of(tid).map(|size| size as u64).map_err(|e| {
        Error::new(
            ErrorKind::TypeInformationError,
            &format!("Failed to get size of {}: {:?}", struct_name, e),
        )
    })
}

/// Get the pointer size for this kernel by looking at struct list_head
pub fn get_pointer_size(type_info: &TypeInformation) -> Result<u64> {
    get_struct_size(type_info, "list_head").map(|size| size / 2)
}
