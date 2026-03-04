//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

//! Snapshot implementations for reading physical memory dumps.
//!
//! Each snapshot format models a view of the physical address space through
//! the [`Readable`] trait. The format determines the physical memory extent
//! (reported via [`Readable::regions`]):
//!
//! - Reads within the defined extent return actual data, or zeroes for
//!   known-empty regions (e.g. LiME zero-filled ranges).
//! - Reads outside the defined extent are errors; there is no physical
//!   memory at those addresses.
//!
//! The extent is determined entirely by the snapshot format (file size for
//! raw dumps, headers for LiME), not by an external parameter.

pub mod lime_snapshot;
pub mod raw_snapshot;

use crate::memory::readable::Readable;

use {lime_snapshot::LimeSnapshot, raw_snapshot::RawSnapshot};

use std::{
    io::{self, ErrorKind},
    path::Path,
    sync::Arc,
};

/// Opens a memory dump file and returns a Readable instance.
pub fn open_memory(path: &Path) -> io::Result<Arc<dyn Readable>> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("raw") => {
            let snapshot: Arc<dyn Readable> = RawSnapshot::new(path)
                .map_err(|e| io::Error::other(format!("Failed to open raw snapshot: {e:?}")))?;

            Ok(snapshot)
        }

        Some("lime") => {
            let snapshot: Arc<dyn Readable> = LimeSnapshot::new(path)
                .map_err(|e| io::Error::other(format!("Failed to open lime snapshot: {e:?}")))?;

            Ok(snapshot)
        }

        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Unsupported memory dump format. Use .raw or .lime files.",
        )),
    }
}
