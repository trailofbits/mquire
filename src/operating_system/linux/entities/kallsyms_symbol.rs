//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::virtual_address::VirtualAddress;

/// Represents a kernel symbol from kallsyms
#[derive(Debug, Clone)]
pub struct KallsymsSymbol {
    /// The symbol name
    pub symbol_name: String,

    /// The virtual address of the symbol
    pub virtual_address: VirtualAddress,

    /// The symbol type
    pub symbol_type: char,
}
