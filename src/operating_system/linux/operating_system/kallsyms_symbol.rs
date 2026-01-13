//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::{
    core::error::{Error, ErrorKind, Result},
    memory::virtual_address::VirtualAddress,
    operating_system::linux::{
        entities::kallsyms_symbol::KallsymsSymbol, operating_system::LinuxOperatingSystem,
    },
};

/// Iterator over kernel symbols from kallsyms
pub type KallsymsSymbolIterator = std::vec::IntoIter<KallsymsSymbol>;

impl LinuxOperatingSystem {
    /// Returns an iterator over kernel symbols from kallsyms
    pub(super) fn iter_kallsyms_symbols_impl(&self) -> Result<KallsymsSymbolIterator> {
        let kallsyms = self.kallsyms.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                "Kallsyms not initialized",
            )
        })?;

        let root_page_table = self.init_task_vaddr.root_page_table();

        let symbols: Vec<KallsymsSymbol> = kallsyms
            .symbols()
            .map(|(name, data)| KallsymsSymbol {
                symbol_name: name.to_string(),
                virtual_address: VirtualAddress::new(root_page_table, data.address),
                symbol_type: data.symbol_type,
            })
            .collect();

        Ok(symbols.into_iter())
    }
}
