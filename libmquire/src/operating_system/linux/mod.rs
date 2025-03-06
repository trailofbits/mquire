//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

mod linux_operating_system;
pub use linux_operating_system::*;

mod btfparse_readable_adapter;
use btfparse_readable_adapter::*;

mod virtual_struct;
use virtual_struct::*;
