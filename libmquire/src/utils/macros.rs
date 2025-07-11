//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

#[macro_export]
macro_rules! try_chain {
    ($expr:expr) => {
        (|| $expr)()
    };
}
