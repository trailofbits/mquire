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

#[macro_export]
macro_rules! generate_address_ranges {
    ($starting_address:expr, $ending_address:expr, $range_size:expr, $overlap:expr) => {{
        let mut current_address = $starting_address;
        let ending_address = $ending_address;
        let mut range_list = Vec::new();

        while current_address < ending_address {
            let start = current_address;

            let end = if start + $range_size as u64 >= ending_address {
                ending_address
            } else {
                start + $range_size as u64
            };

            range_list.push(std::ops::Range { start, end });
            current_address = current_address + ($range_size - $overlap) as u64;
        }

        range_list
    }};
}
