//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use std::{fmt, ops};

macro_rules! define_address_type {
    ("base_defs", $name:ident, $inner_type:ty) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
        pub struct $name($inner_type);

        impl $name {
            pub const fn new(address: $inner_type) -> Self {
                Self (
                    address
                )
            }

            pub const fn value(&self) -> $inner_type {
                self.0
            }

            pub const fn is_null(&self) -> bool {
                self.0 == 0
            }

            pub const fn aligned_to(&self, size: $inner_type) -> Self {
                if size == 0 {
                    *self
                } else {
                    Self::new((self.0 + size - 1) & !(size - 1))
                }
            }

            pub fn range_step(
                &self,
                end: $name,
                step: $inner_type,
            ) -> impl Iterator<Item = $name> {
                let mut curr = *self;
                let mut yielded = false;

                std::iter::from_fn(move || {
                    if step == 0 {
                        if !yielded && curr < end {
                            yielded = true;
                            Some(curr)
                        } else {
                            None
                        }

                    } else if curr < end {
                        let ret = curr;
                        curr = curr + step;
                        Some(ret)

                    } else {
                        None
                    }
                })
            }
        }

        impl From<$inner_type> for $name {
            fn from(address: u64) -> Self {
                Self::new(address)
            }
        }

        impl From<$name> for $inner_type {
            fn from(addr: $name) -> Self {
                addr.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}(0x{:016X})", stringify!($name), self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl ops::Sub for $name {
            type Output = $inner_type;

            fn sub(self, rhs: $name) -> Self::Output {
                self.0.wrapping_sub(rhs.0)
            }
        }
    };

    ("arithmetic_ops", $name:ident, $inner_type:ty, $trait_name:ident, $trait_method:ident, $method_name:ident; $($primitive_type:ty),*) => {
        $(
            impl ops::$trait_name<$primitive_type> for $name {
                type Output = $name;

                fn $trait_method(self, rhs: $primitive_type) -> Self::Output {
                    Self::new(self.0.$method_name(rhs as $inner_type))
                }
            }
        )*
    };

    ("main", $name:ident, $inner_type:ty, $test_module:ident) => {
        define_address_type!("base_defs", $name, $inner_type);

        define_address_type!(
            "arithmetic_ops", $name, $inner_type,
            Add, add, wrapping_add; u8, u16, u32, u64, usize
        );

        define_address_type!(
            "arithmetic_ops", $name, $inner_type,
            Sub, sub, wrapping_sub;u8, u16, u32, u64, usize
        );

        #[cfg(test)]
        mod $test_module {
            use super::*;

            #[test]
            fn test_range_step_zero() {
                let start = <$name>::new(0x1000);
                let end = <$name>::new(0x1005);
                let step = 0u64;

                let collected: Vec<_> = start.range_step(end, step).map(|a| a.value()).collect();
                assert_eq!(collected, vec![0x1000]);
            }

            #[test]
            fn test_range_step_one() {
                let start = <$name>::new(0x1000);
                let end = <$name>::new(0x1005);
                let step = 1u64;

                let collected: Vec<_> = start.range_step(end, step).map(|a| a.value()).collect();
                assert_eq!(collected, vec![0x1000, 0x1001, 0x1002, 0x1003, 0x1004]);
            }

            #[test]
            fn test_range_step_four() {
                let start = <$name>::new(0x1000);
                let end = <$name>::new(0x1010);
                let step = 4u64;

                let collected: Vec<_> = start.range_step(end, step).map(|a| a.value()).collect();
                assert_eq!(collected, vec![0x1000, 0x1004, 0x1008, 0x100C]);
            }

            #[test]
            fn test_range_step_large() {
                let start = <$name>::new(0x1000);
                let end = <$name>::new(0x1005);
                let step = 1000u64;

                let collected: Vec<_> = start.range_step(end, step).map(|a| a.value()).collect();
                assert_eq!(collected, vec![0x1000]);
            }

            #[test]
            fn test_aligned_to_zero() {
                let addr = <$name>::new(0x1234);
                assert_eq!(addr.aligned_to(0).value(), 0x1234);
            }

            #[test]
            fn test_aligned_to_one() {
                let addr = <$name>::new(0x1234);
                assert_eq!(addr.aligned_to(1).value(), 0x1234);
            }

            #[test]
            fn test_aligned_to_power_of_two() {
                let addr = <$name>::new(0x1003);
                assert_eq!(addr.aligned_to(0x1000).value(), 0x2000);
            }

            #[test]
            fn test_aligned_to_already_aligned() {
                let addr = <$name>::new(0x4000);
                assert_eq!(addr.aligned_to(0x1000).value(), 0x4000);
            }

            #[test]
            fn test_aligned_to_non_power_of_two() {
                let addr = <$name>::new(0x1234);
                let expected = (0x1234 + 0x123 - 1) & !(0x123 - 1);
                assert_eq!(addr.aligned_to(0x123).value(), expected);
            }

            #[test]
            fn test_new_and_value() {
                let addr = <$name>::new(0xAABBCCDD);
                assert_eq!(addr.value(), 0xAABBCCDD);
            }

            #[test]
            fn test_from_u64() {
                let addr: $name = 0xAABBCCDD.into();
                assert_eq!(addr.value(), 0xAABBCCDD);
            }

            #[test]
            fn test_into_u64() {
                let addr = <$name>::new(0xAABBCCDD);
                let val: u64 = addr.into();
                assert_eq!(val, 0xAABBCCDD);
            }

            #[test]
            fn test_display_format() {
                let addr = <$name>::new(0xAABBCCDD);
                assert_eq!(format!("{}", addr), format!("{}(0x00000000AABBCCDD)", stringify!($name)));
            }

            #[test]
            fn test_debug_format() {
                let addr = <$name>::new(0xAABBCCDD);
                assert_eq!(format!("{:?}", addr), format!("{}(0x00000000AABBCCDD)", stringify!($name)));
            }

            #[test]
            fn test_equality_and_ordering() {
                let a = <$name>::new(10);
                let b = <$name>::new(20);

                assert!(a < b);
                assert!(b > a);
            }

            #[test]
            fn test_default() {
                let addr = <$name>::default();
                assert_eq!(addr.value(), 0);
            }

            #[test]
            fn test_is_null() {
                let null_addr = <$name>::new(0);
                assert!(null_addr.is_null());

                let non_null_addr = <$name>::new(1);
                assert!(!non_null_addr.is_null());
            }

            #[test]
            fn test_addition() {
                let addr = <$name>::new(100);
                let result = addr + 1u64;

                assert_eq!(result.value(), 101);
            }

            #[test]
            fn test_subtraction() {
                let addr = <$name>::new(100);
                let result = addr - 1u64;

                assert_eq!(result.value(), 99);
            }

            #[test]
            fn test_wrapping_add() {
                let addr = <$name>::new(u64::MAX);
                let result = addr + 1u64;

                assert_eq!(result.value(), 0);
            }

            #[test]
            fn test_wrapping_sub() {
                let addr = <$name>::new(0);
                let result = addr - 1u64;

                assert_eq!(result.value(), u64::MAX);
            }
        }
    };

    ($($name:ident, $inner_type:ty, $test_module:ident);* $(;)?) => {
        $(
            define_address_type!("main", $name, $inner_type, $test_module);
        )*
    }
}

impl RawVirtualAddress {
    /// Returns the canonicalized version of this RawVirtualAddress
    pub fn canonicalized(&self) -> Self {
        if self.0 > 0x0000_7FFF_FFFF_FFFF {
            RawVirtualAddress::new(self.0 | 0xFFFF_0000_0000_0000)
        } else {
            *self
        }
    }
}

define_address_type!(
    PhysicalAddress, u64, physical_address_tests;
    RawVirtualAddress, u64, raw_virtual_address_tests;
);
