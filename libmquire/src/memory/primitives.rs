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

define_address_type!(
    PhysicalAddress, u64, physical_address_tests;
    RawVirtualAddress, u64, raw_virtual_address_tests;
);
