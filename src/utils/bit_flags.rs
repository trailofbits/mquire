//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

/// Generates a flag enum plus a companion struct that decodes a raw bitmask
/// value into the set flags and any leftover (unrecognized) bits.
#[macro_export]
macro_rules! define_bit_flags {
    (
        $(#[doc = $enum_doc:literal])*
        $enum_vis:vis enum $Enum:ident : $int:ty {
            $(
                $(#[doc = $variant_doc:literal])*
                $Variant:ident = ($name:literal, $value:literal)
            ),* $(,)?
        }

        $(#[doc = $struct_doc:literal])*
        $struct_vis:vis struct $Struct:ident;
    ) => {
        $(#[doc = $enum_doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $enum_vis enum $Enum {
            $(
                $(#[doc = $variant_doc])*
                $Variant,
            )*
        }

        impl $Enum {
            /// All known flags, in declaration order.
            pub const ALL: &[$Enum] = &[ $( $Enum::$Variant, )* ];

            /// The name of this flag.
            pub fn name(self) -> &'static str {
                match self {
                    $( $Enum::$Variant => $name, )*
                }
            }

            /// The bit mask of this flag within the raw value.
            pub const fn value(self) -> $int {
                match self {
                    $( $Enum::$Variant => $value, )*
                }
            }
        }

        // Compile-time guarantee that each flag owns a distinct, non-empty set of
        // bits: no flag may be zero, and no two flags may share a bit.
        const _: () = {
            let all = $Enum::ALL;

            let mut outer = 0;
            while outer < all.len() {
                assert!(
                    all[outer].value() != 0,
                    concat!(
                        "define_bit_flags! for ",
                        stringify!($Enum),
                        ": a flag has a zero bit value"
                    )
                );

                let mut inner = outer + 1;
                while inner < all.len() {
                    assert!(
                        (all[outer].value() & all[inner].value()) == 0,
                        concat!(
                            "define_bit_flags! for ",
                            stringify!($Enum),
                            ": two flags share one or more bits"
                        )
                    );

                    inner += 1;
                }

                outer += 1;
            }
        };

        $(#[doc = $struct_doc])*
        #[derive(Debug, Clone)]
        $struct_vis struct $Struct {
            /// The raw value.
            pub raw: $int,

            /// Bits set in `raw` that do not correspond to any known flag.
            pub unused: $int,

            /// The known flags that are set.
            pub flags: Vec<$Enum>,
        }

        impl $Struct {
            /// Decodes a raw value into its known flags and residue.
            pub fn from_raw(raw: $int) -> Self {
                let known: $int = $Enum::ALL
                    .iter()
                    .fold(0, |accumulator, flag| accumulator | flag.value());

                let flags = $Enum::ALL
                    .iter()
                    .copied()
                    .filter(|flag| (raw & flag.value()) != 0)
                    .collect();

                Self {
                    raw,
                    unused: raw & !known,
                    flags,
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    crate::define_bit_flags! {
        enum DemoFlag: u32 {
            One = ("ONE", 0x00000001),
            Two = ("TWO", 0x00000002),
            Sixteen = ("SIXTEEN", 0x00000010),
            Top = ("TOP", 0x80000000),
        }

        struct DemoSet;
    }

    crate::define_bit_flags! {
        enum TinyFlag: u8 {
            Low = ("LOW", 0x01),
            High = ("HIGH", 0x80),
        }

        struct TinySet;
    }

    crate::define_bit_flags! {
        enum WideFlag: u64 {
            Bit0 = ("BIT0", 0x0000000000000001),
            Bit63 = ("BIT63", 0x8000000000000000),
        }

        struct WideSet;
    }

    // All the DemoFlag values combined plus some unused bits
    const DEMO_KNOWN: u32 = 0x00000001 | 0x00000002 | 0x00000010 | 0x80000000;

    #[test]
    fn value_and_name_map_each_variant_exactly() {
        assert_eq!(DemoFlag::One.value(), 0x00000001);
        assert_eq!(DemoFlag::Two.value(), 0x00000002);
        assert_eq!(DemoFlag::Sixteen.value(), 0x00000010);
        assert_eq!(DemoFlag::Top.value(), 0x80000000);

        assert_eq!(DemoFlag::One.name(), "ONE");
        assert_eq!(DemoFlag::Two.name(), "TWO");
        assert_eq!(DemoFlag::Sixteen.name(), "SIXTEEN");
        assert_eq!(DemoFlag::Top.name(), "TOP");
    }

    #[test]
    fn all_lists_every_variant_in_declaration_order() {
        assert_eq!(
            DemoFlag::ALL.to_vec(),
            vec![
                DemoFlag::One,
                DemoFlag::Two,
                DemoFlag::Sixteen,
                DemoFlag::Top,
            ]
        );
    }

    #[test]
    fn from_raw_zero_yields_no_flags() {
        let decoded = DemoSet::from_raw(0);
        assert!(decoded.flags.is_empty());
        assert_eq!(decoded.unused, 0);
        assert_eq!(decoded.raw, 0);
    }

    #[test]
    fn unknown_bits_surface_as_unused_never_dropped() {
        let decoded = DemoSet::from_raw(0x00000001 | 0x00000004);
        assert_eq!(decoded.flags, [DemoFlag::One]);
        assert_eq!(decoded.unused, 0x00000004);
        assert_eq!(decoded.raw, 0x00000005);
    }

    #[test]
    fn from_raw_recognizes_the_top_u32_bit() {
        let decoded = DemoSet::from_raw(0x80000000);
        assert_eq!(decoded.flags, [DemoFlag::Top]);
        assert_eq!(decoded.unused, 0);
    }

    #[test]
    fn from_raw_all_known_bits_sets_every_flag() {
        let decoded = DemoSet::from_raw(DEMO_KNOWN);
        assert_eq!(decoded.flags, DemoFlag::ALL);
        assert_eq!(decoded.unused, 0);
    }

    #[test]
    fn flags_and_unused_partition_raw_exactly() {
        for raw in [
            0u32,
            0x00000001,
            0x00000013,
            0x00000004,
            0x80000000,
            DEMO_KNOWN,
            u32::MAX,
            0xAABBCCDD,
        ] {
            let decoded = DemoSet::from_raw(raw);
            let flag_bits = decoded
                .flags
                .iter()
                .fold(0u32, |accumulator, flag| accumulator | flag.value());

            assert_eq!(flag_bits | decoded.unused, raw, "lost bits for {raw:#010x}");
            assert_eq!(flag_bits & decoded.unused, 0, "overlap for {raw:#010x}");
            assert_eq!(decoded.raw, raw);
        }
    }

    #[test]
    fn from_raw_max_routes_unknown_bits_to_unused() {
        let decoded = DemoSet::from_raw(u32::MAX);
        assert_eq!(decoded.flags, DemoFlag::ALL);

        assert_eq!(decoded.unused, !DEMO_KNOWN);
        assert_eq!(decoded.unused | DEMO_KNOWN, u32::MAX);
        assert_eq!(decoded.unused & DEMO_KNOWN, 0);
    }

    #[test]
    fn macro_is_generic_over_u8() {
        assert_eq!(TinyFlag::High.value(), 0x80_u8);
        assert_eq!(TinyFlag::High.name(), "HIGH");

        let only_high = TinySet::from_raw(0x80);
        assert_eq!(only_high.flags, [TinyFlag::High]);
        assert_eq!(only_high.unused, 0);
        assert_eq!(only_high.raw, 0x80);

        let all = TinySet::from_raw(0xFF);
        assert_eq!(all.flags, [TinyFlag::Low, TinyFlag::High]);
        assert_eq!(all.unused, 0x7E);
    }

    #[test]
    fn macro_is_generic_over_u64() {
        assert_eq!(WideFlag::Bit63.value(), 0x8000000000000000u64);
        assert_eq!(WideFlag::Bit63.name(), "BIT63");

        let decoded = WideSet::from_raw(0x8000000000000000);
        assert_eq!(decoded.flags, [WideFlag::Bit63]);
        assert_eq!(decoded.unused, 0);
        assert_eq!(decoded.raw, 0x8000000000000000);
    }
}
