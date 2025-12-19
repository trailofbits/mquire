//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

/// Converts an IPv4 address from a 32-bit integer to a dotted-decimal string
pub fn ipv4_to_string(addr: u32) -> Option<String> {
    Some(std::net::Ipv4Addr::from(addr.to_be_bytes()).to_string())
}

/// Converts an IPv6 address from a 16-byte array to compressed notation
pub fn ipv6_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 16 {
        return None;
    }

    let bytes_array: [u8; 16] = bytes.try_into().ok()?;
    Some(std::net::Ipv6Addr::from(bytes_array).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_string() {
        // Test localhost
        assert_eq!(ipv4_to_string(0x7f000001), Some("127.0.0.1".to_string()));

        // Test common private addresses
        assert_eq!(ipv4_to_string(0xc0a80101), Some("192.168.1.1".to_string()));

        assert_eq!(ipv4_to_string(0x0a000001), Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_ipv6_to_string_localhost() {
        // Test localhost (::1)
        let localhost = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(ipv6_to_string(&localhost), Some("::1".to_string()));
    }

    #[test]
    fn test_ipv6_to_string_all_zeros() {
        // Test all zeros (::)
        let all_zeros = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(ipv6_to_string(&all_zeros), Some("::".to_string()));
    }

    #[test]
    fn test_ipv6_to_string_documentation_prefix() {
        // Test documentation prefix (2001:db8::1)
        let doc_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(ipv6_to_string(&doc_addr), Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_ipv6_to_string_link_local() {
        // Test link-local address (fe80::1)
        let link_local = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(ipv6_to_string(&link_local), Some("fe80::1".to_string()));
    }

    #[test]
    fn test_ipv6_to_string_no_compression() {
        // Test address with no consecutive zeros (2001:db8:1:2:3:4:5:6)
        let no_zeros = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6];

        assert_eq!(
            ipv6_to_string(&no_zeros),
            Some("2001:db8:1:2:3:4:5:6".to_string())
        );
    }

    #[test]
    fn test_ipv6_to_string_compression_in_middle() {
        // Test compression in the middle (2001:db8:0:0:0:0:0:1 -> 2001:db8::1)
        let middle_zeros = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        assert_eq!(
            ipv6_to_string(&middle_zeros),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_ipv6_to_string_compression_at_end() {
        // Test compression at the end (2001:db8:: -> "2001:db8::")
        let end_zeros = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(ipv6_to_string(&end_zeros), Some("2001:db8::".to_string()));
    }

    #[test]
    fn test_ipv6_to_string_compression_at_start() {
        // Test compression at the start (::ffff:192.0.2.1 is an IPv4-mapped IPv6 address)
        let start_zeros = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0, 0x02, 0x01,
        ];

        assert_eq!(
            ipv6_to_string(&start_zeros),
            Some("::ffff:192.0.2.1".to_string())
        );
    }

    #[test]
    fn test_ipv6_to_string_multiple_zero_sequences() {
        // Test multiple zero sequences - compress the first longest one
        // 2001:db8:0:0:1:0:0:1 -> 2001:db8::1:0:0:1
        let multiple_zeros = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

        assert_eq!(
            ipv6_to_string(&multiple_zeros),
            Some("2001:db8::1:0:0:1".to_string())
        );
    }

    #[test]
    fn test_ipv6_to_string_single_zero_no_compression() {
        // Test single zeros not compressed (1:0:1:0:1:0:1:0)
        let single_zeros = [0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0];

        assert_eq!(
            ipv6_to_string(&single_zeros),
            Some("1:0:1:0:1:0:1:0".to_string())
        );
    }

    #[test]
    fn test_ipv6_to_string_leading_zeros_omitted() {
        // Test that leading zeros in hextets are omitted (0001 -> 1)
        let leading_zeros = [
            0x20, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06,
            0x00, 0x07,
        ];

        assert_eq!(
            ipv6_to_string(&leading_zeros),
            Some("2001:1:2:3:4:5:6:7".to_string())
        );
    }

    #[test]
    fn test_ipv6_to_string_invalid_length() {
        assert_eq!(ipv6_to_string(&[1, 2, 3]), None);
        assert_eq!(ipv6_to_string(&[]), None);
        assert_eq!(ipv6_to_string(&[0; 15]), None);
        assert_eq!(ipv6_to_string(&[0; 17]), None);
    }

    #[test]
    fn test_ipv6_to_string_full_address() {
        // Test a full address with no zeros
        let full_addr = [0xff; 16];

        assert_eq!(
            ipv6_to_string(&full_addr),
            Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string())
        );
    }
}
