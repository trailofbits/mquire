//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

/// Validates if a text string contains at least `threshold_percent`% printable characters.
///
/// `threshold_percent` is clamped to 0..=100.
pub fn is_valid_text(text: &str, min_length: usize, threshold_percent: u8) -> bool {
    if text.len() < min_length {
        return false;
    }

    let threshold = threshold_percent.min(100);

    let printable_count = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();

    // printable_count / len >= threshold / 100
    printable_count
        .checked_mul(100)
        .zip(text.len().checked_mul(threshold as usize))
        .is_some_and(|(lhs, rhs)| lhs >= rhs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_text_accepts_fully_printable() {
        assert!(is_valid_text("This is 100% valid ASCII text!", 1, 80));
        assert!(is_valid_text("Line with spaces and punctuation.", 1, 80));
        assert!(is_valid_text("Numbers 12345 are fine", 1, 80));
    }

    #[test]
    fn test_is_valid_text_rejects_mostly_binary() {
        let binary_heavy = "abc\x00\x01\x02\x03\x04\x05";
        assert!(!is_valid_text(binary_heavy, 1, 80));
    }

    #[test]
    fn test_is_valid_text_full_threshold() {
        assert!(is_valid_text("All printable text!", 1, 100));
        assert!(!is_valid_text("Almost\x00valid", 1, 100));
    }

    #[test]
    fn test_is_valid_text_respects_min_length() {
        assert!(!is_valid_text("ab", 5, 80));
        assert!(is_valid_text("abcde", 5, 80));
        assert!(is_valid_text("abcdef", 5, 80));
    }
}
