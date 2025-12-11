//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::core::error::{Error, ErrorKind, Result};

use std::str::FromStr;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl FromStr for KernelVersion {
    type Err = Error;

    fn from_str(version: &str) -> Result<Self> {
        let version_field_list = version
            .split('.')
            .collect::<Vec<&str>>()
            .iter()
            .enumerate()
            .take(3)
            .map(|(index, &version_field)| {
                let trimmed_version_field = if index == 2 {
                    version_field
                        .chars()
                        .take_while(|c| c.is_digit(10))
                        .collect::<String>()
                } else {
                    version_field.to_string()
                };

                trimmed_version_field.parse::<u32>().map_err(|error| {
                    Error::new(
                        ErrorKind::OperatingSystemInitializationFailed,
                        &format!(
                            "Invalid kernel version field: {}. Error: {error:?}",
                            version_field
                        ),
                    )
                })
            })
            .collect::<Result<Vec<u32>>>()?;

        let major = version_field_list.get(0).copied().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                &format!("Missing major version field in: {}", version),
            )
        })?;

        let minor = version_field_list.get(1).copied().ok_or_else(|| {
            Error::new(
                ErrorKind::OperatingSystemInitializationFailed,
                &format!("Missing minor version field in: {}", version),
            )
        })?;

        let patch = version_field_list.get(2).copied().unwrap_or_default();

        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl KernelVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equality() {
        let v1: KernelVersion = "6.10.5".parse().unwrap();
        let v2: KernelVersion = "6.10.5".parse().unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_inequality() {
        let v1: KernelVersion = "6.10.5".parse().unwrap();
        let v2: KernelVersion = "6.10.6".parse().unwrap();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_less_than_patch() {
        let v1: KernelVersion = "6.10.5".parse().unwrap();
        let v2: KernelVersion = "6.10.6".parse().unwrap();
        assert!(v1 < v2);
        assert!(v2 > v1);
    }

    #[test]
    fn test_less_than_minor() {
        let v1: KernelVersion = "6.10.9".parse().unwrap();
        let v2: KernelVersion = "6.11.0".parse().unwrap();
        assert!(v1 < v2);
        assert!(v2 > v1);
    }

    #[test]
    fn test_less_than_major() {
        let v1: KernelVersion = "5.19.99".parse().unwrap();
        let v2: KernelVersion = "6.0.0".parse().unwrap();
        assert!(v1 < v2);
        assert!(v2 > v1);
    }

    #[test]
    fn test_less_than_or_equal() {
        let v1: KernelVersion = "6.10".parse().unwrap();
        let v2: KernelVersion = "6.17.7".parse().unwrap();
        let v3: KernelVersion = "6.10.0".parse().unwrap();

        assert!(v1 <= v2);
        assert!(v1 <= v3);
        assert!(v2 >= v1);
    }

    #[test]
    fn test_greater_than_or_equal() {
        let v1: KernelVersion = "6.17.7".parse().unwrap();
        let v2: KernelVersion = "6.10".parse().unwrap();
        let v3: KernelVersion = "6.17.7".parse().unwrap();

        assert!(v1 >= v2);
        assert!(v1 >= v3);
        assert!(v2 <= v1);
    }

    #[test]
    fn test_missing_patch_defaults_to_zero() {
        let v1: KernelVersion = "6.10".parse().unwrap();
        let v2: KernelVersion = "6.10.0".parse().unwrap();
        assert_eq!(v1, v2);
        assert_eq!(v1.patch, 0);
    }

    #[test]
    fn test_comparison_with_missing_patch() {
        let v1: KernelVersion = "6.10".parse().unwrap();
        let v2: KernelVersion = "6.10.1".parse().unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_comparison_chain() {
        let v1: KernelVersion = "5.15.0".parse().unwrap();
        let v2: KernelVersion = "6.1.0".parse().unwrap();
        let v3: KernelVersion = "6.1.5".parse().unwrap();
        let v4: KernelVersion = "6.17.7".parse().unwrap();

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
        assert!(v1 < v4);
    }

    #[test]
    fn test_ordering_with_suffix() {
        let v1: KernelVersion = "6.10.5-arch1".parse().unwrap();
        let v2: KernelVersion = "6.10.6".parse().unwrap();
        assert!(v1 < v2);
        assert_eq!(v1.patch, 5);
    }

    #[test]
    fn test_major_version_difference_dominates() {
        let v1: KernelVersion = "5.99.99".parse().unwrap();
        let v2: KernelVersion = "6.0.0".parse().unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_minor_version_difference_dominates() {
        let v1: KernelVersion = "6.19.99".parse().unwrap();
        let v2: KernelVersion = "6.20.0".parse().unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_error_on_empty_string() {
        let result: Result<KernelVersion> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_error_on_missing_minor_version() {
        let result: Result<KernelVersion> = "6".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_error_on_invalid_major() {
        let result: Result<KernelVersion> = "abc.10.5".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_error_on_invalid_minor() {
        let result: Result<KernelVersion> = "6.xyz.5".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_error_on_completely_invalid() {
        let result: Result<KernelVersion> = "not-a-version".parse();
        assert!(result.is_err());
    }
}
