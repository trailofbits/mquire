//
// Copyright (c) 2025-present, Trail of Bits, Inc.
// All rights reserved.
//
// This source code is licensed in accordance with the terms specified in
// the LICENSE file found in the root directory of this source tree.
//

use crate::memory::{error::Result, primitives::PhysicalAddress, readable::Readable};

/// Provides a convenient interface for reading from a Readable instance
pub struct Reader<'a> {
    /// The Readable instance
    readable: &'a dyn Readable,

    /// The endianness of the target architecture
    little_endian: bool,
}

impl<'a> Reader<'a> {
    /// Creates a new Reader instance
    pub fn new(readable: &'a dyn Readable, little_endian: bool) -> Self {
        Reader {
            readable,
            little_endian,
        }
    }

    /// Reads the specified number of bytes from the given physical address
    pub fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
        self.readable.read(buffer, physical_address)
    }

    /// Returns the size of the readable instance
    pub fn len(&self) -> Result<u64> {
        self.readable.len()
    }

    /// Returns true if the readable instance is empty
    pub fn is_empty(&self) -> Result<bool> {
        self.readable.is_empty()
    }

    /// Reads a single unsigned byte from the given physical address
    pub fn read_u8(&self, physical_address: PhysicalAddress) -> Result<u8> {
        let mut buffer = [0; 1];
        self.readable.read_exact(&mut buffer, physical_address)?;
        Ok(buffer[0])
    }

    /// Reads a 16-bit unsigned integer from the given physical address
    pub fn read_u16(&self, physical_address: PhysicalAddress) -> Result<u16> {
        let mut buffer = [0; 2];
        self.readable.read_exact(&mut buffer, physical_address)?;

        match self.little_endian {
            true => Ok(u16::from_le_bytes(buffer)),
            false => Ok(u16::from_be_bytes(buffer)),
        }
    }

    /// Reads a 32-bit unsigned integer from the given physical address
    pub fn read_u32(&self, physical_address: PhysicalAddress) -> Result<u32> {
        let mut buffer = [0; 4];
        self.readable.read_exact(&mut buffer, physical_address)?;

        match self.little_endian {
            true => Ok(u32::from_le_bytes(buffer)),
            false => Ok(u32::from_be_bytes(buffer)),
        }
    }

    /// Reads a 64-bit unsigned integer from the given physical address
    pub fn read_u64(&self, physical_address: PhysicalAddress) -> Result<u64> {
        let mut buffer = [0; 8];
        self.readable.read_exact(&mut buffer, physical_address)?;

        match self.little_endian {
            true => Ok(u64::from_le_bytes(buffer)),
            false => Ok(u64::from_be_bytes(buffer)),
        }
    }

    /// Reads a single signed byte from the given physical address
    pub fn read_i8(&self, physical_address: PhysicalAddress) -> Result<i8> {
        self.read_u8(physical_address).map(|value| value as i8)
    }

    /// Reads a 16-bit signed integer from the given physical address
    pub fn read_i16(&self, physical_address: PhysicalAddress) -> Result<i16> {
        self.read_u16(physical_address).map(|value| value as i16)
    }

    /// Reads a 32-bit signed integer from the given physical address
    pub fn read_i32(&self, physical_address: PhysicalAddress) -> Result<i32> {
        self.read_u32(physical_address).map(|value| value as i32)
    }

    /// Reads a 64-bit signed integer from the given physical address
    pub fn read_i64(&self, physical_address: PhysicalAddress) -> Result<i64> {
        self.read_u64(physical_address).map(|value| value as i64)
    }
}
#[cfg(test)]
mod tests {
    use crate::memory::{
        error::{Error, ErrorKind, Result},
        primitives::PhysicalAddress,
        readable::Readable,
    };

    use super::*;

    struct ReadableBuffer {
        data: Vec<u8>,
    }

    impl ReadableBuffer {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl Readable for ReadableBuffer {
        fn read(&self, buffer: &mut [u8], physical_address: PhysicalAddress) -> Result<usize> {
            let offset = physical_address.value() as usize;
            if offset + buffer.len() > self.data.len() {
                return Err(Error::new(
                    ErrorKind::IOError,
                    "Attempted to read past the end of the buffer",
                ));
            }

            buffer.copy_from_slice(&self.data[offset..offset + buffer.len()]);
            Ok(buffer.len())
        }

        fn len(&self) -> Result<u64> {
            Ok(self.data.len() as u64)
        }
    }

    #[test]
    fn test_read_u8() {
        for little_endiann in [false, true] {
            let readable = ReadableBuffer::new(vec![0x11]);
            let reader = Reader::new(&readable, little_endiann);
            assert_eq!(reader.read_u8(PhysicalAddress::default()).unwrap(), 0x11);

            let readable = ReadableBuffer::new(vec![]);
            let reader = Reader::new(&readable, little_endiann);

            assert_eq!(
                reader
                    .read_u8(PhysicalAddress::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::IOError
            );
        }
    }

    #[test]
    fn test_read_u16() {
        for little_endiann in [false, true] {
            let readable = ReadableBuffer::new(vec![0x11, 0x22]);
            let reader = Reader::new(&readable, little_endiann);

            let expected_value = match little_endiann {
                false => 0x1122,
                true => 0x2211,
            };

            assert_eq!(
                reader.read_u16(PhysicalAddress::default()).unwrap(),
                expected_value
            );

            let readable = ReadableBuffer::new(vec![]);
            let reader = Reader::new(&readable, little_endiann);

            assert_eq!(
                reader
                    .read_u16(PhysicalAddress::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::IOError
            );
        }
    }

    #[test]
    fn test_read_u32() {
        for little_endiann in [false, true] {
            let readable = ReadableBuffer::new(vec![0x11, 0x22, 0x33, 0x44]);
            let reader = Reader::new(&readable, little_endiann);

            let expected_value = match little_endiann {
                false => 0x11223344,
                true => 0x44332211,
            };

            assert_eq!(
                reader.read_u32(PhysicalAddress::default()).unwrap(),
                expected_value
            );

            let readable = ReadableBuffer::new(vec![]);
            let reader = Reader::new(&readable, little_endiann);

            assert_eq!(
                reader
                    .read_u32(PhysicalAddress::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::IOError
            );
        }
    }

    #[test]
    fn test_read_u64() {
        for little_endiann in [false, true] {
            let readable =
                ReadableBuffer::new(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

            let reader = Reader::new(&readable, little_endiann);

            let expected_value = match little_endiann {
                false => 0x1122334455667788,
                true => 0x8877665544332211,
            };

            assert_eq!(
                reader.read_u64(PhysicalAddress::default()).unwrap(),
                expected_value
            );

            let readable = ReadableBuffer::new(vec![]);
            let reader = Reader::new(&readable, little_endiann);

            assert_eq!(
                reader
                    .read_u64(PhysicalAddress::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::IOError
            );
        }
    }

    #[test]
    fn test_read_i8() {
        for little_endiann in [false, true] {
            let readable = ReadableBuffer::new(vec![0xFF]);
            let reader = Reader::new(&readable, little_endiann);
            assert_eq!(reader.read_i8(PhysicalAddress::default()).unwrap(), -1);

            let readable = ReadableBuffer::new(vec![]);
            let reader = Reader::new(&readable, little_endiann);

            assert_eq!(
                reader
                    .read_i8(PhysicalAddress::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::IOError
            );
        }
    }

    #[test]
    fn test_read_i16() {
        let test_data = [0xFF, 0x7F];

        for little_endiann in [false, true] {
            let readable = ReadableBuffer::new(test_data.to_vec());
            let reader = Reader::new(&readable, little_endiann);

            let expected_value = match little_endiann {
                false => i16::from_be_bytes(test_data),
                true => i16::from_le_bytes(test_data),
            };

            assert_eq!(
                reader.read_i16(PhysicalAddress::default()).unwrap(),
                expected_value
            );

            let readable = ReadableBuffer::new(vec![]);
            let reader = Reader::new(&readable, little_endiann);

            assert_eq!(
                reader
                    .read_i16(PhysicalAddress::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::IOError
            );
        }
    }

    #[test]
    fn test_read_i32() {
        let test_data = [0xFF, 0xFF, 0xFF, 0x7F];

        for little_endiann in [false, true] {
            let readable = ReadableBuffer::new(test_data.to_vec());
            let reader = Reader::new(&readable, little_endiann);

            let expected_value = match little_endiann {
                false => i32::from_be_bytes(test_data),
                true => i32::from_le_bytes(test_data),
            };

            assert_eq!(
                reader.read_i32(PhysicalAddress::default()).unwrap(),
                expected_value
            );

            let readable = ReadableBuffer::new(vec![]);
            let reader = Reader::new(&readable, little_endiann);

            assert_eq!(
                reader
                    .read_i32(PhysicalAddress::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::IOError
            );
        }
    }

    #[test]
    fn test_read_i64() {
        let test_data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];

        for little_endiann in [false, true] {
            let readable = ReadableBuffer::new(test_data.to_vec());
            let reader = Reader::new(&readable, little_endiann);

            let expected_value = match little_endiann {
                false => i64::from_be_bytes(test_data),
                true => i64::from_le_bytes(test_data),
            };

            assert_eq!(
                reader.read_i64(PhysicalAddress::default()).unwrap(),
                expected_value
            );

            let readable = ReadableBuffer::new(vec![]);
            let reader = Reader::new(&readable, little_endiann);

            assert_eq!(
                reader
                    .read_i64(PhysicalAddress::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::IOError
            );
        }
    }

    #[test]
    fn test_read() {
        let data = vec![0x11, 0x22, 0x33, 0x44];
        let readable = ReadableBuffer::new(data.clone());
        let reader = Reader::new(&readable, true);

        let mut buffer = [0u8; 4];
        reader
            .read(&mut buffer, PhysicalAddress::default())
            .unwrap();

        assert_eq!(buffer, [0x11, 0x22, 0x33, 0x44]);

        let mut buffer = [0u8; 2];
        reader
            .read(&mut buffer, PhysicalAddress::default())
            .unwrap();

        assert_eq!(buffer, [0x11, 0x22]);

        let mut buffer = [0u8; 2];
        reader.read(&mut buffer, PhysicalAddress::from(2)).unwrap();
        assert_eq!(buffer, [0x33, 0x44]);

        let mut buffer = [0u8; 8];
        let err = reader
            .read(&mut buffer, PhysicalAddress::default())
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::IOError);
    }

    #[test]
    fn test_len() {
        let data = vec![0x11, 0x22, 0x33, 0x44, 0x55];
        let readable = ReadableBuffer::new(data.clone());
        let reader = Reader::new(&readable, false);
        assert_eq!(reader.len().unwrap(), 5);

        let empty = ReadableBuffer::new(vec![]);
        let reader = Reader::new(&empty, true);
        assert_eq!(reader.len().unwrap(), 0);
    }

    #[test]
    fn test_is_empty() {
        let data = vec![0x11];
        let readable = ReadableBuffer::new(data);
        let reader = Reader::new(&readable, false);
        assert!(!reader.is_empty().unwrap());

        let empty = ReadableBuffer::new(vec![]);
        let reader = Reader::new(&empty, true);
        assert!(reader.is_empty().unwrap());
    }
}
