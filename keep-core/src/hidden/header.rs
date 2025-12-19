#![forbid(unsafe_code)]

use subtle::ConstantTimeEq;

use crate::crypto::{self, Argon2Params, SALT_SIZE};
use crate::error::{KeepError, Result};

pub const HEADER_SIZE: usize = 512;
pub const OUTER_HEADER_OFFSET: u64 = 0;
pub const HIDDEN_HEADER_OFFSET: u64 = 512;
pub const DATA_START_OFFSET: u64 = 1024;

pub const OUTER_MAGIC: &[u8; 8] = b"KEEPVALT";

#[derive(Clone)]
#[repr(C)]
pub struct OuterHeader {
    pub magic: [u8; 8],
    pub version: u16,
    pub flags: u16,
    pub reserved: u32,
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; 24],
    pub encrypted_data_key: [u8; 48],
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    pub _align_pad: u32,
    pub outer_data_size: u64,
    pub total_size: u64,
    pub padding: [u8; 360],
}

impl OuterHeader {
    pub fn new(params: Argon2Params, outer_size: u64, total_size: u64) -> Self {
        Self {
            magic: *OUTER_MAGIC,
            version: 1,
            flags: 0,
            reserved: 0,
            salt: crypto::random_bytes(),
            nonce: crypto::random_bytes(),
            encrypted_data_key: [0; 48],
            argon2_memory_kib: params.memory_kib,
            argon2_iterations: params.iterations,
            argon2_parallelism: params.parallelism,
            _align_pad: 0,
            outer_data_size: outer_size,
            total_size,
            padding: [0; 360],
        }
    }

    pub fn argon2_params(&self) -> Argon2Params {
        Argon2Params {
            memory_kib: self.argon2_memory_kib,
            iterations: self.argon2_iterations,
            parallelism: self.argon2_parallelism,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        let mut offset = 0;

        bytes[offset..offset + 8].copy_from_slice(&self.magic);
        offset += 8;

        bytes[offset..offset + 2].copy_from_slice(&self.version.to_le_bytes());
        offset += 2;
        bytes[offset..offset + 2].copy_from_slice(&self.flags.to_le_bytes());
        offset += 2;
        bytes[offset..offset + 4].copy_from_slice(&self.reserved.to_le_bytes());
        offset += 4;

        bytes[offset..offset + SALT_SIZE].copy_from_slice(&self.salt);
        offset += SALT_SIZE;
        bytes[offset..offset + 24].copy_from_slice(&self.nonce);
        offset += 24;
        bytes[offset..offset + 48].copy_from_slice(&self.encrypted_data_key);
        offset += 48;

        bytes[offset..offset + 4].copy_from_slice(&self.argon2_memory_kib.to_le_bytes());
        offset += 4;
        bytes[offset..offset + 4].copy_from_slice(&self.argon2_iterations.to_le_bytes());
        offset += 4;
        bytes[offset..offset + 4].copy_from_slice(&self.argon2_parallelism.to_le_bytes());
        offset += 4;
        bytes[offset..offset + 4].copy_from_slice(&self._align_pad.to_le_bytes());
        offset += 4;

        bytes[offset..offset + 8].copy_from_slice(&self.outer_data_size.to_le_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.total_size.to_le_bytes());

        bytes
    }

    pub fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> Result<Self> {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);

        if magic != *OUTER_MAGIC {
            return Err(KeepError::Other("Invalid keep file".into()));
        }

        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version > 1 {
            return Err(KeepError::Other("Unsupported version".into()));
        }

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&bytes[16..16 + SALT_SIZE]);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[16 + SALT_SIZE..16 + SALT_SIZE + 24]);

        let mut encrypted_data_key = [0u8; 48];
        encrypted_data_key.copy_from_slice(&bytes[16 + SALT_SIZE + 24..16 + SALT_SIZE + 24 + 48]);

        let offset = 16 + SALT_SIZE + 24 + 48;

        Ok(Self {
            magic,
            version,
            flags: u16::from_le_bytes([bytes[10], bytes[11]]),
            reserved: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            salt,
            nonce,
            encrypted_data_key,
            argon2_memory_kib: u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
            argon2_iterations: u32::from_le_bytes(
                bytes[offset + 4..offset + 8].try_into().unwrap(),
            ),
            argon2_parallelism: u32::from_le_bytes(
                bytes[offset + 8..offset + 12].try_into().unwrap(),
            ),
            _align_pad: u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().unwrap()),
            outer_data_size: u64::from_le_bytes(
                bytes[offset + 16..offset + 24].try_into().unwrap(),
            ),
            total_size: u64::from_le_bytes(bytes[offset + 24..offset + 32].try_into().unwrap()),
            padding: [0; 360],
        })
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct HiddenHeader {
    pub version: u16,
    pub reserved: u16,
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; 24],
    pub encrypted_data_key: [u8; 48],
    pub _align_pad: u32,
    pub hidden_data_offset: u64,
    pub hidden_data_size: u64,
    pub checksum: [u8; 32],
    pub padding: [u8; 352],
}

impl HiddenHeader {
    pub fn new(hidden_offset: u64, hidden_size: u64) -> Self {
        let mut header = Self {
            version: 1,
            reserved: 0,
            salt: crypto::random_bytes(),
            nonce: crypto::random_bytes(),
            encrypted_data_key: [0; 48],
            _align_pad: 0,
            hidden_data_offset: hidden_offset,
            hidden_data_size: hidden_size,
            checksum: [0; 32],
            padding: [0; 352],
        };

        header.checksum = header.compute_checksum();
        header
    }

    pub fn compute_checksum(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.reserved.to_le_bytes());
        data.extend_from_slice(&self.salt);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.encrypted_data_key);
        data.extend_from_slice(&self.hidden_data_offset.to_le_bytes());
        data.extend_from_slice(&self.hidden_data_size.to_le_bytes());

        crypto::blake2b_256(&data)
    }

    pub fn verify_checksum(&self) -> bool {
        let expected = self.compute_checksum();
        expected.ct_eq(&self.checksum).into()
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        let compact = self.to_bytes_compact();
        bytes[..compact.len()].copy_from_slice(&compact);
        bytes
    }

    pub fn to_bytes_compact(&self) -> [u8; Self::COMPACT_SIZE] {
        let mut bytes = [0u8; Self::COMPACT_SIZE];
        let mut offset = 0;

        bytes[offset..offset + 2].copy_from_slice(&self.version.to_le_bytes());
        offset += 2;
        bytes[offset..offset + 2].copy_from_slice(&self.reserved.to_le_bytes());
        offset += 2;
        bytes[offset..offset + SALT_SIZE].copy_from_slice(&self.salt);
        offset += SALT_SIZE;
        bytes[offset..offset + 24].copy_from_slice(&self.nonce);
        offset += 24;
        bytes[offset..offset + 48].copy_from_slice(&self.encrypted_data_key);
        offset += 48;
        bytes[offset..offset + 4].copy_from_slice(&self._align_pad.to_le_bytes());
        offset += 4;
        bytes[offset..offset + 8].copy_from_slice(&self.hidden_data_offset.to_le_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.hidden_data_size.to_le_bytes());
        offset += 8;
        bytes[offset..offset + 32].copy_from_slice(&self.checksum);

        bytes
    }

    pub const COMPACT_SIZE: usize = 2 + 2 + SALT_SIZE + 24 + 48 + 4 + 8 + 8 + 32;

    pub fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> Result<Self> {
        Self::from_bytes_compact(bytes)
    }

    pub fn from_bytes_compact(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::COMPACT_SIZE {
            return Err(KeepError::Other(format!(
                "Hidden header too short: {} bytes, expected at least {}",
                bytes.len(),
                Self::COMPACT_SIZE
            )));
        }

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&bytes[4..4 + SALT_SIZE]);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[4 + SALT_SIZE..4 + SALT_SIZE + 24]);

        let mut encrypted_data_key = [0u8; 48];
        encrypted_data_key.copy_from_slice(&bytes[4 + SALT_SIZE + 24..4 + SALT_SIZE + 72]);

        let offset = 4 + SALT_SIZE + 72;

        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&bytes[offset + 20..offset + 52]);

        Ok(Self {
            version: u16::from_le_bytes([bytes[0], bytes[1]]),
            reserved: u16::from_le_bytes([bytes[2], bytes[3]]),
            salt,
            nonce,
            encrypted_data_key,
            _align_pad: u32::from_le_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| KeepError::Other("Invalid hidden header: align_pad".into()))?,
            ),
            hidden_data_offset: u64::from_le_bytes(
                bytes[offset + 4..offset + 12]
                    .try_into()
                    .map_err(|_| KeepError::Other("Invalid hidden header: data_offset".into()))?,
            ),
            hidden_data_size: u64::from_le_bytes(
                bytes[offset + 12..offset + 20]
                    .try_into()
                    .map_err(|_| KeepError::Other("Invalid hidden header: data_size".into()))?,
            ),
            checksum,
            padding: [0; 352],
        })
    }
}

const _: () = assert!(std::mem::size_of::<OuterHeader>() == HEADER_SIZE);
const _: () = assert!(std::mem::size_of::<HiddenHeader>() == HEADER_SIZE);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outer_header_roundtrip() {
        let header = OuterHeader::new(Argon2Params::TESTING, 1000, 2000);
        let bytes = header.to_bytes();
        let parsed = OuterHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, header.magic);
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(parsed.outer_data_size, 1000);
        assert_eq!(parsed.total_size, 2000);
    }

    #[test]
    fn test_hidden_header_roundtrip() {
        let header = HiddenHeader::new(1024, 500);
        let bytes = header.to_bytes();
        let parsed = HiddenHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(parsed.hidden_data_offset, 1024);
        assert_eq!(parsed.hidden_data_size, 500);
        assert!(parsed.verify_checksum());
    }

    #[test]
    fn test_hidden_header_checksum_detects_corruption() {
        let mut header = HiddenHeader::new(1024, 500);
        header.hidden_data_size = 999;
        assert!(!header.verify_checksum());
    }

    #[test]
    fn test_outer_header_invalid_magic() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..8].copy_from_slice(b"BADMAGIC");
        let result = OuterHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }
}
