//! Cryptographic primitives for key derivation, encryption, and hashing.
//!
//! This module provides:
//! - Argon2id key derivation with configurable parameters
//! - XChaCha20-Poly1305 authenticated encryption
//! - Blake2b-256 hashing
//! - Memory-locked types for sensitive data

#![deny(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    XChaCha20Poly1305,
};
use memsecurity::EncryptedMem;
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::{KeepError, Result};

#[allow(unsafe_code)]
mod mlock {
    use std::alloc::{alloc_zeroed, dealloc, Layout};
    use zeroize::Zeroize;

    /// Fixed-size memory-locked byte array.
    ///
    /// The contents are locked in memory to prevent swapping and
    /// automatically zeroized when dropped.
    pub struct MlockedBox<const N: usize> {
        ptr: *mut [u8; N],
        locked: bool,
    }

    impl<const N: usize> MlockedBox<N> {
        /// Creates a new mlocked box from a mutable reference, zeroing the source.
        ///
        /// The source data is copied into mlocked memory and then immediately
        /// zeroed to prevent secrets from remaining on the stack.
        pub fn new(data: &mut [u8; N]) -> Self {
            let layout = Layout::new::<[u8; N]>();
            let ptr = unsafe { alloc_zeroed(layout) as *mut [u8; N] };
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }

            // Copy data to mlocked memory
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, N) };

            // Zero the source immediately
            data.zeroize();

            let locked = unsafe { memsec::mlock(ptr as *mut u8, N) };

            Self { ptr, locked }
        }

        /// Returns true if the memory is successfully locked.
        #[allow(dead_code)]
        pub fn is_locked(&self) -> bool {
            self.locked
        }
    }

    impl<const N: usize> std::ops::Deref for MlockedBox<N> {
        type Target = [u8; N];

        fn deref(&self) -> &Self::Target {
            unsafe { &*self.ptr }
        }
    }

    impl<const N: usize> std::ops::DerefMut for MlockedBox<N> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            unsafe { &mut *self.ptr }
        }
    }

    impl<const N: usize> Drop for MlockedBox<N> {
        fn drop(&mut self) {
            unsafe {
                memsec::memzero(self.ptr as *mut u8, N);
                if self.locked {
                    memsec::munlock(self.ptr as *mut u8, N);
                }
                dealloc(self.ptr as *mut u8, Layout::new::<[u8; N]>());
            }
        }
    }

    impl<const N: usize> Zeroize for MlockedBox<N> {
        fn zeroize(&mut self) {
            unsafe { memsec::memzero(self.ptr as *mut u8, N) };
        }
    }

    unsafe impl<const N: usize> Send for MlockedBox<N> {}
    unsafe impl<const N: usize> Sync for MlockedBox<N> {}

    /// Variable-size memory-locked byte vector.
    ///
    /// The contents are locked in memory to prevent swapping and
    /// automatically zeroized when dropped.
    pub struct MlockedVec {
        ptr: *mut u8,
        len: usize,
        capacity: usize,
        locked: bool,
    }

    impl MlockedVec {
        /// Creates a new mlocked vec, taking ownership and locking the memory.
        ///
        /// Note: The Vec's memory is locked in place. The original allocation
        /// is preserved (not copied), so this is efficient for large data.
        pub fn new(mut data: Vec<u8>) -> Self {
            let len = data.len();
            let capacity = data.capacity();
            let ptr = data.as_mut_ptr();
            std::mem::forget(data);

            let locked = unsafe { memsec::mlock(ptr, capacity) };

            Self {
                ptr,
                len,
                capacity,
                locked,
            }
        }

        /// Returns true if the memory is successfully locked.
        #[allow(dead_code)]
        pub fn is_locked(&self) -> bool {
            self.locked
        }

        /// Returns a slice view of the locked data.
        pub fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }

    impl Drop for MlockedVec {
        fn drop(&mut self) {
            unsafe {
                // Zero the full capacity, not just len, to catch any leftover data
                memsec::memzero(self.ptr, self.capacity);
                if self.locked {
                    memsec::munlock(self.ptr, self.capacity);
                }
                let _ = Vec::from_raw_parts(self.ptr, self.len, self.capacity);
            }
        }
    }

    impl Zeroize for MlockedVec {
        fn zeroize(&mut self) {
            unsafe { memsec::memzero(self.ptr, self.capacity) };
        }
    }

    unsafe impl Send for MlockedVec {}
    unsafe impl Sync for MlockedVec {}
}

pub use mlock::{MlockedBox, MlockedVec};

/// Salt size for key derivation.
pub const SALT_SIZE: usize = 32;

/// Variable-length secret stored encrypted in RAM.
pub struct SecretVec {
    encrypted: EncryptedMem,
}

impl SecretVec {
    /// Encrypt data into a new SecretVec.
    pub fn new(mut data: Vec<u8>) -> Result<Self> {
        let mut encrypted = EncryptedMem::new();
        encrypted
            .encrypt(&data)
            .map_err(|_| KeepError::Other("Failed to encrypt secret in RAM".into()))?;
        data.zeroize();
        Ok(Self { encrypted })
    }

    /// Decrypt and return the data.
    pub fn as_slice(&self) -> Result<Vec<u8>> {
        self.encrypted
            .decrypt()
            .map(|z| z.expose_borrowed().to_vec())
            .map_err(|_| KeepError::Other("Failed to decrypt secret from RAM".into()))
    }
}

/// XChaCha20-Poly1305 nonce size.
pub const NONCE_SIZE: usize = 24;
/// Encryption key size.
pub const KEY_SIZE: usize = 32;
/// Authentication tag size.
pub const TAG_SIZE: usize = 16;

/// Parameters for Argon2id key derivation.
#[derive(Clone, Copy)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of iterations.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl Argon2Params {
    /// Fast parameters for testing only.
    pub const TESTING: Self = Self {
        memory_kib: 1024,
        iterations: 1,
        parallelism: 1,
    };

    /// Default parameters (256 MiB memory, 4 iterations).
    pub const DEFAULT: Self = Self {
        memory_kib: 256 * 1024,
        iterations: 4,
        parallelism: 4,
    };

    /// High security parameters (512 MiB memory, 6 iterations).
    pub const HIGH: Self = Self {
        memory_kib: 512 * 1024,
        iterations: 6,
        parallelism: 4,
    };
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A 32-byte encryption key stored encrypted in RAM.
pub struct SecretKey {
    encrypted: EncryptedMem,
}

impl SecretKey {
    /// Encrypt raw bytes into a new SecretKey.
    pub fn new(mut bytes: [u8; KEY_SIZE]) -> Result<Self> {
        let mut encrypted = EncryptedMem::new();
        encrypted
            .encrypt(&bytes)
            .map_err(|_| KeepError::Other("Failed to encrypt key in RAM".into()))?;
        bytes.zeroize();
        Ok(Self { encrypted })
    }

    /// Generate a new random encryption key.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEY_SIZE];
        rand::rng().fill_bytes(&mut bytes);
        Self::new(bytes)
    }

    /// Decrypt into memory-locked storage.
    pub fn decrypt(&self) -> Result<MlockedBox<KEY_SIZE>> {
        let decrypted = self
            .encrypted
            .decrypt_32byte()
            .map_err(|_| KeepError::Other("Failed to decrypt key".into()))?;
        let mut bytes = *decrypted.expose_borrowed();
        Ok(MlockedBox::new(&mut bytes))
    }

    /// Create a SecretKey from a byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != KEY_SIZE {
            return Err(KeepError::Other("Invalid key length".into()));
        }
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(slice);
        Self::new(bytes)
    }

    /// Clone the key. Returns an error if RAM encryption fails.
    pub fn try_clone(&self) -> Result<Self> {
        let decrypted = self.decrypt()?;
        Self::new(*decrypted)
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        self.try_clone()
            .expect("SecretKey clone failed: RAM encryption invariant violated")
    }
}

/// Derive an encryption key from a password using Argon2id.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    params: Argon2Params,
) -> Result<SecretKey> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_SIZE),
    )
    .map_err(|e| KeepError::Other(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| KeepError::Other(format!("Argon2 error: {}", e)))?;

    SecretKey::new(output)
}

/// Derive a subkey from a master key using domain separation.
pub fn derive_subkey(master_key: &SecretKey, context: &[u8]) -> Result<SecretKey> {
    let decrypted = master_key.decrypt()?;
    let mut hasher = Blake2b512::new();
    hasher.update(*decrypted);
    hasher.update(context);
    let result = hasher.finalize();

    let mut output = [0u8; KEY_SIZE];
    output.copy_from_slice(&result[..KEY_SIZE]);
    SecretKey::new(output)
}

/// Encrypted data with nonce for authenticated decryption.
#[derive(Clone)]
pub struct EncryptedData {
    /// The encrypted ciphertext with authentication tag.
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption.
    pub nonce: [u8; NONCE_SIZE],
}

impl EncryptedData {
    /// Serialize to bytes: nonce || ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(NONCE_SIZE + self.ciphertext.len());
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Deserialize from bytes: nonce || ciphertext.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NONCE_SIZE + TAG_SIZE {
            return Err(KeepError::Other("Encrypted data too short".into()));
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[..NONCE_SIZE]);

        Ok(Self {
            nonce,
            ciphertext: bytes[NONCE_SIZE..].to_vec(),
        })
    }
}

/// Encrypt plaintext using XChaCha20-Poly1305.
pub fn encrypt(plaintext: &[u8], key: &SecretKey) -> Result<EncryptedData> {
    let decrypted = key.decrypt()?;
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&*decrypted));

    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_ga = GenericArray::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce_ga, plaintext)
        .map_err(|_| KeepError::Encryption("Encryption failed".into()))?;

    Ok(EncryptedData { ciphertext, nonce })
}

/// Decrypt ciphertext using XChaCha20-Poly1305.
pub fn decrypt(encrypted: &EncryptedData, key: &SecretKey) -> Result<SecretVec> {
    let decrypted_key = key.decrypt()?;
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&*decrypted_key));
    let nonce = GenericArray::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| KeepError::DecryptionFailed)?;

    SecretVec::new(plaintext)
}

/// Compute Blake2b-256 hash of data.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output
}

/// Generate cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = b"test password";
        let salt: [u8; SALT_SIZE] = random_bytes();

        let key1 = derive_key(password, &salt, Argon2Params::TESTING).unwrap();
        let key2 = derive_key(password, &salt, Argon2Params::TESTING).unwrap();

        assert_eq!(&*key1.decrypt().unwrap(), &*key2.decrypt().unwrap());

        let key3 = derive_key(b"different", &salt, Argon2Params::TESTING).unwrap();
        assert_ne!(&*key1.decrypt().unwrap(), &*key3.decrypt().unwrap());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SecretKey::generate().unwrap();
        let plaintext = b"Hello, Keep!";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(
            plaintext.as_slice(),
            decrypted.as_slice().unwrap().as_slice()
        );
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = SecretKey::generate().unwrap();
        let wrong_key = SecretKey::generate().unwrap();
        let plaintext = b"Secret data";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let result = decrypt(&encrypted, &wrong_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_subkey_derivation() {
        let master = SecretKey::generate().unwrap();

        let subkey1 = derive_subkey(&master, b"header").unwrap();
        let subkey2 = derive_subkey(&master, b"data").unwrap();

        assert_ne!(&*subkey1.decrypt().unwrap(), &*subkey2.decrypt().unwrap());

        let subkey1_again = derive_subkey(&master, b"header").unwrap();
        assert_eq!(
            &*subkey1.decrypt().unwrap(),
            &*subkey1_again.decrypt().unwrap()
        );
    }

    #[test]
    fn test_secret_key_encrypted_in_ram() {
        let key = SecretKey::generate().unwrap();
        let decrypted = key.decrypt().unwrap();
        assert!(!decrypted.iter().all(|&b| b == 0));
    }
}
