// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

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
use zeroize::Zeroize;

use crate::entropy;
use crate::error::{CryptoError, KeepError, Result};

use std::sync::atomic::{AtomicBool, Ordering};

static MLOCK_DISABLED: AtomicBool = AtomicBool::new(false);
static MLOCK_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);

/// Globally disable memory locking for the process.
///
/// When disabled, secret keys will not be locked in memory (mlock),
/// which means they may be paged to disk. This is useful in container
/// environments where mlock may not be available.
pub fn disable_mlock() {
    MLOCK_DISABLED.store(true, Ordering::SeqCst);
}

fn warn_once() {
    if !MLOCK_WARNING_SHOWN.swap(true, Ordering::SeqCst) {
        tracing::warn!(
            "Failed to lock memory. Secrets may be paged to disk. \
             To fix: ulimit -l unlimited (or increase RLIMIT_MEMLOCK)"
        );
    }
}

#[allow(unsafe_code)]
fn try_mlock(ptr: *mut u8, len: usize) -> bool {
    if MLOCK_DISABLED.load(Ordering::SeqCst) {
        return false;
    }
    let locked = unsafe { memsec::mlock(ptr, len) };
    if !locked {
        warn_once();
    }
    locked
}

#[allow(unsafe_code)]
mod mlock {
    use super::try_mlock;
    use std::alloc::{alloc_zeroed, dealloc, Layout};
    use std::ptr::NonNull;
    use zeroize::Zeroize;

    /// Fixed-size memory-locked byte array.
    ///
    /// The contents are locked in memory to prevent swapping and
    /// automatically zeroized when dropped.
    pub struct MlockedBox<const N: usize> {
        ptr: NonNull<[u8; N]>,
        locked: bool,
    }

    impl<const N: usize> MlockedBox<N> {
        /// Creates a new mlocked box from a mutable reference, zeroing the source.
        ///
        /// The source data is copied into mlocked memory and then immediately
        /// zeroed to prevent secrets from remaining on the stack.
        pub fn new(data: &mut [u8; N]) -> Self {
            let layout = Layout::new::<[u8; N]>();
            let raw_ptr = unsafe { alloc_zeroed(layout) as *mut [u8; N] };
            let ptr =
                NonNull::new(raw_ptr).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));

            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.as_ptr() as *mut u8, N) };
            data.zeroize();

            let locked = try_mlock(ptr.as_ptr() as *mut u8, N);
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
            // SAFETY: ptr is guaranteed non-null by NonNull and valid by construction
            unsafe { self.ptr.as_ref() }
        }
    }

    impl<const N: usize> std::ops::DerefMut for MlockedBox<N> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            // SAFETY: ptr is guaranteed non-null by NonNull and valid by construction,
            // and we have exclusive access via &mut self
            unsafe { self.ptr.as_mut() }
        }
    }

    impl<const N: usize> Drop for MlockedBox<N> {
        fn drop(&mut self) {
            // SAFETY: ptr is guaranteed valid by construction, and we own the allocation
            unsafe {
                memsec::memzero(self.ptr.as_ptr() as *mut u8, N);
                if self.locked {
                    memsec::munlock(self.ptr.as_ptr() as *mut u8, N);
                }
                dealloc(self.ptr.as_ptr() as *mut u8, Layout::new::<[u8; N]>());
            }
        }
    }

    impl<const N: usize> Zeroize for MlockedBox<N> {
        fn zeroize(&mut self) {
            // SAFETY: ptr is guaranteed valid by construction
            unsafe { memsec::memzero(self.ptr.as_ptr() as *mut u8, N) };
        }
    }

    // SAFETY: MlockedBox owns its data exclusively (like Box<T>).
    // NonNull<T> is covariant over T and the data is heap-allocated.
    // The type is safe to send/share because it doesn't contain any thread-local
    // state, and all operations on the inner data require &mut self for mutation.
    unsafe impl<const N: usize> Send for MlockedBox<N> {}
    unsafe impl<const N: usize> Sync for MlockedBox<N> {}

    /// Variable-size memory-locked byte vector.
    ///
    /// The contents are locked in memory to prevent swapping and
    /// automatically zeroized when dropped.
    pub struct MlockedVec {
        ptr: NonNull<u8>,
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
            let raw_ptr = data.as_mut_ptr();
            std::mem::forget(data);

            // SAFETY: Vec guarantees a valid, non-null pointer for non-zero capacity.
            // For zero-capacity Vec, we use NonNull::dangling() which is valid for zero-sized access.
            let ptr = NonNull::new(raw_ptr).unwrap_or(NonNull::dangling());
            let locked = if capacity > 0 {
                try_mlock(ptr.as_ptr(), capacity)
            } else {
                false
            };

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
            // SAFETY: ptr and len are valid from Vec construction
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }
    }

    impl Drop for MlockedVec {
        fn drop(&mut self) {
            if self.capacity == 0 {
                return;
            }
            // SAFETY: ptr is valid and we own the allocation from the original Vec
            unsafe {
                memsec::memzero(self.ptr.as_ptr(), self.capacity);
                if self.locked {
                    memsec::munlock(self.ptr.as_ptr(), self.capacity);
                }
                let _ = Vec::from_raw_parts(self.ptr.as_ptr(), self.len, self.capacity);
            }
        }
    }

    impl Zeroize for MlockedVec {
        fn zeroize(&mut self) {
            if self.capacity > 0 {
                // SAFETY: ptr is valid for capacity bytes
                unsafe { memsec::memzero(self.ptr.as_ptr(), self.capacity) };
            }
        }
    }

    // SAFETY: MlockedVec owns its data exclusively (like Vec<T>).
    // NonNull<u8> is used for the heap allocation which we own.
    // The type is safe to send/share because it doesn't contain any thread-local
    // state, and the inner data is only accessed via &self methods.
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

#[allow(missing_docs)]
impl SecretVec {
    pub fn new(mut data: Vec<u8>) -> Result<Self> {
        let mut encrypted = EncryptedMem::new();
        encrypted
            .encrypt(&data)
            .map_err(|_| CryptoError::encryption("encrypt secret in RAM"))?;
        data.zeroize();
        Ok(Self { encrypted })
    }

    pub fn as_slice(&self) -> Result<Vec<u8>> {
        self.encrypted
            .decrypt()
            .map(|z| z.expose_borrowed().to_vec())
            .map_err(|_| CryptoError::decryption("decrypt secret from RAM").into())
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

#[allow(missing_docs)]
impl SecretKey {
    pub fn new(mut bytes: [u8; KEY_SIZE]) -> Result<Self> {
        let mut encrypted = EncryptedMem::new();
        encrypted
            .encrypt(&bytes)
            .map_err(|_| CryptoError::encryption("encrypt key in RAM"))?;
        bytes.zeroize();
        Ok(Self { encrypted })
    }

    pub fn generate() -> Result<Self> {
        let bytes: [u8; KEY_SIZE] = entropy::random_bytes();
        Self::new(bytes)
    }

    pub fn decrypt(&self) -> Result<MlockedBox<KEY_SIZE>> {
        let decrypted = self
            .encrypted
            .decrypt_32byte()
            .map_err(|_| CryptoError::decryption("decrypt key"))?;
        let mut bytes = *decrypted.expose_borrowed();
        Ok(MlockedBox::new(&mut bytes))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != KEY_SIZE {
            return Err(CryptoError::invalid_key("invalid key length").into());
        }
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(slice);
        Self::new(bytes)
    }

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
    .map_err(|e| CryptoError::kdf(format!("argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::kdf(format!("argon2: {}", e)))?;

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
            return Err(CryptoError::decryption("encrypted data too short").into());
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

    let nonce: [u8; NONCE_SIZE] = entropy::random_bytes();
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
    entropy::random_bytes()
}

/// NIP-44 encryption using a raw ECDH shared secret.
///
/// This module implements NIP-44 v2 encryption/decryption for use with
/// threshold ECDH, where the shared secret is computed via distributed
/// key operations rather than from a single private key.
pub mod nip44 {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use super::{entropy, CryptoError, Result};

    const NIP44_SALT: &[u8] = b"nip44-v2";
    #[allow(dead_code)]
    const MIN_PLAINTEXT_SIZE: usize = 1;
    const MAX_PLAINTEXT_SIZE: usize = 65535;

    fn derive_conversation_key(shared_secret: &[u8; 32]) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(NIP44_SALT), shared_secret);
        let mut key = [0u8; 32];
        hk.expand(b"", &mut key)
            .map_err(|_| CryptoError::kdf("NIP-44 conversation key derivation failed"))?;
        Ok(key)
    }

    fn derive_message_keys(
        conversation_key: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
        let hk = Hkdf::<Sha256>::new(Some(nonce), conversation_key);
        let mut keys = [0u8; 96];
        hk.expand(b"nip44-v2", &mut keys)
            .map_err(|_| CryptoError::kdf("NIP-44 message key derivation failed"))?;

        let mut chacha_key = [0u8; 32];
        let mut chacha_nonce = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        chacha_key.copy_from_slice(&keys[0..32]);
        chacha_nonce.copy_from_slice(&keys[32..64]);
        hmac_key.copy_from_slice(&keys[64..96]);

        Ok((chacha_key, chacha_nonce, hmac_key))
    }

    fn pad_plaintext(plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(CryptoError::encryption("Plaintext size out of range").into());
        }

        let len = plaintext.len();
        let padded_len = calc_padded_len(len);
        let mut padded = vec![0u8; 2 + padded_len];
        padded[0] = (len >> 8) as u8;
        padded[1] = (len & 0xff) as u8;
        padded[2..2 + len].copy_from_slice(plaintext);
        Ok(padded)
    }

    fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>> {
        if padded.len() < 2 {
            return Err(CryptoError::decryption("Padded data too short").into());
        }

        let len = ((padded[0] as usize) << 8) | (padded[1] as usize);
        if len == 0 || len > MAX_PLAINTEXT_SIZE || 2 + len > padded.len() {
            return Err(CryptoError::decryption("Invalid plaintext length").into());
        }

        Ok(padded[2..2 + len].to_vec())
    }

    fn calc_padded_len(unpadded_len: usize) -> usize {
        if unpadded_len <= 32 {
            return 32;
        }
        let next_power = (unpadded_len as f64).log2().ceil() as u32;
        let chunk = 2_usize.pow(next_power.max(5) - 5);
        chunk * ((unpadded_len + chunk - 1) / chunk)
    }

    /// Encrypt plaintext using NIP-44 v2 with a raw ECDH shared secret.
    ///
    /// Returns the encrypted payload as raw bytes (version + nonce + ciphertext + MAC).
    pub fn encrypt(shared_secret: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let conversation_key = derive_conversation_key(shared_secret)?;
        let nonce: [u8; 32] = entropy::random_bytes();
        let (chacha_key, chacha_nonce, hmac_key) = derive_message_keys(&conversation_key, &nonce)?;

        let padded = pad_plaintext(plaintext)?;

        let mut ciphertext = padded;
        let mut cipher = XChaCha20::new(
            chacha_key.as_ref().into(),
            chacha_nonce[..24].as_ref().into(),
        );
        cipher.apply_keystream(&mut ciphertext);

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
            .map_err(|_| CryptoError::encryption("Failed to create HMAC"))?;
        mac.update(&nonce);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        let version = 2u8;
        let mut result = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
        result.push(version);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag);

        Ok(result)
    }

    /// Decrypt a NIP-44 v2 payload using a raw ECDH shared secret.
    ///
    /// Takes the encrypted payload as raw bytes and returns the plaintext.
    pub fn decrypt(shared_secret: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 1 + 32 + 2 + 32 {
            return Err(CryptoError::decryption("Payload too short").into());
        }

        let version = payload[0];
        if version != 2 {
            return Err(CryptoError::decryption("Unsupported NIP-44 version").into());
        }

        let nonce: [u8; 32] = payload[1..33]
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid nonce"))?;

        let ciphertext = &payload[33..payload.len() - 32];
        let expected_tag: [u8; 32] = payload[payload.len() - 32..]
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid tag"))?;

        let conversation_key = derive_conversation_key(shared_secret)?;
        let (chacha_key, chacha_nonce, hmac_key) = derive_message_keys(&conversation_key, &nonce)?;

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
            .map_err(|_| CryptoError::decryption("Failed to create HMAC"))?;
        mac.update(&nonce);
        mac.update(ciphertext);
        mac.verify_slice(&expected_tag)
            .map_err(|_| CryptoError::decryption("HMAC verification failed"))?;

        let mut plaintext = ciphertext.to_vec();
        let mut cipher = XChaCha20::new(
            chacha_key.as_ref().into(),
            chacha_nonce[..24].as_ref().into(),
        );
        cipher.apply_keystream(&mut plaintext);

        unpad_plaintext(&plaintext)
    }
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
