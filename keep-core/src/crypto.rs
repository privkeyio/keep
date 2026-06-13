// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

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
use zeroize::{Zeroize, Zeroizing};

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

            if capacity == 0 {
                return Self {
                    ptr: NonNull::dangling(),
                    len: 0,
                    capacity: 0,
                    locked: false,
                };
            }

            let raw_ptr = data.as_mut_ptr();
            std::mem::forget(data);

            // SAFETY: Vec guarantees a valid, non-null pointer for non-zero capacity.
            let ptr = NonNull::new(raw_ptr).expect("non-zero capacity Vec had null pointer");
            let locked = try_mlock(ptr.as_ptr(), capacity);

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
                let _ = Vec::from_raw_parts(self.ptr.as_ptr(), 0, self.capacity);
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

    pub fn as_slice(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.encrypted
            .decrypt()
            .map(|z| Zeroizing::new(z.expose_borrowed().to_vec()))
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
    /// Fast parameters for testing only. Do not use in production.
    #[cfg(any(test, feature = "testing"))]
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
    .map_err(|e| CryptoError::kdf(format!("argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::kdf(format!("argon2: {e}")))?;

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
    encrypt_with_aad(plaintext, &[], key)
}

/// Decrypt ciphertext using XChaCha20-Poly1305.
pub fn decrypt(encrypted: &EncryptedData, key: &SecretKey) -> Result<SecretVec> {
    decrypt_with_aad(encrypted, &[], key)
}

/// Encrypt plaintext using XChaCha20-Poly1305 with additional authenticated data.
///
/// The `aad` is authenticated but not encrypted; decryption fails unless the
/// same `aad` is supplied. Passing an empty slice is byte-identical to [`encrypt`].
pub fn encrypt_with_aad(plaintext: &[u8], aad: &[u8], key: &SecretKey) -> Result<EncryptedData> {
    use chacha20poly1305::aead::Payload;

    let decrypted = key.decrypt()?;
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&*decrypted));

    let nonce: [u8; NONCE_SIZE] = entropy::random_bytes();
    let nonce_ga = GenericArray::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(
            nonce_ga,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeepError::Encryption("Encryption failed".into()))?;

    Ok(EncryptedData { ciphertext, nonce })
}

/// Decrypt ciphertext using XChaCha20-Poly1305 with additional authenticated data.
///
/// Passing an empty `aad` slice is byte-identical to [`decrypt`].
pub fn decrypt_with_aad(
    encrypted: &EncryptedData,
    aad: &[u8],
    key: &SecretKey,
) -> Result<SecretVec> {
    use chacha20poly1305::aead::Payload;

    let decrypted_key = key.decrypt()?;
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&*decrypted_key));
    let nonce = GenericArray::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: encrypted.ciphertext.as_ref(),
                aad,
            },
        )
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

/// HMAC-SHA256 of `data` keyed by `key`. Keyed so the output is a MAC (forgeable
/// only with the key), used for tamper-evident hash chains such as the NIP-55
/// signing-audit log. Accepts a key of any length (HMAC pads/hashes as needed).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    let result = mac.finalize().into_bytes();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
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
    use chacha20::cipher::StreamCipher;
    use chacha20::{ChaCha20, KeyIvInit, XChaCha20};
    use hkdf::Hkdf;
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use super::{entropy, CryptoError, Result};
    use zeroize::Zeroizing;

    const NIP44_SALT: &[u8] = b"nip44-v2";
    #[allow(dead_code)]
    const MIN_PLAINTEXT_SIZE: usize = 1;
    const MAX_PLAINTEXT_SIZE: usize = 65535;

    fn derive_conversation_key(shared_secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let hk = Hkdf::<Sha256>::new(Some(NIP44_SALT), shared_secret);
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(b"", key.as_mut())
            .map_err(|_| CryptoError::kdf("NIP-44 conversation key derivation failed"))?;
        Ok(key)
    }

    #[allow(clippy::type_complexity)]
    fn derive_message_keys(
        conversation_key: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<(Zeroizing<[u8; 32]>, [u8; 32], Zeroizing<[u8; 32]>)> {
        let hk = Hkdf::<Sha256>::new(Some(nonce), conversation_key);
        let mut keys = Zeroizing::new([0u8; 96]);
        hk.expand(b"nip44-v2", keys.as_mut())
            .map_err(|_| CryptoError::kdf("NIP-44 message key derivation failed"))?;

        let mut chacha_key = Zeroizing::new([0u8; 32]);
        let mut chacha_nonce = [0u8; 32];
        let mut hmac_key = Zeroizing::new([0u8; 32]);
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
        chunk * unpadded_len.div_ceil(chunk)
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
            (&*chacha_key).into(),
            <&[u8; 24]>::try_from(&chacha_nonce[..24])
                .expect("chacha_nonce is 32 bytes; first 24 always valid")
                .into(),
        );
        cipher.apply_keystream(&mut ciphertext);

        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(hmac_key.as_ref())
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

        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(hmac_key.as_ref())
            .map_err(|_| CryptoError::decryption("Failed to create HMAC"))?;
        mac.update(&nonce);
        mac.update(ciphertext);
        mac.verify_slice(&expected_tag)
            .map_err(|_| CryptoError::decryption("HMAC verification failed"))?;

        let mut plaintext = ciphertext.to_vec();
        let mut cipher = XChaCha20::new(
            (&*chacha_key).into(),
            <&[u8; 24]>::try_from(&chacha_nonce[..24])
                .expect("chacha_nonce is 32 bytes; first 24 always valid")
                .into(),
        );
        cipher.apply_keystream(&mut plaintext);

        unpad_plaintext(&plaintext)
    }

    // --- NIP-44 v3 (nostr-land/nip44v3 draft): kind/scope-aware ---
    //
    // Differs from v2: keys are derived per-message with the salt
    // `"nip44-v3\0" || nonce`, ChaCha20 (IETF 96-bit zero nonce) replaces
    // XChaCha20, and a decryptor-supplied (kind, scope) context is authenticated
    // alongside the ciphertext so a payload cannot be replayed in a different
    // context. Raw payload (pre-base64):
    //   0x03 | nonce(32) | mac(32) | kind(u32be) | scope_len(u32be) | scope | ciphertext
    const NIP44_V3_VERSION: u8 = 0x03;
    const NIP44_V3_SALT_PREFIX: &[u8] = b"nip44-v3\x00";
    // version + nonce(32) + mac(32) + kind(4) + scope_len(4) + min ciphertext(4)
    const NIP44_V3_MIN_PAYLOAD: usize = 1 + 32 + 32 + 4 + 4 + 4;
    const NIP44_V3_MIN_PADDING: u64 = 32;
    const NIP44_V3_PAD_THRESHOLD: u64 = 32768;

    fn v3_derive_keys(
        shared_secret: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
        let mut salt = Vec::with_capacity(NIP44_V3_SALT_PREFIX.len() + 32);
        salt.extend_from_slice(NIP44_V3_SALT_PREFIX);
        salt.extend_from_slice(nonce);
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut mac = Zeroizing::new([0u8; 32]);
        hk.expand(b"encryption_key", enc.as_mut())
            .map_err(|_| CryptoError::kdf("NIP-44 v3 encryption key derivation failed"))?;
        hk.expand(b"mac_key", mac.as_mut())
            .map_err(|_| CryptoError::kdf("NIP-44 v3 mac key derivation failed"))?;
        Ok((enc, mac))
    }

    // Matches the draft's padding schedule (used on the 4-byte-length-prefixed plaintext).
    fn v3_target_size(len: u64) -> u64 {
        if len == 0 {
            return NIP44_V3_MIN_PADDING;
        }
        let next_power = 1u64 << (u64::BITS - (len - 1).leading_zeros());
        let subdivs: u64 = if next_power >= NIP44_V3_PAD_THRESHOLD {
            8
        } else {
            4
        };
        let chunk = core::cmp::max(NIP44_V3_MIN_PADDING, next_power / subdivs);
        chunk * len.div_ceil(chunk)
    }

    fn v3_pad(plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(CryptoError::encryption("NIP-44 v3 plaintext too large").into());
        }
        let prefixed = 4u64
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| CryptoError::encryption("NIP-44 v3 plaintext too large"))?;
        let target = v3_target_size(prefixed);
        if target > usize::MAX as u64 {
            return Err(CryptoError::encryption("NIP-44 v3 padded length overflow").into());
        }
        let mut out = vec![0u8; target as usize];
        out[0..4].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
        out[4..4 + plaintext.len()].copy_from_slice(plaintext);
        Ok(out)
    }

    fn v3_unpad(padded: &[u8]) -> Result<Vec<u8>> {
        if padded.len() < 4 {
            return Err(CryptoError::decryption("NIP-44 v3 padded buffer too short").into());
        }
        let plen = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
        if plen > MAX_PLAINTEXT_SIZE
            || 4usize
                .checked_add(plen)
                .is_none_or(|end| end > padded.len())
        {
            return Err(CryptoError::decryption("NIP-44 v3 invalid padding length").into());
        }
        // The draft does not mandate a canonical padded length, so only require the
        // trailing region to be all zeroes (checked without early exit on length).
        let mut diff = 0u8;
        for &b in &padded[4 + plen..] {
            diff |= b;
        }
        if diff != 0 {
            return Err(CryptoError::decryption("NIP-44 v3 non-zero padding").into());
        }
        Ok(padded[4..4 + plen].to_vec())
    }

    fn v3_mac_update(
        mac: &mut Hmac<Sha256>,
        nonce: &[u8; 32],
        kind: u32,
        scope: &[u8],
        ciphertext: &[u8],
    ) {
        mac.update(nonce);
        mac.update(&kind.to_be_bytes());
        mac.update(&(scope.len() as u32).to_be_bytes());
        mac.update(scope);
        mac.update(ciphertext);
    }

    /// Encrypt with NIP-44 v3 using a raw ECDH shared secret. `kind`/`scope` are
    /// authenticated into the payload. Returns the raw payload (pre-base64).
    pub fn encrypt_v3(
        shared_secret: &[u8; 32],
        plaintext: &[u8],
        kind: u32,
        scope: &str,
    ) -> Result<Vec<u8>> {
        let nonce: [u8; 32] = entropy::random_bytes();
        encrypt_v3_with_nonce(shared_secret, plaintext, kind, scope, &nonce)
    }

    // Nonce-injectable core; production callers must use [encrypt_v3], which supplies
    // a fresh random nonce.
    fn encrypt_v3_with_nonce(
        shared_secret: &[u8; 32],
        plaintext: &[u8],
        kind: u32,
        scope: &str,
        nonce: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let (enc_key, mac_key) = v3_derive_keys(shared_secret, nonce)?;
        let mut buf = v3_pad(plaintext)?;
        let zero_nonce = [0u8; 12];
        let mut cipher = ChaCha20::new((&*enc_key).into(), (&zero_nonce).into());
        cipher.apply_keystream(&mut buf);

        let scope_bytes = scope.as_bytes();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&*mac_key)
            .map_err(|_| CryptoError::encryption("Failed to create NIP-44 v3 HMAC"))?;
        v3_mac_update(&mut mac, nonce, kind, scope_bytes, &buf);
        let tag = mac.finalize().into_bytes();

        let mut payload = Vec::with_capacity(1 + 32 + 32 + 4 + 4 + scope_bytes.len() + buf.len());
        payload.push(NIP44_V3_VERSION);
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&tag);
        payload.extend_from_slice(&kind.to_be_bytes());
        payload.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(scope_bytes);
        payload.extend_from_slice(&buf);
        Ok(payload)
    }

    /// Decrypt a NIP-44 v3 payload, verifying the (kind, scope) context binds to the
    /// caller's expectations. Returns the plaintext.
    pub fn decrypt_v3(
        shared_secret: &[u8; 32],
        payload: &[u8],
        expected_kind: u32,
        expected_scope: &str,
    ) -> Result<Vec<u8>> {
        if payload.len() < NIP44_V3_MIN_PAYLOAD {
            return Err(CryptoError::decryption("NIP-44 v3 payload too short").into());
        }
        if payload[0] != NIP44_V3_VERSION {
            return Err(CryptoError::decryption("Unsupported NIP-44 version").into());
        }
        let nonce: [u8; 32] = payload[1..33]
            .try_into()
            .map_err(|_| CryptoError::decryption("NIP-44 v3 bad nonce"))?;
        let provided_mac = &payload[33..65];
        let kind = u32::from_be_bytes([payload[65], payload[66], payload[67], payload[68]]);
        let scope_len =
            u32::from_be_bytes([payload[69], payload[70], payload[71], payload[72]]) as usize;
        let scope_off = 73usize;
        let scope_end = scope_off
            .checked_add(scope_len)
            .filter(|&end| end <= payload.len())
            .ok_or_else(|| CryptoError::decryption("NIP-44 v3 scope length out of bounds"))?;
        let scope = &payload[scope_off..scope_end];
        let ciphertext = &payload[scope_end..];
        // Context binding: reject a payload encrypted for a different kind/scope.
        if kind != expected_kind || scope != expected_scope.as_bytes() {
            return Err(CryptoError::decryption("NIP-44 v3 context mismatch").into());
        }

        let (enc_key, mac_key) = v3_derive_keys(shared_secret, &nonce)?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&*mac_key)
            .map_err(|_| CryptoError::decryption("Failed to create NIP-44 v3 HMAC"))?;
        v3_mac_update(&mut mac, &nonce, kind, scope, ciphertext);
        mac.verify_slice(provided_mac)
            .map_err(|_| CryptoError::decryption("NIP-44 v3 invalid MAC"))?;

        let mut buf = ciphertext.to_vec();
        let zero_nonce = [0u8; 12];
        let mut cipher = ChaCha20::new((&*enc_key).into(), (&zero_nonce).into());
        cipher.apply_keystream(&mut buf);
        v3_unpad(&buf)
    }

    #[cfg(test)]
    mod v3_tests {
        use super::*;
        use base64::Engine;

        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        fn unhex32(s: &str) -> [u8; 32] {
            unhex(s).try_into().unwrap()
        }
        fn hex_lower(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        #[test]
        fn v3_target_size_matches_draft_table() {
            let table: [(u64, u64); 12] = [
                (0, 32),
                (1, 32),
                (32, 32),
                (33, 64),
                (34, 64),
                (64, 64),
                (65, 96),
                (66, 96),
                (96, 96),
                (97, 128),
                (98, 128),
                (128, 128),
            ];
            for (len, expected) in table {
                assert_eq!(v3_target_size(len), expected, "target_size({len})");
            }
        }

        // nostr-land/nip44v3 draft vector (encrypt_decrypt[0]); shared_secret is the
        // x-only ECDH of the vector's key pair, verified against its published prk.
        #[test]
        fn v3_known_answer_vector() {
            let ss = unhex32("dff79f877ba3953557c8502bf6da24c6f378419d138786e5ddd53034e84077d6");
            let nonce = unhex32("b5451a6d90ec575b4cdcedf4987429eeab1bbaa192ea3db89eafa058826885a6");
            let pt = unhex("efbbbf48656c6c6f20776f726c6421");
            let (enc, mac) = v3_derive_keys(&ss, &nonce).unwrap();
            assert_eq!(
                hex_lower(&*enc),
                "de94e4663af538351a9b75b8af31e968ed8b88241ddbce43ad1d4ae2b984327d"
            );
            assert_eq!(
                hex_lower(&*mac),
                "70e65d5ff8769e92fbdf163b00b1b317bd4d30fe82de6b00d05cd74fb576febd"
            );
            let payload = encrypt_v3_with_nonce(&ss, &pt, 1, "", &nonce).unwrap();
            assert_eq!(
                base64::engine::general_purpose::STANDARD.encode(&payload),
                "A7VFGm2Q7FdbTNzt9Jh0Ke6rG7qhkuo9uJ6voFiCaIWmMJrEDBNRRCorotVxmP7ge14Y+UtDn1/Pn3uzAaNNzHUAAAABAAAAAPJgoFXpn6mjFE0hUZrnZljeaYwSdqBKbVDXcyLgVGC8"
            );
            assert_eq!(decrypt_v3(&ss, &payload, 1, "").unwrap(), pt);
        }

        #[test]
        fn v3_round_trips_with_kind_and_scope() {
            let ss = [7u8; 32];
            let cases: [(u32, &str, &[u8]); 3] = [
                (1, "", b"hi"),
                (4, "dm", b"secret message"),
                (22242, "wss://relay.example.com", b""),
            ];
            for (kind, scope, msg) in cases {
                let payload = encrypt_v3(&ss, msg, kind, scope).unwrap();
                assert_eq!(decrypt_v3(&ss, &payload, kind, scope).unwrap(), msg);
            }
        }

        #[test]
        fn v3_rejects_context_mismatch_and_tamper() {
            let ss = [9u8; 32];
            let payload = encrypt_v3(&ss, b"hello", 4, "dm").unwrap();
            // Wrong kind or scope must fail (context binding).
            assert!(decrypt_v3(&ss, &payload, 5, "dm").is_err());
            assert!(decrypt_v3(&ss, &payload, 4, "other").is_err());
            // Tampered ciphertext fails the MAC.
            let mut bad = payload.clone();
            *bad.last_mut().unwrap() ^= 0x01;
            assert!(decrypt_v3(&ss, &bad, 4, "dm").is_err());
            // Wrong key fails.
            assert!(decrypt_v3(&[8u8; 32], &payload, 4, "dm").is_err());
        }

        #[test]
        fn v3_rejects_wrong_version() {
            let ss = [3u8; 32];
            let mut payload = encrypt_v3(&ss, b"hi", 1, "").unwrap();
            payload[0] = 0x02;
            assert!(decrypt_v3(&ss, &payload, 1, "").is_err());
        }

        #[test]
        fn v3_rejects_short_payload() {
            let ss = [3u8; 32];
            let payload = vec![NIP44_V3_VERSION; NIP44_V3_MIN_PAYLOAD - 1];
            assert!(decrypt_v3(&ss, &payload, 1, "").is_err());
        }

        #[test]
        fn v3_rejects_scope_len_out_of_bounds() {
            let ss = [3u8; 32];
            let mut payload = encrypt_v3(&ss, b"hi", 1, "dm").unwrap();
            // scope_len occupies bytes 69..73.
            payload[69..73].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
            assert!(decrypt_v3(&ss, &payload, 1, "dm").is_err());
        }

        #[test]
        fn v3_unpad_rejects_nonzero_trailing_and_accepts_zero() {
            // Declared length 2 with all-zero trailing region decodes cleanly.
            let mut good = vec![0u8; 8];
            good[0..4].copy_from_slice(&2u32.to_be_bytes());
            good[4] = 0xaa;
            good[5] = 0xbb;
            assert_eq!(v3_unpad(&good).unwrap(), vec![0xaa, 0xbb]);
            // A non-zero byte in the trailing region is rejected.
            let mut bad = good.clone();
            bad[6] = 0x01;
            assert!(v3_unpad(&bad).is_err());
        }
    }
}

/// NIP-04 encryption using a raw ECDH shared secret.
///
/// This module implements NIP-04 AES-256-CBC encryption/decryption for use with
/// threshold ECDH, where the shared secret is computed via distributed
/// key operations rather than from a single private key.
pub mod nip04 {
    use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
    use base64::Engine;

    use super::{entropy, CryptoError, Result};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    /// Encrypt plaintext using NIP-04 (AES-256-CBC) with a raw ECDH shared secret.
    ///
    /// Returns the encrypted payload in NIP-04 format: base64(ciphertext)?iv=base64(iv)
    pub fn encrypt(shared_secret: &[u8; 32], plaintext: &[u8]) -> Result<String> {
        let iv: [u8; 16] = entropy::random_bytes();

        let cipher = Aes256CbcEnc::new(shared_secret.into(), &iv.into());
        let ciphertext = cipher.encrypt_padded_vec::<Pkcs7>(plaintext);

        let b64 = base64::engine::general_purpose::STANDARD;
        Ok(format!("{}?iv={}", b64.encode(&ciphertext), b64.encode(iv)))
    }

    /// Decrypt a NIP-04 payload using a raw ECDH shared secret.
    ///
    /// Takes the encrypted payload in format: base64(ciphertext)?iv=base64(iv)
    pub fn decrypt(shared_secret: &[u8; 32], payload: &str) -> Result<Vec<u8>> {
        let (ciphertext_b64, iv_b64) = payload
            .split_once("?iv=")
            .ok_or_else(|| CryptoError::decryption("Invalid NIP-04 format: missing ?iv="))?;

        let b64 = base64::engine::general_purpose::STANDARD;

        let ciphertext = b64
            .decode(ciphertext_b64)
            .map_err(|_| CryptoError::decryption("Invalid base64 ciphertext"))?;

        let iv: [u8; 16] = b64
            .decode(iv_b64)
            .map_err(|_| CryptoError::decryption("Invalid base64 IV"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid IV length"))?;

        let cipher = Aes256CbcDec::new(shared_secret.into(), &iv.into());
        cipher
            .decrypt_padded_vec::<Pkcs7>(&ciphertext)
            .map_err(|_| CryptoError::decryption("AES decryption failed").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        // RFC 4231 test case 1: 20-byte 0x0b key, "Hi There".
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

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

    #[test]
    fn test_nip04_roundtrip() {
        let shared_secret: [u8; 32] = random_bytes();
        let plaintext = b"Hello, NIP-04!";

        let encrypted = nip04::encrypt(&shared_secret, plaintext).unwrap();
        assert!(encrypted.contains("?iv="));

        let decrypted = nip04::decrypt(&shared_secret, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_nip04_wrong_key_fails() {
        let shared_secret: [u8; 32] = random_bytes();
        let wrong_secret: [u8; 32] = random_bytes();
        let plaintext = b"Secret message";

        let encrypted = nip04::encrypt(&shared_secret, plaintext).unwrap();
        let result = nip04::decrypt(&wrong_secret, &encrypted);
        match result {
            Err(_) => {}
            Ok(decrypted) => assert_ne!(plaintext.as_slice(), decrypted.as_slice()),
        }
    }

    #[test]
    fn test_nip04_invalid_format() {
        let shared_secret: [u8; 32] = random_bytes();

        let result = nip04::decrypt(&shared_secret, "invalid_no_iv");
        assert!(result.is_err());
    }

    #[test]
    fn test_nip44_roundtrip() {
        let shared_secret: [u8; 32] = random_bytes();
        let plaintext = b"Hello, NIP-44!";

        let encrypted = nip44::encrypt(&shared_secret, plaintext).unwrap();
        let decrypted = nip44::decrypt(&shared_secret, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
