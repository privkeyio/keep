# Security

## Threat Model

### Trust Boundaries

1. **Local Storage**: Attacker has read access to disk but not memory
2. **Network**: Attacker can observe and inject relay traffic
3. **Enclave**: Attacker controls host OS but not enclave memory
4. **Physical**: Attacker has brief physical access (cold-boot attacks)

### Security Assumptions

- Cryptographic primitives (XChaCha20-Poly1305, Argon2id, Blake2b, secp256k1) are secure
- Operating system provides correct mlock/munlock syscalls
- AWS Nitro Enclave attestation root certificate is trustworthy
- Random number generation (OsRng) is cryptographically secure

### Out of Scope

- Side-channel attacks requiring prolonged physical access
- Attacks on the Rust compiler or dependencies
- Social engineering attacks
- Denial of service (availability)

## FROST Threshold Signatures

### Security Properties

FROST (Flexible Round-Optimized Schnorr Threshold) provides:

- **t-of-n threshold**: Any t participants can sign; fewer than t learn nothing
- **Unforgeability**: Signatures cannot be forged without t honest participants
- **Key privacy**: Group public key reveals nothing about individual shares

### Threshold Configuration

```
Minimum threshold: 2
Maximum shares: 255
Presets: 2-of-3, 3-of-5
```

### Trusted Dealer Warning

The trusted dealer key generation (`frost::keys::generate_with_dealer`) generates the full private key on a single machine. Use distributed key generation (DKG) for production deployments where no single party should see the complete key.

### Nonce Reuse Prevention

Nonce reuse in Schnorr signatures leaks the private key. Prevention mechanisms:

1. **Session ID uniqueness**: `blake2b_256(message || timestamp_nanos || random_16_bytes)`
2. **Persistent tracking**: `FileNonceStore` records consumed session IDs to disk
3. **File locking**: Exclusive locks prevent TOCTOU races during nonce recording
4. **Single-use enforcement**: `SigningNonces` consumed after Round 2

## Key Storage

### Key Derivation

```
Master Key = Argon2id(password, salt_32, params)

Default params:
  Memory: 256 MiB
  Iterations: 4
  Parallelism: 4
  Output: 32 bytes

Subkeys = Blake2b-512(master_key || context)[0..32]
```

### Encryption

All secrets encrypted with XChaCha20-Poly1305:

- 24-byte random nonce (sufficient entropy for random generation)
- 32-byte key
- 16-byte Poly1305 authentication tag

### Storage Format

```
Vault file layout:
  [0..512]     Outer header (salt, encrypted_data_key, params)
  [512..1024]  Hidden header (encrypted, or random if unused)
  [1024..]     Outer data (redb database, encrypted records)
  [hidden..]   Hidden data (encrypted, padded with random)
```

## Memory Protection

### MlockedBox

Fixed-size secret storage with:

- `mlock()`: Prevents swapping to disk
- Zero-on-drop: `memzero()` before deallocation
- No-copy: Data locked in place

### EncryptedMem

Variable-size secrets double-encrypted:

1. XChaCha20-Poly1305 at rest
2. `memsecurity::EncryptedMem` in RAM

### Zeroize

All secret types implement `Zeroize` and `ZeroizeOnDrop`:

- `SecretKey`, `SecretVec`, `MlockedBox`, `MlockedVec`
- `SigningNonces`, `KeyPackage`, `Coordinator`

## Rate Limiting

### Parameters

```
Max attempts before delay: 5
Base delay: 1 second
Max delay: 300 seconds (5 minutes)
Backoff: Exponential (2^n seconds)
```

### Implementation

After 5 failed attempts:
```
Attempt 6:  1 second delay
Attempt 7:  2 seconds
Attempt 8:  4 seconds
Attempt 9:  8 seconds
Attempt 10: 16 seconds
Attempt 13: 128 seconds
Attempt 14+: 300 seconds (capped)
```

### Tamper Protection

Rate limit records include HMAC-Blake2b:
```
HMAC_key = Blake2b(b"keep-rate-limit-hmac-key" || vault_salt)
Record = failed_attempts || last_failure_timestamp || HMAC[0..8]
```

## Hidden Volumes

### Plausible Deniability

The hidden volume provides deniability against coercion:

1. **Independent KDF**: Outer and hidden passwords derive separate keys from separate salts
2. **Indistinguishable failure**: Wrong password and no-hidden-volume produce identical errors
3. **No timing leaks**: Both decryption paths execute regardless of which succeeds
4. **Random padding**: Unused space filled with random bytes

### Unlocking

```
unlock(password):
  result_outer = try_unlock_outer(password)  // Always runs
  result_hidden = try_unlock_hidden(password) // Always runs
  return first_success_or_error
```

### Checksum Verification

Hidden header integrity verified with constant-time comparison:
```
expected = Blake2b-256(version || salt || nonce || encrypted_key || offset || size)
valid = constant_time_eq(expected, stored_checksum)
```

## Unsafe Code

All modules use `#![forbid(unsafe_code)]` except memory protection.

### MlockedBox (keep-core/src/crypto.rs, `mlock` module)

| Location | Operation | Safety Invariant |
|----------|-----------|------------------|
| `MlockedBox::new` | `alloc_zeroed()` | Layout valid for `[u8; N]`; null check before use |
| `MlockedBox::new` | `copy_nonoverlapping()` | Source valid slice, dest from `alloc_zeroed`; no overlap |
| `MlockedBox::new` | `mlock()` | Failure handled gracefully (sets `locked=false`) |
| `impl Deref` | `&*self.ptr` | Pointer valid from allocation until `Drop` |
| `impl DerefMut` | `&mut *self.ptr` | Pointer valid from allocation until `Drop` |
| `impl Drop` | `memzero()` | Pointer valid; size `N` matches allocation |
| `impl Drop` | `munlock()` | Size `N` matches original `mlock` call |
| `impl Drop` | `dealloc()` | Layout matches original `alloc_zeroed` |
| `impl Zeroize` | `memzero()` | Pointer valid; size `N` matches allocation |
| `unsafe impl Send/Sync` | Marker traits | Interior pointer never exposed; no shared mutation |

*Note: Verified against commit `760cd18`. Line numbers omitted for maintainability.*

### Enclave MlockedBox (keep-enclave/enclave/src/mlock.rs)

Identical implementation and safety invariants.

## Attack Surface

### Local Storage

**Protected against:**
- Offline brute force (Argon2id with 256 MiB memory cost)
- Key enumeration (encrypted database, no plaintext metadata)
- Hidden volume detection (random padding, constant-time operations)
- Rate limit bypass (HMAC-protected state)

**Not protected against:**
- Weak passwords (use 32+ character passwords)
- Memory dumps during active session (use enclave for high-value keys)

### Relay Protocol

**Message limits:**
```
MAX_MESSAGE_SIZE: 64 KB
MAX_COMMITMENT_SIZE: 128 bytes
MAX_SIGNATURE_SHARE_SIZE: 64 bytes
MAX_PARTICIPANTS: 255
```

**Protected against:**
- Buffer overflow (size validation on all messages)
- Replay attacks (nonce tracking, session ID uniqueness)

**Not protected against:**
- Traffic analysis (message timing may leak signing activity)

### Enclave Attestation

**Verification:**
1. COSE_Sign1 signature chain validation
2. Certificate chain: enclave cert → CA cert → AWS Nitro root
3. PCR values match expected measurements
4. Nonce matches request (replay prevention)

**Protected against:**
- Attestation forgery (requires AWS root key)
- Replay attacks (nonce validation)
- PCR tampering (measured boot)

**Not protected against:**
- Compromised AWS Nitro infrastructure
- Side-channel attacks on enclave (Spectre/Meltdown on vulnerable CPUs)

## Responsible Disclosure

Report security vulnerabilities to: security@privkey.io

**PGP Key:**
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEaGVRQBYJKwYBBAHaRw8BAQdAF9dwAiS2eOxTwDNy/1LvnTfqP6m8h4rY
BZxx1v30tJjNKXNlY3VyaXR5QHByaXZrZXkuaW8gPHNlY3VyaXR5QHByaXZr
ZXkuaW8+wsARBBMWCgCDBYJoZVFAAwsJBwmQuDUnCJWoCwtFFAAAAAAAHAAg
c2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ1633ld0W07KI/fGiqv/RPdn
rKNn456SSIdAiJXTdN5bAxUKCAQWAAIBAhkBApsDAh4BFiEE50kamFXBudeZ
trSRuDUnCJWoCwsAAELLAQD8gmp8ClfdlOXbOEeFGuvz4LoDlAktfN4L28Wl
EeedvQD/VrR64FFB0ZsJ4eW0axdjcT3ph4xv96Lqn6tNO0WmUgbOOARoZVFA
EgorBgEEAZdVAQUBAQdANUQ4xZ3hZzlCsOAJeVN7PkZwEF/Q9DdTZNaUkFXT
8T8DAQgHwr4EGBYKAHAFgmhlUUAJkLg1JwiVqAsLRRQAAAAAABwAIHNhbHRA
bm90YXRpb25zLm9wZW5wZ3Bqcy5vcme2RcuuIdqCuXe6p0nzXLc6RICA0iVC
/6RhJxujpAdrdQKbDBYhBOdJGphVwbnXmba0kbg1JwiVqAsLAABrEwEA1Y9e
BF6SXFgvOtu+iRdD6e+a1E1l0j3N8qyqb1tJ39MBAMT4UzjZ9IQ2Brz3ZYmV
kyew0MAIis6DCtVkNduBlBYA
=3LT9
-----END PGP PUBLIC KEY BLOCK-----
```

**Fingerprint:** `E749 1A98 55C1 B9D7 99B6 B491 B835 2708 95A8 0B0B`

**Process:**
1. Encrypt report with PGP key above
2. Send to security@privkey.io
3. Expect acknowledgment within 48 hours
4. Coordinate disclosure timeline (default: 90 days)
