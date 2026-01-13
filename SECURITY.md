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
Attempt 10: 16 seconds
Attempt 13: 128 seconds
Attempt 14+: 300 seconds (capped)
```

### Tamper Protection

Rate limit records include HMAC-Blake2b:
```
HMAC_key = Blake2b(b"keep-rate-limit-hmac-key" || vault_salt)
Record = failed_attempts || last_failure_timestamp || HMAC[0..4]
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

### MlockedBox (keep-core/src/crypto.rs:16-88)

| Line | Operation | Safety Invariant |
|------|-----------|------------------|
| 32 | `alloc_zeroed()` | Layout valid; null check at line 33 |
| 38 | `copy_nonoverlapping()` | Source/dest valid; no overlap |
| 43 | `mlock()` | Failure handled (sets locked=false) |
| 58, 64 | Deref/DerefMut | Pointer valid until Drop |
| 71, 82 | `memzero()` | Pointer valid; size matches allocation |
| 73 | `munlock()` | Size matches original mlock |
| 75 | `dealloc()` | Layout matches original allocation |
| 86-87 | `Send`/`Sync` | Interior pointer never exposed |

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
MAX_PARTICIPANTS: 256
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

mDMEZ4VPYRYJKwYBBAHaRw8BAQdA3kT0h/x/12RdTsJO2zHdEUmNuJN5cLw94O0p
mwFYyXu0H3NlY3VyaXR5QHByaXZrZXkuaW8gPHNlY3VyaXR5PohpBBMWCgAZBQJn
hU9hBAsJCgcFFQoJCAsEFgIDAQIZAQAhCRDiOy8VeWa2TBYhBF8K5dULQr6RCPDk
puI7LxV5ZrZMmjMA+wRpqBLl37qb1+mLAJoT//Ypk3a1jDx6/6o4N75gLJwJAQD8
i51qfJhkOyY7WvKSpOAGxFVEwuqOLdD4U9xLBk3HALg4BGeGN6kSCisGAQQBl1UB
BQEBB0ARu1bMYdPbV0YhpF8qg6aTxlZ6IiK3mmNfBJV7C5f2ZAMBCAeIfgQYFgoA
JgUCZ4Y3qQkQ4jsvFXlmtkwWIQRfCuXVC0K+kQjw5KbiOy8VeWa2TAIbDAAhCRDi
Oy8VeWa2TBYhBF8K5dULQr6RCPDkpuI7LxV5ZrZMCDEA/0O0y6AOrVpTqUMKg/N6
wRrb3mDQgIf5d/W3rNHUqblbAP9HnBV9W8m+aJvQW3c0VSTQh5CXTQWbr35Qe3NG
r8nwAA==
=2Zt8
-----END PGP PUBLIC KEY BLOCK-----
```

**Fingerprint:** `5F0A E5D5 0B42 BE91 08F0 E4A6 E23B 2F15 7966 B64C`

**Process:**
1. Encrypt report with PGP key above
2. Send to security@privkey.io
3. Expect acknowledgment within 48 hours
4. Coordinate disclosure timeline (default: 90 days)
