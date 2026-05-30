# Security

## Cryptography

| Feature | Implementation |
|---------|----------------|
| Key Derivation | Argon2id (256MB memory, 4 iterations) |
| Encryption | XChaCha20-Poly1305 |
| Checksums | BLAKE2b |
| RAM Protection | Keys encrypted with Ascon-128a, zeroized on drop |
| Memory Locking | mlock(2) prevents secrets from swapping to disk |
| Code Safety | Pure Rust, `#![forbid(unsafe_code)]` |
| Threshold Sigs | FROST with BIP-340 Schnorr |
| Hardware Isolation | AWS Nitro Enclaves with attestation-based KMS |

## Memory Locking

Keep uses `mlock(2)` to prevent secret key material from being paged to disk. If mlock fails (common on systems with low `RLIMIT_MEMLOCK`), Keep warns but continues with degraded security.

**If you see the warning:**
```text
Warning: Failed to lock memory. Secrets may be paged to disk.
To fix: ulimit -l unlimited (or increase RLIMIT_MEMLOCK)
```

**Solutions:**
- Temporary: `ulimit -l unlimited` before running keep
- Permanent: Add to `/etc/security/limits.conf`:
  ```conf
  * soft memlock unlimited
  * hard memlock unlimited
  ```
- Containers: Use `--no-mlock` flag to disable (accepts degraded security)

## FROST Threat Model

A FROST share is more than a cryptographic blinding factor: any device holding share `i` of a `t-of-n` group can act as that share for the lifetime of the share. There is no per-signing-round binding to a specific physical device.

This means:

- **A copied share is a permanent compromise.** If an attacker exfiltrates share `i` from a vault, they can sign as share `i` from anywhere until the group rotates (`keep frost refresh`). Treat each share file with the same care you would treat an unsplit private key.
- **`keep frost export` produces a transferable identity.** Anyone with the exported share (and the export passphrase) can sign as that share's identity. Do not export shares to long-lived files unless those files are themselves protected to the same standard as the vault.
- **`keep frost split` retains the original key by default unless `--keep-original` is passed.** After `frost split`, the original single-key Nostr identity is deleted. Use `--keep-original` only when you explicitly want to retain it as a separate identity.
- **Share number leaks operational structure.** A peer-discovered announce reveals which share index a device claims. Pair this with relay metadata and an attacker can map your topology even without breaking any crypto. Run announces on a dedicated FROST relay (`--frost-relay`) when that matters.
- **Rotate shares with `keep frost refresh` after suspected compromise of any device, even if the group pubkey doesn't need to change.** Refresh invalidates the old share bundle without producing a new group identity.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/privkeyio/keep/security/advisories/new) rather than opening a public issue.
