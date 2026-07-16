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

## Relay Trust

Keep treats the Nostr relay as untrusted transport, not a trusted party. Coordination security does not depend on the relay behaving honestly:

- **Payloads are end-to-end encrypted.** Every FROST/OPRF coordination message is NIP-44 (v2) encrypted to the recipient's key before it reaches a relay, so a relay (or anyone who intercepts its TLS connection) sees only ciphertext, never share material, nonces, or OPRF evaluations.
- **Messages are authenticated.** Coordination events are Nostr-signed and re-verified by peers, so a relay cannot forge or tamper with a message; a substituted or replayed event is rejected on receipt.
- **The client authenticates to the relay (NIP-42).** Keep responds to relay `AUTH` challenges automatically, so a relay that requires authentication (kind 22242) admits only your quorum members.
- **What a relay (or a TLS man-in-the-middle) can still do** is limited to metadata analysis (which keys talk, and when) and availability attacks (dropping, delaying, or censoring messages). It cannot read or forge coordination.
- **For high assurance, run your own relay.** Self-hosting a relay (privkey's [`wisp`](https://github.com/privkeyio/wisp) is designed for this) and pointing your quorum at it removes the third-party relay from the trust and metadata surface entirely; binding it to a private, authenticated network (e.g. a WireGuard mesh) also removes reliance on relay TLS. This is the model the keep-node appliance uses.
- **Certificate pinning is available as opt-in defense-in-depth** for the metadata/availability surface when coordinating over an external `wss://` relay (`verify_relay_certificate`, `PinningServerCertVerifier`). It hardens against a relay-TLS man-in-the-middle observing metadata or impersonating the relay endpoint; it is not required for confidentiality or integrity, which the two properties above already provide.
- **Strict pinning closes the first-use window.** By default a relay with no recorded pin is trusted on first connection (TOFU) and its SPKI hash is pinned for subsequent connections, so the very first connection is the exposed one. Enabling strict pinning (the "Strict pinning" toggle under Settings → TLS certificate pinning on desktop, `set_strict_cert_pinning` on mobile) rejects any `wss://` relay that has no recorded pin instead of trusting it. For high-assurance deployments, provision pins out-of-band before enabling strict mode: obtain each relay's SPKI SHA-256 (e.g. `openssl s_client -connect relay.example.com:443 -servername relay.example.com </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -hex`) and place it in the pin store (`cert-pins.json` in the Keep data directory on desktop, mapping hostname to one or more lowercase hex SPKI hashes, e.g. `{"relay.example.com":"<64-hex>"}` or `{"relay.example.com":["<hex1>","<hex2>"]}`; `stage_certificate_pin` on mobile). The current check runs as a pre-flight TLS probe before the relay session is established: with strict mode on it rejects a relay that presents an un-pinned key, so a persistent man-in-the-middle presenting the same rogue certificate to every connection is refused. It does not yet re-verify the pin inside the live coordination handshake itself, so a selective attacker able to present one certificate to the probe and a different one to the data connection is not caught by the probe alone; installing the pin verifier on the live connection is tracked separately. For the strongest guarantee, run your own relay on an authenticated private network (above) rather than relying on relay TLS.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/privkeyio/keep/security/advisories/new) rather than opening a public issue.
