# Keep

Sovereign Key Management for Nostr and Bitcoin.

## Install

```bash
cargo install --path keep-cli
```

## Usage

```bash
keep init                     # Create encrypted vault
keep generate --name main     # Generate new key
keep import --name backup     # Import nsec
keep list                     # List keys
keep export --name main       # Export nsec
keep delete --name main       # Delete key
keep serve                    # Start NIP-46 remote signer
keep --hidden init            # Create vault with hidden volume
keep --hidden list            # Access hidden volume
```

## Remote Signing (NIP-46)

Start the remote signer to use your keys with Nostr clients:

```bash
keep serve --relay wss://relay.damus.io
```

This displays a TUI with:
- Bunker URL to paste into your Nostr client
- Activity log of all signing requests
- Approval prompts for signing events

Controls:
- `Y` / `Enter` - Approve request
- `N` - Reject request
- `Q` - Quit

## Bitcoin (Taproot)

Native Bitcoin support with BIP-86 Taproot addresses:

```bash
keep bitcoin address --key main                  # Get receive address
keep bitcoin address --key main --change         # Get change address
keep bitcoin descriptor --key main               # Export for watch-only wallets
keep bitcoin sign --key main --psbt unsigned.psbt  # Sign PSBT
keep bitcoin analyze --psbt unsigned.psbt        # Inspect before signing
```

## Threshold Signatures (FROST)

Split keys into t-of-n shares for distributed signing:

```bash
keep frost generate --threshold 2 --shares 3    # Create 2-of-3 key
keep frost split --key main -t 2 -s 3           # Split existing key
keep frost list                                  # List shares
keep frost export --share 1 --group npub1...    # Export share
keep frost import                                # Import share
keep frost sign --group npub1... --message <hex> # Sign with local shares
keep frost sign --group npub1... --message <hex> --interactive  # Multi-device
```

When serving with FROST shares, the NIP-46 signer automatically uses threshold signing:

```bash
keep serve --headless   # Detects FROST shares and uses threshold signing
```

## Enclave (AWS Nitro)

TEE-based signing for institutional security:

```bash
keep enclave status                              # Check enclave status
keep enclave verify                              # Verify attestation
keep enclave generate-key --name agent          # Generate key in enclave
keep enclave import-key --name agent --from-vault mykey  # Import from vault
keep enclave sign --key agent --message <hex>   # Sign in enclave
keep enclave sign-psbt --key agent --psbt tx.psbt --network testnet  # Sign PSBT
```

For local development without AWS Nitro hardware:

```bash
keep enclave status --local                      # Mock enclave status
keep enclave generate-key --name test --local   # Generate in mock enclave
keep enclave sign --key test --message <hex> --local  # Sign locally
```

Mock enclave persists keys to `/tmp/keep-mock-enclave.redb` for testing.

See [docs/ENCLAVE.md](docs/ENCLAVE.md) for full deployment guide.

**WARNING: `--local` mode is for development and testing only.** It is NOT secure for production use. Keys stored in `/tmp/keep-mock-enclave.redb` can be read or tampered with by any process on the system. Before deploying to production: delete any mock keys (`rm /tmp/keep-mock-enclave.redb`), never use `--local` flags, and use the AWS Nitro enclave workflow with proper KMS key policies for real deployments.

## Hidden Volumes (Plausible Deniability)

Create a vault with a hidden volume that is cryptographically undetectable:

```bash
KEEP_PASSWORD="outerpass" KEEP_HIDDEN_PASSWORD="hiddenpass" keep --hidden init
```

Two separate volumes:
- **Outer volume** (outerpass) - Store decoy keys here
- **Hidden volume** (hiddenpass) - Store real keys here

An attacker cannot prove the hidden volume exists. Under duress, reveal only the outer password.

```bash
KEEP_PASSWORD="outerpass" keep list                    # Shows decoy keys
KEEP_PASSWORD="hiddenpass" keep --hidden list          # Shows real keys
```

## Security

- Argon2id key derivation (256MB memory, 4 iterations)
- XChaCha20-Poly1305 AEAD encryption
- BLAKE2b checksums
- redb encrypted storage (pure Rust, ACID transactions)
- Keys encrypted in RAM using Ascon-128a via the memsecurity crate
- Secure memory handling with zeroize
- Zero unsafe code - enforced via `#![forbid(unsafe_code)]` in all modules
- VeraCrypt-style hidden volumes with no detectable markers
- FROST threshold signatures (BIP-340 compatible Schnorr)
- AWS Nitro Enclave support with attestation verification
- Policy engine runs inside enclave (amount limits, rate limits, address allowlists)
- Bitcoin Taproot (BIP-86) with PSBT signing (BIP-174/370)

## License

AGPL-3.0
