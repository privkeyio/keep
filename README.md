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

## License

AGPL-3.0
