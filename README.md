# Keep

Sovereign Key Management for Nostr and Bitcoin.

## Install

```bash
cargo install --path .
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

## Environment Variables

- `KEEP_PASSWORD` - Password for vault (outer password for hidden vaults)
- `KEEP_HIDDEN_PASSWORD` - Hidden volume password (only for `--hidden init`)
- `KEEP_YES` - Skip confirmation prompts
- `RUST_LOG` - Logging level (error, warn, info, debug, trace)

## Security

- Argon2id key derivation (256MB memory, 4 iterations)
- XChaCha20-Poly1305 AEAD encryption
- BLAKE2b checksums
- LMDB encrypted storage
- Secure memory handling with zeroize
- VeraCrypt-style hidden volumes with no detectable markers

## License

AGPL-3.0
