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
```

## Environment Variables

- `KEEP_PASSWORD` - Password for non-interactive use
- `KEEP_YES` - Skip confirmation prompts
- `RUST_LOG` - Logging level (error, warn, info, debug, trace)

## Security

- Argon2id key derivation (256MB memory, 4 iterations)
- XChaCha20-Poly1305 encryption
- LMDB encrypted storage
- Secure memory handling with zeroize

## License

AGPL-3.0
