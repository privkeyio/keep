<div align="center">

# Keep

*Self-custodial key management for Nostr and Bitcoin.*

</div>

## About

Keep is an encrypted vault for Nostr and Bitcoin keys. It stores keys locally with strong encryption, signs remotely via NIP-46 without exposing private keys, and supports FROST threshold signatures so no single device ever holds enough to spend.

Keep runs as a CLI, a desktop app (Linux/macOS/Windows), a mobile library (Android/iOS via UniFFI), or inside AWS Nitro Enclaves for hardware-isolated signing. FROST shares can be distributed across phones, hardware signers, and cloud enclaves—then coordinated over Nostr relays for multisig signing.

## Features

- **Encrypted vault** — Argon2id + XChaCha20-Poly1305, keys zeroized in RAM
- **Remote signing** — NIP-46 bunker mode for any compatible Nostr client
- **Threshold signatures** — FROST t-of-n key splitting with distributed key generation (DKG)
- **Network signing** — Coordinate FROST signing across devices over Nostr relays
- **Bitcoin** — BIP-86 Taproot addresses, PSBT signing, wallet descriptor coordination
- **Hardware signers** — Air-gapped FROST shares on [keep-esp32](https://github.com/privkeyio/keep-esp32)
- **Mobile** — UniFFI library for Android ([keep-android](https://github.com/privkeyio/keep-android)) and iOS
- **Enclaves** — AWS Nitro Enclave signing with attestation-based KMS
- **Agent SDK** — Constrained signing sessions for AI agents (Python, TypeScript, MCP)
- **Hidden volumes** — Plausibly deniable storage, cryptographically undetectable
- **Desktop app** — Iced GUI with system tray, QR scanning, NIP-49 import/export

## Quick Start

```bash
cargo install --path keep-cli
```

```bash
keep init                     # Create encrypted vault
keep generate --name main     # Generate a new Nostr key
keep serve --relay wss://nos.lol  # Start remote signer
```

Keys are stored encrypted at `~/.keep`. See [`docs/USAGE.md`](docs/USAGE.md) for full CLI reference, FROST setup, Bitcoin commands, and more.

## Development

```bash
cargo build --release   # Build
cargo test              # Test
cargo clippy            # Lint
```

Minimum Supported Rust Version: **1.89**.

## Security

Pure Rust with `#![forbid(unsafe_code)]`. Keys are derived with Argon2id, encrypted with XChaCha20-Poly1305, protected in RAM with Ascon-128a, and locked with mlock(2). FROST uses BIP-340 Schnorr signatures. See [`docs/SECURITY.md`](docs/SECURITY.md) for details.

## License

[AGPL-3.0](LICENSE)
