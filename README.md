<div align="center">

# Keep

*Self-custodial key management for Nostr and Bitcoin.*

</div>

## About

Keep is an encrypted vault for Nostr and Bitcoin keys. It stores keys locally with strong encryption, signs remotely via NIP-46 without exposing private keys, and supports FROST threshold signatures so no single device ever holds enough to spend.

Keep runs as a CLI, a desktop app (Linux/macOS/Windows), a mobile library (Android/iOS via UniFFI), a StartOS service for always-on FROST co-signing, or inside AWS Nitro Enclaves for hardware-isolated signing. FROST shares can be distributed across phones, hardware signers, StartOS boxes, and cloud enclaves, then coordinated over Nostr relays for multisig signing.

## Ecosystem

| Repo | Lang | Role |
|------|------|------|
| this repo | Rust | Encrypted vault, CLI, desktop app, Nitro Enclave signing, and [`keep-web`](keep-web) headless co-signer |
| [keep-android](https://github.com/privkeyio/keep-android) | Kotlin | FROST mobile signer with NIP-55 and NIP-46 |
| [keep-esp32](https://github.com/privkeyio/keep-esp32) | C | Air-gapped ESP32-S3 hardware signer |
| [keep-startos](https://github.com/start9-community/keep-startos) | TypeScript | Always-on FROST co-signer node packaging |

## Features

- **Encrypted vault**: Argon2id + XChaCha20-Poly1305, keys zeroized in RAM
- **Remote signing**: NIP-46 bunker mode for any compatible Nostr client
- **Threshold signatures**: FROST t-of-n key splitting with distributed key generation (DKG)
- **Network signing**: Coordinate FROST signing across devices over Nostr relays
- **Bitcoin**: BIP-86 Taproot addresses, PSBT signing, wallet descriptor coordination
- **Enclaves**: AWS Nitro Enclave signing with attestation-based KMS
- **Agent SDK**: Constrained signing sessions for AI agents (Python, TypeScript, MCP)
- **Hidden volumes**: Plausibly deniable storage, cryptographically undetectable
- **Desktop app**: Iced GUI with system tray, QR scanning, NIP-49 import/export

## Quick Start

Install the CLI (Rust 1.89+):

```bash
cargo install --git https://github.com/privkeyio/keep keep-cli
```

Building needs `pkg-config` and `libudev` (Linux); see [`BUILD.md`](BUILD.md) for the full
per-platform dependency list.

Or build from a clone:

```bash
git clone https://github.com/privkeyio/keep
cd keep
cargo install --path keep-cli
```

Then:

```bash
keep init                     # Create encrypted vault (prompts for a password)
keep generate --name main     # Generate a new Nostr key
keep serve --relay wss://bucket.coracle.social  # Start remote signer
```

Keys are stored encrypted at `~/.keep` (override with `KEEP_HOME` or `--path`). Set
`KEEP_PASSWORD` to skip the interactive unlock prompt in scripts. Back up your vault with
`keep backup`; see [`docs/USAGE.md`](docs/USAGE.md) for the full CLI reference, FROST
setup, Bitcoin commands, and more.

## Documentation

| Doc | Covers |
|-----|--------|
| [`docs/USAGE.md`](docs/USAGE.md) | CLI reference, FROST, Bitcoin, agents, hidden volumes, troubleshooting |
| [`keep-web/README.md`](keep-web/README.md) | Self-hosting the headless co-signer (config, auth, API) |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Cryptography and threat model |
| [`docs/ENCLAVE.md`](docs/ENCLAVE.md) | AWS Nitro Enclave deployment |
| [`docs/RELEASE_SIGNING.md`](docs/RELEASE_SIGNING.md) | Threshold-signed releases |
| [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) | Reproducible builds |
| [`BUILD.md`](BUILD.md) | Building from source, system dependencies |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributing guidelines |

## Development

```bash
cargo build --release   # Build
cargo test              # Test
cargo clippy            # Lint
```

Minimum Supported Rust Version: **1.89**.

## Security

Pure Rust with `#![forbid(unsafe_code)]`. Keys are derived with Argon2id, encrypted with XChaCha20-Poly1305, protected in RAM with Ascon-128a, and locked with mlock(2). FROST uses BIP-340 Schnorr signatures. See [`docs/SECURITY.md`](docs/SECURITY.md) for details.

Keep can threshold-sign software releases with a FROST-Ed25519 group (minisign-compatible), so no single maintainer holds the signing key. See [`docs/RELEASE_SIGNING.md`](docs/RELEASE_SIGNING.md).

## License

[MIT](LICENSE)
