# Keep

*Self-custodial key management for Nostr and Bitcoin.*

Keep is an encrypted vault for Nostr and Bitcoin keys. It stores keys locally with strong
encryption, signs remotely via NIP-46 without exposing private keys, and supports FROST
threshold signatures so no single device ever holds enough to spend.

Keep runs as a CLI, a desktop app (Linux/macOS/Windows), a mobile library (Android/iOS via
UniFFI), a StartOS service for always-on FROST co-signing, or inside AWS Nitro Enclaves for
hardware-isolated signing.

## Where to start

- **[Usage](./USAGE.md)** — install the CLI, create a vault, generate keys, remote
  signing, Bitcoin, FROST, agents, and troubleshooting.
- **[Security](./SECURITY.md)** — cryptography and threat model.
- **[AWS Nitro Enclaves](./ENCLAVE.md)** — hardware-isolated signing deployment.
- **[Release Signing](./RELEASE_SIGNING.md)** — how Keep threshold-signs its own releases.
- **[Reproducible Builds](./REPRODUCIBILITY.md)** — verifying builds bit-for-bit.

## Project links

- Source: <https://github.com/privkeyio/keep>
- License: [MIT](https://github.com/privkeyio/keep/blob/main/LICENSE)
- Self-hosting the headless co-signer:
  [keep-web/README.md](https://github.com/privkeyio/keep/blob/main/keep-web/README.md)
