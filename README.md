# Keep

Self-custodial key management for Nostr and Bitcoin.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Remote Signing (NIP-46)](#remote-signing-nip-46)
- [Bitcoin](#bitcoin)
- [Threshold Signatures (FROST)](#threshold-signatures-frost)
- [Agent SDK](#agent-sdk)
- [AWS Nitro Enclaves](#aws-nitro-enclaves)
- [Hidden Volumes](#hidden-volumes)
- [Configuration](#configuration)
- [Security](#security)
- [Development](#development)

---

## Installation

```bash
cargo install --path keep-cli
```

Requires Rust 1.70+.

**From source:**

```bash
git clone https://github.com/privkeyio/keep
cd keep
cargo build --release
./target/release/keep --help
```

---

## Quick Start

```bash
# Create your encrypted vault
keep init

# Generate a new Nostr key
keep generate --name main

# List your keys
keep list
```

Keys are stored encrypted at `~/.keep`.

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `keep init` | Create encrypted vault |
| `keep generate --name <n>` | Generate new key |
| `keep import --name <n>` | Import existing nsec |
| `keep list` | List all keys |
| `keep export --name <n>` | Export nsec |
| `keep delete --name <n>` | Delete key |
| `keep serve` | Start NIP-46 remote signer |

---

## Remote Signing (NIP-46)

Sign from any NIP-46 compatible client without exposing your private key:

```bash
keep serve --relay wss://nos.lol
```

This displays a bunker URL to paste into your client.

**Controls:** `Y` approve, `N` reject, `Q` quit

---

## Bitcoin

BIP-86 Taproot addresses and PSBT signing:

```bash
# Get receive address
keep bitcoin address --key main

# Get change address
keep bitcoin address --key main --change

# Export watch-only descriptor
keep bitcoin descriptor --key main

# Analyze PSBT
keep bitcoin analyze --psbt unsigned.psbt

# Sign PSBT
keep bitcoin sign --key main --psbt unsigned.psbt
```

---

## Threshold Signatures (FROST)

Split keys into t-of-n shares for distributed signing.

### Local Operations

```bash
# Create new 2-of-3 threshold key
keep frost generate --threshold 2 --shares 3

# Split existing key into shares
keep frost split --key main -t 2 -s 3

# List shares
keep frost list

# Export share (encrypted with passphrase)
keep frost export --share 1 --group npub1...

# Import share
keep frost import

# Sign with local shares
keep frost sign --group npub1... --message <hex>
```

### Network Signing

Coordinate signing across devices over nostr relays:

```bash
# Device 2: Start signer node
keep frost network serve --group npub1... --relay wss://nos.lol

# Device 1: Check online peers
keep frost network peers --group npub1...

# Device 1: Request signature
keep frost network sign --group npub1... --message "hello"

# Device 1: Sign nostr event
keep frost network sign-event --group npub1... --kind 1 --content "Posted via FROST"
```

### Hardware Signing

Store FROST shares on an air-gapped hardware signer. See [keep-esp32](https://github.com/privkeyio/keep-esp32) for firmware.

```bash
# Test connection
keep frost hardware ping --device /dev/ttyUSB0

# List shares on device
keep frost hardware list --device /dev/ttyUSB0

# Import share to hardware
keep frost hardware import --device /dev/ttyUSB0 --group npub1... --share 1

# Network sign using hardware
keep frost network sign --group npub1... --message <hex> --relay wss://nos.lol --hardware /dev/ttyUSB0
```

---

## Agent SDK

Secure signing for AI agents with constrained sessions.

### Python

```bash
pip install keep-agent
```

```python
from keep_agent import AgentSession, SessionScope, RateLimit

session = AgentSession(
    scope=SessionScope.nostr_only(),
    rate_limit=RateLimit.conservative(),
    duration_hours=24,
)

if session.check_operation("sign_nostr_event"):
    session.record_request()

info = session.get_session_info()
print(f"Requests remaining: {info.requests_remaining}")
```

**LangChain:**

```python
from keep_agent import AgentSession
from keep_agent.langchain import KeepSignerTool

session = AgentSession()
tool = KeepSignerTool(session=session)
```

**CrewAI:**

```python
from keep_agent import AgentSession
from keep_agent.crewai import create_keep_tools

session = AgentSession()
tools = create_keep_tools(session)
```

### TypeScript

```bash
npm install @keep/agent
```

```typescript
import { KeepAgentSession, createNostrScope } from '@keep/agent';

const session = new KeepAgentSession(createNostrScope());
const info = await session.getSessionInfo();
```

### MCP Server (Claude/Cursor)

Add to your MCP configuration:

```json
{
  "servers": {
    "keep-signer": {
      "command": "keep",
      "args": ["mcp-server"],
      "env": {
        "KEEP_SESSION_TOKEN": "keep_sess_...",
        "KEEP_BUNKER_URL": "bunker://npub1.../wss://relay.example.com"
      }
    }
  }
}
```

---

## AWS Nitro Enclaves

Hardware-isolated signing—keys never leave enclave memory.

```bash
# Check enclave status
keep enclave status

# Verify attestation
keep enclave verify

# Generate key in enclave
keep enclave generate-key --name agent

# Import from vault to enclave
keep enclave import-key --name agent --from-vault mykey

# Sign message
keep enclave sign --key agent --message <hex>

# Sign PSBT
keep enclave sign-psbt --key agent --psbt tx.psbt --network testnet
```

**Local testing (insecure, dev only):**

```bash
keep enclave generate-key --name test --local
keep enclave sign --key test --message <hex> --local
```

See [docs/ENCLAVE.md](docs/ENCLAVE.md) for deployment.

---

## Hidden Volumes

Plausibly deniable storage—hidden volume is cryptographically undetectable:

```bash
# Create vault with hidden volume
KEEP_PASSWORD="outer" KEEP_HIDDEN_PASSWORD="hidden" keep --hidden init

# Access outer (decoy) volume
KEEP_PASSWORD="outer" keep list

# Access hidden volume
KEEP_PASSWORD="hidden" keep --hidden list
```

---

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `KEEP_PASSWORD` | Vault password (avoids interactive prompt) |
| `KEEP_HIDDEN_PASSWORD` | Hidden volume password (with `--hidden` flag) |
| `KEEP_PATH` | Custom vault path (default: `~/.keep`) |

---

## Security

| Feature | Implementation |
|---------|----------------|
| Key Derivation | Argon2id (256MB memory, 4 iterations) |
| Encryption | XChaCha20-Poly1305 |
| Checksums | BLAKE2b |
| RAM Protection | Keys encrypted with Ascon-128a, zeroized on drop |
| Code Safety | Pure Rust, `#![forbid(unsafe_code)]` |
| Threshold Sigs | FROST with BIP-340 Schnorr |
| Hardware Isolation | AWS Nitro Enclaves with attestation-based KMS |

---

## Development

```bash
# Build
cargo build --release

# Run tests
cargo test

# Debug logging
RUST_LOG=debug cargo run --bin keep -- <command>
```

---

## License

AGPL-3.0
