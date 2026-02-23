# Keep

Self-custodial key management for Nostr and Bitcoin.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Remote Signing (NIP-46)](#remote-signing-nip-46)
- [Bitcoin](#bitcoin)
- [Threshold Signatures (FROST)](#threshold-signatures-frost)
- [Mobile (NIP-55)](#mobile-nip-55)
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

Requires Rust 1.89+ (MSRV).

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

### Policy Enforcement (Warden)

Integrate with [Warden](https://github.com/privkeyio/warden) for policy-based signing controls:

```bash
# Build with warden support
cargo build --release --features warden

# Sign with policy check
export WARDEN_TOKEN="<jwt>"
keep frost sign --warden-url http://localhost:3000 --group npub1... --message <hex>

# Network sign with policy check
keep frost network sign --warden-url http://localhost:3000 --group npub1... --message <hex>
```

Policy decisions:
- **ALLOW**: Signing proceeds
- **DENY**: Signing blocked with reason
- **REQUIRE_APPROVAL**: CLI waits for approval workflow (polls up to 5 minutes)

### Hardware Signing

Store FROST shares on an air-gapped hardware signer. See [keep-esp32](https://github.com/privkeyio/keep-esp32) for firmware.

```bash
# Test connection
keep frost hardware ping --device /dev/ttyACM0

# List shares on device
keep frost hardware list --device /dev/ttyACM0

# Import share to hardware
keep frost hardware import --device /dev/ttyACM0 --group npub1... --share 1

# Export share from hardware (encrypted backup)
keep frost hardware export --device /dev/ttyACM0 --group npub1... --output backup.json

# Network sign using hardware
keep frost network sign --group npub1... --message <hex> --relay wss://nos.lol --hardware /dev/ttyACM0
```

### Distributed Key Generation (DKG)

Generate threshold keys without any single party knowing the full private key. Each participant runs independently and coordinates via Nostr relay.

**Security: DKG vs Trusted Dealer**

| Aspect | Trusted Dealer (`frost generate`) | Distributed DKG (`frost network dkg`) |
|--------|-----------------------------------|---------------------------------------|
| Key exposure | Full key exists on one machine | Full key never exists anywhere |
| Entropy source | Single machine | All participants contribute |
| Compromise risk | Single point of failure | Requires threshold breach |
| Use case | Testing/development | Production |

The trusted dealer approach (`keep frost generate`) generates the full private key on a single machine. If that machine is compromised during generation, all funds are at risk. Distributed DKG ensures the complete key is never computed—each participant generates their share from independent entropy, so no single device ever holds enough information to reconstruct the key.

```bash
# Participant 1 (on first device)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 1 \
  --relay wss://nos.lol \
  --hardware /dev/ttyACM0

# Participant 2 (on second device, run simultaneously)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 2 \
  --relay wss://nos.lol \
  --hardware /dev/ttyACM0

# Participant 3 (on third device, run simultaneously)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 3 \
  --relay wss://nos.lol \
  --hardware /dev/ttyACM0
```

All participants must run the command within 5 minutes. On completion, each device stores its share and outputs the group public key.

---

## Mobile (NIP-55)

UniFFI library for Android/iOS apps to hold FROST shares and sign via NIP-55 protocol. See [keep-android](https://github.com/privkeyio/keep-android) for the Android app implementation.

```kotlin
// Android: Initialize with secure storage
val mobile = KeepMobile(AndroidSecureStorage(context))
mobile.importShare(kshare, passphrase, "phone")
mobile.initialize(listOf("wss://relay.example.com"))

// Handle NIP-55 intents
val handler = Nip55Handler(mobile)
val request = handler.parseIntentUri(intentUri)
val response = handler.handleRequest(request, callerPackage)
```

Supports `get_public_key`, `sign_event`, `nip44_encrypt`, `nip44_decrypt`.

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
| `WARDEN_TOKEN` | JWT token for Warden API authentication (requires `--features warden`) |

---

## Security

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

### Memory Locking

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

---

## Development

Install [just](https://github.com/casey/just):

```bash
cargo install just
```

Common tasks:

```bash
just build    # Build release binaries
just test     # Run all tests
just lint     # Run clippy and fmt check
just fmt      # Format all code
just doc      # Generate documentation
just ci       # Run full CI checks locally
```

Debug logging:

```bash
RUST_LOG=debug cargo run --bin keep -- <command>
```

### MSRV Policy

Minimum Supported Rust Version is **1.89**. MSRV changes are considered breaking and will be noted in release notes.

---

## License

AGPL-3.0
