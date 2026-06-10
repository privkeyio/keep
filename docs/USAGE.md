# Usage

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Backup & Restore](#backup--restore)
- [Remote Signing (NIP-46)](#remote-signing-nip-46)
- [Bitcoin](#bitcoin)
- [Threshold Signatures (FROST)](#threshold-signatures-frost)
- [Wallet Descriptor Coordination](#wallet-descriptor-coordination)
- [Audit Log](#audit-log)
- [Mobile (NIP-55)](#mobile-nip-55)
- [Agent SDK](#agent-sdk)
- [AWS Nitro Enclaves](#aws-nitro-enclaves)
- [Hidden Volumes](#hidden-volumes)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Installation

Requires Rust 1.89+ (MSRV). System dependencies (for the hardware-signer serial support)
vary by platform: Linux needs `pkg-config` and `libudev` (`build-essential`/`libudev-dev`),
macOS needs the Xcode Command Line Tools, and Windows needs nothing extra. See
[`BUILD.md`](../BUILD.md) for the full list.

**Install the CLI directly:**

```bash
cargo install --git https://github.com/privkeyio/keep keep-cli
```

**From a clone:**

```bash
git clone https://github.com/privkeyio/keep
cd keep
cargo install --path keep-cli   # installs `keep` to ~/.cargo/bin
# or, to run without installing:
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

Run `keep <command> --help` for the full flag list of any command.

**Global flags** (valid on every command):

| Flag | Description |
|------|-------------|
| `--path <dir>` | Use a vault at this path instead of `~/.keep` (also `KEEP_HOME`) |
| `--hidden` | Operate on the hidden volume (see [Hidden Volumes](#hidden-volumes)) |
| `--no-mlock` | Disable memory locking, accepting degraded security |

**Vault & keys:**

| Command | Description |
|---------|-------------|
| `keep init` | Create encrypted vault |
| `keep generate --name <n>` | Generate new Nostr key |
| `keep import --name <n>` | Import existing nsec |
| `keep list` | List all keys |
| `keep export --name <n>` | Print a raw nsec (interactive TTY only, by design) |
| `keep delete --name <n>` | Delete key |
| `keep rotate-password` | Change the vault unlock password |
| `keep rotate-data-key` | Rotate the data-encryption key (re-encrypts every secret) |
| `keep backup [--output <file>]` | Write a passphrase-encrypted vault backup |
| `keep restore <file> --target <dir>` | Restore a backup into a **new** vault |

**Signing & coordination:**

| Command | Description |
|---------|-------------|
| `keep serve` | Start the NIP-46 bunker (and optional FROST co-signer) |
| `keep frost ...` | FROST threshold operations (see [FROST](#threshold-signatures-frost)) |
| `keep wallet ...` | Wallet descriptors, proposals, PSBT spend coordination (see [Wallet](#wallet-descriptor-coordination)) |
| `keep bitcoin ...` | Addresses, descriptors, PSBT signing (see [Bitcoin](#bitcoin)) |
| `keep nip46 ...` | NIP-46 client app grant management (see [Remote Signing](#remote-signing-nip-46)) |
| `keep enclave ...` | AWS Nitro Enclave operations (see [Enclaves](#aws-nitro-enclaves)) |
| `keep agent mcp --key <n>` | Run the MCP signing server (see [Agent SDK](#agent-sdk)) |
| `keep sign <file> --group <npub>` | Threshold-sign a file (minisign-compatible) |
| `keep verify <file> <sig> --group <npub>` | Verify a minisign detached signature |

**Maintenance:**

| Command | Description |
|---------|-------------|
| `keep audit ...` | Inspect, verify, export, or prune the audit log (see [Audit Log](#audit-log)) |
| `keep config show \| path \| init` | Inspect or initialize the CLI config file |
| `keep migrate status` | Inspect on-disk schema migration state |

---

## Backup & Restore

Your vault lives at `~/.keep` (or `KEEP_HOME` / `--path`). Back it up regularly: if you
lose it and have no backup, the keys are gone.

```bash
# Write a passphrase-encrypted backup file
keep backup --output keep-backup.enc

# Restore into a NEW vault (never overwrites the active ~/.keep)
keep restore keep-backup.enc --target ~/keep-restored
```

`restore` requires an explicit `--target` and refuses to write over an existing vault, so
a restore can never clobber your live keys.

For FROST shares specifically, use `keep frost export` / `keep frost import` (per-share,
passphrase-encrypted) so shares can be moved or backed up independently. See
[Threshold Signatures](#threshold-signatures-frost).

---

## Remote Signing (NIP-46)

Sign from any NIP-46 compatible client without exposing your private key:

```bash
keep serve --relay wss://bucket.coracle.social
```

This displays a bunker URL to paste into your client.

**Controls:** `Y` approve, `N` reject, `Q` quit

### Pre-granting client apps (headless)

Instead of approving each connection interactively, pre-authorize a client app's pubkey so
`keep serve` accepts it automatically. This is the headless alternative to the interactive
prompt.

```bash
# Grant a client app a set of permissions
keep nip46 grant <client-npub> \
  --name "my-client" \
  --permissions get_public_key,sign_event \
  --auto-approve-kinds 1,7 \
  --duration forever

# List existing grants
keep nip46 apps

# Revoke a grant
keep nip46 revoke <client-npub>

# Globally auto-approve specific event kinds for every client (interactive serving)
keep nip46 auto-approve --kinds 1,7
```

Permission names: `get_public_key`, `sign_event`, `nip04_encrypt`, `nip04_decrypt`,
`nip44_encrypt`, `nip44_decrypt` (or `all`). `--duration` accepts `session`, `forever`, or
a number of seconds.

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
keep frost network serve --group npub1... --relay wss://bucket.coracle.social

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
keep frost network sign --group npub1... --message <hex> --relay wss://bucket.coracle.social --hardware /dev/ttyACM0
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

The trusted dealer approach (`keep frost generate`) generates the full private key on a single machine. If that machine is compromised during generation, all funds are at risk. Distributed DKG ensures the complete key is never computed: each participant generates their share from independent entropy, so no single device ever holds enough information to reconstruct the key.

```bash
# Participant 1 (on first device)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 1 \
  --relay wss://bucket.coracle.social \
  --hardware /dev/ttyACM0

# Participant 2 (on second device, run simultaneously)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 2 \
  --relay wss://bucket.coracle.social \
  --hardware /dev/ttyACM0

# Participant 3 (on third device, run simultaneously)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 3 \
  --relay wss://bucket.coracle.social \
  --hardware /dev/ttyACM0
```

All participants must run the command within 5 minutes. On completion, each device stores its share and outputs the group public key.

---

## Wallet Descriptor Coordination

Turn a FROST group into a Bitcoin wallet with proper external/internal address chains and
optional time-locked recovery tiers, coordinated across signers over Nostr.

```bash
# Simple descriptor from a FROST group (no recovery tiers).
# Single-key FROST descriptors have no BIP-32 derivation, so receive and change
# collapse to one address; --allow-address-reuse is required to acknowledge that.
keep wallet descriptor --group npub1... --network mainnet --allow-address-reuse

# Propose a coordinated descriptor with a recovery tier (preferred: distinct chains)
keep wallet propose --group npub1... --network mainnet \
  --recovery '2of3@6mo' --relay wss://bucket.coracle.social

# Inspect / export a stored descriptor
keep wallet show --group npub1...
keep wallet export --group npub1... --format sparrow

# Announce recovery xpubs to peers, register on a NIP-46 hardware signer
keep wallet announce-keys --group npub1... --xpub 'xpub.../fingerprint/label'
keep wallet register --group npub1... --device 'bunker://...'

# Coordinate a recovery-tier (scriptpath) spend via PSBT
keep wallet spend --group npub1... --recovery-tier 0 --psbt-file unsigned.psbt
keep wallet approve-psbt --group npub1... --session <id> --signer-bunker 'fp:bunker://...'

# List stored descriptors
keep wallet list
```

Recovery tier syntax is `threshold-of-keys@timelock`, e.g. `2of3@6mo` or `3of5@1y`.

---

## Audit Log

Signing and key-lifecycle operations are recorded in a tamper-evident, hash-chained audit
log inside the vault.

```bash
keep audit list --limit 50      # Recent entries
keep audit verify               # Verify hash-chain integrity
keep audit stats                # Summary statistics
keep audit export --output audit.json
keep audit retention --max-days 90 --apply   # Prune old entries
```

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

Not yet published to PyPI. Install from a repo clone (the build backend is
[maturin](https://www.maturin.rs/)):

```bash
pip install ./keep-agent-py
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

Not yet published to npm. Build from a repo clone:

```bash
cd keep-agent-ts && npm install && npm run build
```

```typescript
import { KeepAgentSession, createNostrScope } from '@keep/agent';

const session = new KeepAgentSession(createNostrScope());
const info = await session.getSessionInfo();
```

### MCP Server (Claude/Cursor)

`keep agent mcp` runs a stdio MCP signing server bound to one vault key. The server signs
under a constrained policy, so the model gets signing capability without ever seeing the
private key.

```bash
keep agent mcp --key main
```

Add it to your MCP client configuration:

```json
{
  "servers": {
    "keep-signer": {
      "command": "keep",
      "args": ["agent", "mcp", "--key", "main"]
    }
  }
}
```

Set `KEEP_PASSWORD` in the server's environment so it can unlock the vault non-interactively.

---

## AWS Nitro Enclaves

Hardware-isolated signing, keys never leave enclave memory.

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

See [ENCLAVE.md](ENCLAVE.md) for deployment.

---

## Hidden Volumes

Plausibly deniable storage, hidden volume is cryptographically undetectable:

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
| `KEEP_HOME` | Custom vault path (default: `~/.keep`). Must be absolute. Equivalent to `--path` |
| `KEEP_PASSWORD` | Vault password (avoids interactive prompt) |
| `KEEP_HIDDEN_PASSWORD` | Hidden volume password (with `--hidden`) |
| `KEEP_YES` | Auto-confirm non-destructive prompts in scripts |
| `WARDEN_TOKEN` | JWT for Warden API authentication (requires `--features warden`) |

> `KEEP_PATH` is **not** used by the CLI; it configures the vault path for the `keep-web`
> co-signer only. For the CLI, use `KEEP_HOME` or `--path`. See
> [`keep-web/README.md`](../keep-web/README.md) for the co-signer's variables.

---

## Troubleshooting

**`mlock` warning at startup.** Keep locks secret memory with `mlock(2)`. On systems with a
low `RLIMIT_MEMLOCK`, locking can fail and Keep logs a warning but continues with degraded
protection. Raise the limit (`ulimit -l`) or pass `--no-mlock` to silence it deliberately.

**`keep export` refuses to run.** Raw nsec export is interactive-only by design: it requires
a real TTY on stdin and stderr and refuses when automation variables (`KEEP_YES` /
`KEEP_PASSWORD`) are set. Run it directly in a terminal.

**Forgot which volume / hidden volume not appearing.** Hidden volumes are unlocked by
password: pass `--hidden` with the hidden password. There is no way to detect or recover a
hidden volume without its password. See [Hidden Volumes](#hidden-volumes).

**`KEEP_HOME must be an absolute path`.** `KEEP_HOME` rejects relative paths. Use a full
path, e.g. `KEEP_HOME=/home/you/.keep-work`.

**Network FROST signers cannot find each other.** All participants must use the same
`--group` and at least one shared `--relay`, and (for DKG) run within the coordination
window. Check liveness with `keep frost network peers --group npub1...`.

