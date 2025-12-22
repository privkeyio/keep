# Keep

Self-custodial key management for Nostr and Bitcoin.

## Quick Start

```bash
# 1. Install
cargo install --path keep-cli

# 2. Create your encrypted vault (you'll set a password)
keep init

# 3. Generate a new Nostr key
keep generate --name main

# 4. See your keys
keep list
```

Your keys are encrypted at `~/.keep`.

## Install

```bash
cargo install --path keep-cli
```

Requires Rust 1.70+. To build from source:

```bash
git clone https://github.com/privkeyio/keep
cd keep
cargo build --release
./target/release/keep --help
```

## Commands

```bash
keep init                     # Create encrypted vault
keep generate --name <n>      # Generate new key
keep import --name <n>        # Import existing nsec
keep list                     # List keys
keep export --name <n>        # Export nsec
keep delete --name <n>        # Delete key
keep serve                    # Start NIP-46 remote signer
```

## Remote Signing (NIP-46)

Sign from any NIP-46 compatible client without exposing your private key:

```bash
keep serve --relay wss://relay.damus.io
```

Displays a bunker URL to paste into your client. Approve requests with `Y`, reject with `N`, quit with `Q`.

## Bitcoin

BIP-86 Taproot addresses and PSBT signing:

```bash
keep bitcoin address --key main              # Receive address
keep bitcoin address --key main --change     # Change address
keep bitcoin descriptor --key main           # Watch-only descriptor
keep bitcoin analyze --psbt unsigned.psbt    # Inspect PSBT
keep bitcoin sign --key main --psbt unsigned.psbt
```

## Threshold Signatures (FROST)

Split keys into t-of-n shares for distributed signing:

```bash
keep frost generate --threshold 2 --shares 3   # Create 2-of-3 key
keep frost split --key main -t 2 -s 3          # Split existing key
keep frost list                                 # List shares
keep frost export --share 1 --group npub1...   # Export share
keep frost import                               # Import share
keep frost sign --group npub1... --message <hex>
keep frost sign --group npub1... --message <hex> --interactive  # Multi-device
```

## Enclave (AWS Nitro)

Hardware-isolated signing—keys never leave enclave memory:

```bash
keep enclave status                              # Check status
keep enclave verify                              # Verify attestation
keep enclave generate-key --name agent           # Generate in enclave
keep enclave import-key --name agent --from-vault mykey
keep enclave sign --key agent --message <hex>
keep enclave sign-psbt --key agent --psbt tx.psbt --network testnet
```

Local testing (insecure, dev only):

```bash
keep enclave generate-key --name test --local
keep enclave sign --key test --message <hex> --local
```

See [docs/ENCLAVE.md](docs/ENCLAVE.md) for deployment.

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

# Check permissions before signing
if session.check_operation("sign_nostr_event"):
    session.record_request()

info = session.get_session_info()
print(f"Requests remaining: {info.requests_remaining}")
```

### LangChain

```python
from keep_agent import AgentSession
from keep_agent.langchain import KeepSignerTool

session = AgentSession()
tool = KeepSignerTool(session=session)
# Use with any LangChain agent
```

### CrewAI

```python
from keep_agent import AgentSession
from keep_agent.crewai import create_keep_tools

session = AgentSession()
tools = create_keep_tools(session)
# Use with CrewAI agents
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

## Hidden Volumes

Plausibly deniable storage—hidden volume is cryptographically undetectable:

```bash
KEEP_PASSWORD="outer" KEEP_HIDDEN_PASSWORD="hidden" keep --hidden init
KEEP_PASSWORD="outer" keep list           # Decoy keys
KEEP_PASSWORD="hidden" keep --hidden list # Real keys
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KEEP_PASSWORD` | Vault password (avoids interactive prompt) |
| `KEEP_HIDDEN_PASSWORD` | Hidden volume password (with `--hidden` flag) |
| `KEEP_PATH` | Custom vault path (default: `~/.keep`) |

## Security

- Argon2id key derivation (256MB, 4 iterations)
- XChaCha20-Poly1305 encryption, BLAKE2b checksums
- Keys encrypted in RAM (Ascon-128a), zeroized on drop
- Pure Rust, `#![forbid(unsafe_code)]`
- FROST uses BIP-340 Schnorr
- Nitro Enclaves with attestation-based KMS policies

## Development

```bash
# Build
cargo build --release

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run --bin keep -- <command>
```

## License

AGPL-3.0
