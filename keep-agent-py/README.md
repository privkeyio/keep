# keep-agent

Python SDK for Keep - secure signing for AI agents.

## Installation

```bash
pip install keep-agent
```

## Quick Start

```python
from keep_agent import AgentSession, SessionScope

# Create a session with signing capability
session = AgentSession(
    scope=SessionScope.full(),
    secret_key="<32-byte-hex-secret-key>",  # Required for signing
)

# Sign a Nostr event
event = session.sign_event(kind=1, content="Hello from AI agent!")
print(f"Event ID: {event['id']}")
print(f"Signature: {event['sig']}")

# Get public key and Bitcoin address
npub = session.get_public_key()
address = session.get_bitcoin_address(network="testnet")
```

## Session Constraints

All operations are enforced by session constraints:

```python
from keep_agent import AgentSession, SessionScope, RateLimit

# Create constrained session
session = AgentSession(
    scope=SessionScope(
        operations=["sign_nostr_event", "get_public_key"],
        event_kinds=[1, 7],          # Only text notes and reactions
        max_amount_sats=100_000,     # Max 0.001 BTC per tx
        address_allowlist=["bc1q..."],
    ),
    rate_limit=RateLimit(
        max_per_minute=10,
        max_per_hour=100,
        max_per_day=1000,
    ),
    duration_hours=24,
    secret_key="<hex-secret-key>",
)

# Signing enforces constraints automatically
event = session.sign_event(kind=1, content="Allowed")  # OK
event = session.sign_event(kind=4, content="DM")       # Raises error (kind 4 not allowed)
```

## Scope Presets

```python
SessionScope.nostr_only()   # sign_nostr_event, get_public_key
SessionScope.bitcoin_only() # sign_psbt, get_public_key, get_bitcoin_address
SessionScope.full()         # All operations
```

## Remote Signing (NIP-46)

Connect to a remote Keep signer via NIP-46 bunker URL:

```python
from keep_agent import RemoteSession

# Connect to remote signer
session = RemoteSession.connect(
    bunker_url="bunker://npub1...?relay=wss://relay.example.com",
    timeout_seconds=30,
)

# Sign events remotely (pass dict, not JSON string)
event = {"kind": 1, "content": "Hello from remote!", "tags": [], "created_at": 0}
signed = session.sign_event(event)
print(f"Signed: {signed['id']}")

# Get public key
npub = session.get_public_key()

# NIP-44 encryption
encrypted = session.nip44_encrypt(recipient_pubkey, "secret message")
decrypted = session.nip44_decrypt(sender_pubkey, encrypted)

# Cleanup
session.disconnect()
```

Or use as context manager:

```python
with RemoteSession.connect("bunker://npub1...?relay=wss://...") as session:
    signed = session.sign_event({"kind": 1, "content": "Hello!", "tags": [], "created_at": 0})
```

## LangChain Integration

```python
from keep_agent import AgentSession, SessionScope
from keep_agent.langchain import KeepSignerTool

session = AgentSession(
    scope=SessionScope.full(),
    secret_key="<hex-secret-key>",
)
tool = KeepSignerTool(session=session)

# Use with LangChain agent
from langchain.agents import create_react_agent
agent = create_react_agent(llm, [tool])
```

## CrewAI Integration

```python
from keep_agent import AgentSession, SessionScope
from keep_agent.crewai import create_keep_tools

session = AgentSession(
    scope=SessionScope.full(),
    secret_key="<hex-secret-key>",
)
tools = create_keep_tools(session)

# Use with CrewAI
from crewai import Agent
agent = Agent(role="Social Manager", tools=tools)
```

## API Reference

### AgentSession

| Method | Description |
|--------|-------------|
| `sign_event(kind, content, tags)` | Sign a Nostr event |
| `sign_psbt(psbt_base64, network)` | Sign a Bitcoin PSBT |
| `get_public_key()` | Get npub |
| `get_bitcoin_address(network)` | Get p2tr address |
| `get_session_info()` | Get session status |
| `check_operation(op)` | Check if operation allowed |
| `check_event_kind(kind)` | Check if event kind allowed |
| `check_amount(sats)` | Check if amount within limit |

### RemoteSession

| Method | Description |
|--------|-------------|
| `RemoteSession.connect(bunker_url, timeout_seconds)` | Connect to remote signer |
| `sign_event(event_json)` | Sign event via remote signer |
| `get_public_key()` | Get public key from remote |
| `nip44_encrypt(pubkey, plaintext)` | NIP-44 encrypt |
| `nip44_decrypt(pubkey, ciphertext)` | NIP-44 decrypt |
| `ping()` | Ping remote signer |
| `disconnect()` | Disconnect from remote |

## License

AGPL-3.0
