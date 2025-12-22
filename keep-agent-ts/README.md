# @keep/agent

TypeScript SDK for Keep - secure signing for AI agents.

## Installation

```bash
npm install @keep/agent
```

## Quick Start

```typescript
import { KeepAgentSession, createFullScope } from '@keep/agent';

// Create a session with signing capability
const session = new KeepAgentSession(
  createFullScope(),
  null,  // Use default rate limits
  24,    // Duration in hours
  null,  // No policy
  '<32-byte-hex-secret-key>'  // Required for signing
);

// Sign a Nostr event
const event = await session.signEvent(1, 'Hello from AI agent!');
console.log(`Event ID: ${event.id}`);
console.log(`Signature: ${event.sig}`);

// Get public key and Bitcoin address
const npub = await session.getPublicKey();
const address = await session.getBitcoinAddress('testnet');
```

## Session Constraints

All operations are enforced by session constraints:

```typescript
import { KeepAgentSession } from '@keep/agent';

// Create constrained session
const session = new KeepAgentSession(
  {
    operations: ['sign_nostr_event', 'get_public_key'],
    eventKinds: [1, 7],          // Only text notes and reactions
    maxAmountSats: 100_000,      // Max 0.001 BTC per tx
    addressAllowlist: ['bc1q...'],
  },
  { maxPerMinute: 10, maxPerHour: 100, maxPerDay: 1000 },
  24,
  null,
  '<hex-secret-key>'
);

// Signing enforces constraints automatically
await session.signEvent(1, 'Allowed');  // OK
await session.signEvent(4, 'DM');       // Throws error (kind 4 not allowed)
```

## Scope Presets

```typescript
import { createNostrScope, createBitcoinScope, createFullScope } from '@keep/agent';

createNostrScope();   // sign_nostr_event, get_public_key
createBitcoinScope(); // sign_psbt, get_public_key, get_bitcoin_address
createFullScope();    // All operations
```

## Remote Signing (NIP-46)

Connect to a remote Keep signer via NIP-46 bunker URL:

```typescript
import { RemoteSession } from '@keep/agent';

// Connect to remote signer
const session = await RemoteSession.connect(
  'bunker://npub1...?relay=wss://relay.example.com',
  30  // timeout in seconds
);

// Sign events remotely
const event = { kind: 1, content: 'Hello from remote!', tags: [] };
const signed = await session.signEvent(JSON.stringify(event));

// Get public key
const npub = await session.getPublicKey();

// NIP-44 encryption
const encrypted = await session.nip44Encrypt(recipientPubkey, 'secret message');
const decrypted = await session.nip44Decrypt(senderPubkey, encrypted);

// Cleanup
await session.disconnect();
```

## API Reference

### KeepAgentSession

| Method | Description |
|--------|-------------|
| `signEvent(kind, content, tags?)` | Sign a Nostr event |
| `signPsbt(psbtBase64, network?)` | Sign a Bitcoin PSBT |
| `getPublicKey()` | Get npub |
| `getBitcoinAddress(network?)` | Get p2tr address |
| `getSessionInfo()` | Get session status |
| `checkOperation(op)` | Check if operation allowed |
| `checkEventKind(kind)` | Check if event kind allowed |
| `checkAmount(sats)` | Check if amount within limit |
| `close()` | Close session |

### RemoteSession

| Method | Description |
|--------|-------------|
| `RemoteSession.connect(bunkerUrl, timeout?)` | Connect to remote signer |
| `signEvent(eventJson)` | Sign event via remote signer |
| `getPublicKey()` | Get public key from remote |
| `nip44Encrypt(pubkey, plaintext)` | NIP-44 encrypt |
| `nip44Decrypt(pubkey, ciphertext)` | NIP-44 decrypt |
| `ping()` | Ping remote signer |
| `disconnect()` | Disconnect from remote |

## Types

```typescript
interface SignedEvent {
  id: string;
  pubkey: string;
  createdAt: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

interface SessionScopeConfig {
  operations?: string[];
  eventKinds?: number[];
  maxAmountSats?: number;
  addressAllowlist?: string[];
}

interface RateLimitOptions {
  maxPerMinute?: number;
  maxPerHour?: number;
  maxPerDay?: number;
}
```

## License

AGPL-3.0
