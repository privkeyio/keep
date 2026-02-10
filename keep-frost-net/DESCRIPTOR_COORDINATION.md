# Wallet Descriptor Coordination Protocol (WDC)

## Problem

FROST group members need to agree on a wallet spending policy — recovery tiers,
timelocks, which keys go where — and each receive a finalized descriptor they can
import into wallet software. Today this is done manually out-of-band (error-prone,
no verification). Nunchuk and Liana solve this with centralized servers. We solve
it with Nostr relays that already carry our FROST signing traffic.

## Architecture Decision

**Build inside keep, not a separate repo.** Rationale:

- `keep-frost-net` already has NIP-44 encrypted messaging, peer discovery,
  session management, replay protection — all reusable
- `keep-bitcoin` already has descriptor generation, recovery tiers, Taproot scripts
- The descriptor coordination is key management, not wallet operations
- Wallet ops (UTXOs, coin selection, fee estimation) remain out of scope — export
  descriptors to Sparrow/Liana/Electrum for spending

## Key Insight: FROST + Taproot

```
Taproot output = internal_key + script_tree
                      │                │
              FROST group pubkey    Recovery paths
              (keypath spend)       (scriptpath spend)
```

The FROST group already handles the primary spending path via threshold signing.
What needs coordination is the **recovery script tree**: which xpubs, what
thresholds, what timelocks. That's what WDC coordinates.

## Protocol Flow

```
Initiator                              Participants
    │                                        │
    │── DescriptorPropose ─────────────────>│
    │   (policy template + own recovery     │
    │    xpub + network)                    │
    │                                        │
    │<──────────── DescriptorContribute ────│
    │   (their account xpub + fingerprint)  │
    │   ... repeat until all slots filled   │
    │                                        │
    │── DescriptorFinalize ────────────────>│
    │   (assembled descriptor pair)         │
    │                                        │
    │<──────────── DescriptorAck ───────────│
    │   (descriptor hash = verified)        │
    │                                        │
    │   All ACKs received → Complete        │
```

## Phase 1: Protocol Messages

**File:** `keep-frost-net/src/protocol.rs`

Add 4 new variants to `KfpMessage`:

```rust
DescriptorPropose(DescriptorProposePayload),
DescriptorContribute(DescriptorContributePayload),
DescriptorFinalize(DescriptorFinalizePayload),
DescriptorAck(DescriptorAckPayload),
```

### Payloads

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DescriptorProposePayload {
    pub session_id: [u8; 32],
    pub group_pubkey: [u8; 32],
    pub created_at: u64,
    pub network: String,       // "bitcoin" | "testnet" | "signet" | "regtest"
    pub policy: WalletPolicy,
    pub initiator_xpub: String,
    pub initiator_fingerprint: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WalletPolicy {
    /// Recovery tiers (primary spend is always FROST keypath)
    pub recovery_tiers: Vec<PolicyTier>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicyTier {
    pub threshold: u32,
    pub key_slots: Vec<KeySlot>,
    pub timelock_months: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum KeySlot {
    /// Participant by share index — they'll contribute their xpub
    Participant(u16),
    /// Pre-known external key (inheritance lawyer, hardware backup, etc.)
    External {
        xpub: String,
        fingerprint: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DescriptorContributePayload {
    pub session_id: [u8; 32],
    pub group_pubkey: [u8; 32],
    pub share_index: u16,
    pub account_xpub: String,
    pub fingerprint: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DescriptorFinalizePayload {
    pub session_id: [u8; 32],
    pub group_pubkey: [u8; 32],
    pub external_descriptor: String,
    pub internal_descriptor: String,
    /// SHA256 of canonical policy — participants verify this matches the proposal
    pub policy_hash: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DescriptorAckPayload {
    pub session_id: [u8; 32],
    pub group_pubkey: [u8; 32],
    /// SHA256 of external_descriptor — proves they independently validated
    pub descriptor_hash: [u8; 32],
}
```

### Session ID Derivation

```rust
fn derive_descriptor_session_id(
    group_pubkey: &[u8; 32],
    policy: &WalletPolicy,
    created_at: u64,
) -> [u8; 32] {
    // SHA256(group_pubkey || canonical_policy_bytes || created_at)
    // Deterministic, prevents replay, ties to specific group + proposal
}
```

### Validation Constants

```rust
pub const MAX_RECOVERY_TIERS: usize = 10;
pub const MAX_KEYS_PER_TIER: usize = 20;
pub const MAX_XPUB_LENGTH: usize = 256;
pub const MAX_FINGERPRINT_LENGTH: usize = 8;
pub const DESCRIPTOR_SESSION_TIMEOUT_SECS: u64 = 600; // 10 minutes
```

## Phase 2: Descriptor Session State Machine

**New file:** `keep-frost-net/src/descriptor_session.rs`

```rust
pub enum DescriptorSessionState {
    /// Proposal sent, waiting for xpub contributions
    Proposed,
    /// All xpubs collected, descriptor assembled and sent
    Finalized,
    /// All participants ACKed — done
    Complete,
    /// Timeout or validation failure
    Failed(String),
}

pub struct DescriptorSession {
    session_id: [u8; 32],
    group_pubkey: [u8; 32],
    policy: WalletPolicy,
    network: String,
    /// share_index → (xpub, fingerprint)
    contributions: BTreeMap<u16, XpubContribution>,
    /// Which share_indices we need xpubs from
    expected_contributors: HashSet<u16>,
    /// Assembled descriptor (set after all contributions received)
    descriptor: Option<FinalizedDescriptor>,
    acks: HashSet<u16>,
    expected_acks: HashSet<u16>,
    state: DescriptorSessionState,
    created_at: Instant,
    timeout: Duration,
}

pub struct XpubContribution {
    pub account_xpub: String,
    pub fingerprint: String,
}

pub struct FinalizedDescriptor {
    pub external: String,
    pub internal: String,
    pub policy_hash: [u8; 32],
}

pub struct DescriptorSessionManager {
    sessions: HashMap<[u8; 32], DescriptorSession>,
    default_timeout: Duration,
}
```

**State transitions:**
- `Proposed` → receives all contributions → auto-transitions to `Finalized`
- `Finalized` → receives all ACKs → `Complete`
- Any state → timeout → `Failed("timeout")`
- Any state → validation error → `Failed(reason)`

## Phase 3: Node Handler

**New file:** `keep-frost-net/src/node/descriptor.rs`

```rust
impl KfpNode {
    /// Initiator calls this to start descriptor coordination.
    /// Sends DescriptorPropose to all online peers in the FROST group.
    pub async fn request_descriptor(
        &self,
        policy: WalletPolicy,
        network: &str,
        own_xpub: &str,
        own_fingerprint: &str,
    ) -> Result<[u8; 32]>; // returns session_id

    /// Handle incoming proposal — validate policy, auto-contribute own xpub
    async fn handle_descriptor_propose(
        &self,
        sender: PublicKey,
        payload: DescriptorProposePayload,
    ) -> Result<()>;

    /// Handle xpub contribution — store it, assemble descriptor when complete
    async fn handle_descriptor_contribute(
        &self,
        sender: PublicKey,
        payload: DescriptorContributePayload,
    ) -> Result<()>;

    /// Handle finalized descriptor — validate independently, ACK if correct
    async fn handle_descriptor_finalize(
        &self,
        sender: PublicKey,
        payload: DescriptorFinalizePayload,
    ) -> Result<()>;

    /// Handle ACK — track, emit DescriptorComplete event when all received
    async fn handle_descriptor_ack(
        &self,
        sender: PublicKey,
        payload: DescriptorAckPayload,
    ) -> Result<()>;
}
```

**Wire into existing dispatch** in `node/mod.rs`:
- Add `DescriptorPropose` to the trusted-peer bypass list (like `Announce`, `SignRequest`)
- Add match arms in `handle_event`
- Add `descriptor_sessions: Arc<RwLock<DescriptorSessionManager>>` to `KfpNode`

**New events** for `KfpNodeEvent`:

```rust
DescriptorProposed {
    session_id: [u8; 32],
    policy: WalletPolicy,
    network: String,
},
DescriptorContributed {
    session_id: [u8; 32],
    share_index: u16,
},
DescriptorComplete {
    session_id: [u8; 32],
    external_descriptor: String,
    internal_descriptor: String,
},
DescriptorFailed {
    session_id: [u8; 32],
    error: String,
},
```

## Phase 4: Descriptor Builder

**File:** `keep-bitcoin/src/descriptor.rs`

Extend `DescriptorExport` to build FROST wallet descriptors:

```rust
impl DescriptorExport {
    /// Build descriptor from FROST group key + recovery tiers.
    ///
    /// Internal key = FROST group pubkey (keypath = threshold sign)
    /// Script tree = recovery tiers from RecoveryConfig
    pub fn from_frost_wallet(
        group_pubkey: &[u8; 32],
        recovery: &RecoveryConfig,
        network: Network,
    ) -> Result<Self>;
}
```

This reuses the existing `RecoveryConfig` + `build_taproot()` machinery in
`recovery.rs`. The only change: instead of NUMS internal key, use the FROST
group pubkey as the Taproot internal key.

Also add a helper to `RecoveryConfig` that builds from `WalletPolicy` +
collected xpubs:

```rust
impl RecoveryConfig {
    pub fn from_policy(
        policy: &WalletPolicy,
        contributions: &BTreeMap<u16, XpubContribution>,
        network: Network,
    ) -> Result<Self>;
}
```

## Phase 5: keep-core Storage

**File:** `keep-core/src/lib.rs` — extend `Keep` API

```rust
pub struct WalletDescriptor {
    pub group_pubkey: [u8; 32],
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub network: String,
    pub policy: WalletPolicy,
    pub created_at: u64,
}

impl Keep {
    pub fn store_wallet_descriptor(
        &self,
        descriptor: &WalletDescriptor,
    ) -> Result<()>;

    pub fn get_wallet_descriptor(
        &self,
        group_pubkey: &[u8; 32],
    ) -> Result<Option<WalletDescriptor>>;

    pub fn list_wallet_descriptors(&self) -> Result<Vec<WalletDescriptor>>;

    pub fn delete_wallet_descriptor(
        &self,
        group_pubkey: &[u8; 32],
    ) -> Result<()>;
}
```

New redb table: `WALLET_DESCRIPTORS` keyed by `[u8; 32]` (group pubkey).
Encrypted at rest like all other Keep data.

## Phase 6: CLI & Desktop Integration

### keep-cli

```
keep wallet propose --group <hex> --network signet --recovery "2of3@6mo"
keep wallet list
keep wallet export --group <hex> --format sparrow
keep wallet delete --group <hex>
```

### keep-desktop

New "Wallet" tab/screen:
- Shows descriptor for each FROST group that has one
- "Setup Wallet" button → starts WDC flow with connected peers
- Policy editor (threshold, tiers, timelocks)
- Export to Sparrow JSON / plain descriptor

### keep-mobile (UniFFI)

Expose through existing UniFFI bindings:
- `wallet_descriptor_list()` → `Vec<WalletDescriptorInfo>`
- `wallet_descriptor_export(group_pubkey, format)` → `String`

## Security Considerations

1. **All messages NIP-44 encrypted** — relays see nothing
2. **Session ID is deterministic** — replay protection via existing mechanism
3. **Each participant independently validates** the finalized descriptor by:
   - Verifying their xpub appears in the correct slot
   - Verifying the policy hash matches the original proposal
   - Recomputing the descriptor locally and comparing
4. **Descriptor hash in ACK** — proves validation happened, not blind acceptance
5. **Timeout prevents stale sessions** — 10 minute default
6. **Xpubs are not secret** — but still encrypted in transit to prevent
   address correlation by relay operators

## Future Extensions

- **Non-FROST multisig**: Extend protocol to coordinate standard `multi()` or
  `sortedmulti()` descriptors where participants aren't in a FROST group
- **Descriptor updates**: Version field in policy, migration protocol for
  adding/removing recovery keys
- **Hardware wallet registration**: NIP-46 extension to trigger `register_wallet`
  on remote hardware signers
- **PSBT coordination**: Extend protocol for coordinating PSBT signing for
  scriptpath spends (recovery tier activation)
- **Nonce pre-exchange**: Bifrost-style nonce pool management during idle time
  for instant signing when needed

## Implementation Status

| Phase | Status | Files |
|-------|--------|-------|
| 1. Protocol messages | **Done** | `keep-frost-net/src/protocol.rs` — 4 new `KfpMessage` variants, `WalletPolicy`/`PolicyTier`/`KeySlot` types, validation |
| 2. Session state machine | **Done** | `keep-frost-net/src/descriptor_session.rs` — `DescriptorSession`, `DescriptorSessionManager`, 20 unit tests |
| 3. Node handler | **Done** | `keep-frost-net/src/node/descriptor.rs` — `request_descriptor()`, `contribute_descriptor()`, `finalize_descriptor()`, 4 handle methods, 7 new `KfpNodeEvent` variants |
| 4. Descriptor builder | **Done** | `keep-bitcoin/src/descriptor.rs` — `from_frost_wallet()`, `pubkey_fingerprint()`. `keep-bitcoin/src/recovery.rs` — `build_with_internal_key()`. 3 unit tests |
| 5. Storage | **Done** | `keep-core/src/wallet.rs`, `keep-core/src/storage.rs`, `keep-core/src/backend.rs`, `keep-core/src/migration.rs` — `WalletDescriptor`, redb table, schema v2 migration, rotation support |
| 6. CLI/Desktop | **Pending** | — |

## Implementation Order

1. Protocol messages (Phase 1) — foundation, no behavior change
2. Session state machine (Phase 2) — testable in isolation
3. Descriptor builder (Phase 4) — extend keep-bitcoin, testable in isolation
4. Node handler (Phase 3) — wires 1+2+4 together
5. Storage (Phase 5) — persist results
6. CLI/Desktop (Phase 6) — user-facing

Phases 1-3 can be developed and tested independently before integration.

## References

- **Bifrost**: FROST-over-Nostr nonce pools, onboarding flow, middleware hooks
- **Joinstr**: NIP-4 encrypted coordination, ephemeral keypairs per session, timeout pools
- **Liana**: Descriptor templates, hardware wallet registration, HMAC tokens
- **Liana Connect**: Centralized coordination we're replacing with Nostr relays
