# Agent approvals over Nostr

Protocol version 1. **Status: draft for review.** Nothing in this document is implemented yet; it specifies keep-7oeou.4, and the gateway and keep-android work follow it once it is signed off. The decisions it still needs from the owner are listed at the end.

## What this is for

The agent gateway (`keep gateway serve`) refuses every request its policy marks as needing a human approval: Nostr kinds that move funds or rewrite the owner's data, NIP-44 with the key's own payloads, and spends above a grant's threshold. This protocol lets the gateway ask the owner's phone instead, and lets the phone answer with a decision the gateway can verify. It also carries the management changes that give agents more power (issuing a credential, unfreezing), freezes from the phone, and an anchor of the audit log the phone watches for rollback.

The goals, from the gateway design:

- An agent cannot produce, forge, replay or redirect an approval (C1, H2).
- The phone shows what will actually be signed, parsed from canonical data, with anything the agent wrote set apart (H2).
- A relay can delay or withhold messages but cannot read, change or replay them; silence means deny.
- Every request, decision and outcome is in the vault's audit log, and the phone notices if that log is rolled back (M2).

Out of scope, as in the design: a compromised approver phone, a compromised gateway host (root), kernel exploits, a malicious owner.

Approvals are optional. A gateway with no approver registered behaves as it does today: every request that needs an approval is refused, and management goes over the admin socket alone.

## Roles and keys

| Key | Held by | Used for |
|---|---|---|
| Channel key | The gateway, as a second TPM-sealed systemd credential, `channel-key` | Sealing every message the gateway sends; the identity approvers accept requests from |
| Approver key | One per approver device, generated and kept on the device | Sealing every message the approver sends, and signing decisions, freezes and unfreezes |
| Vault keys | The gateway's keyring | What agents use through their grants. Never used by this protocol |

- The channel key is a secp256k1 key sealed to the host the same way as the vault password, as the owner decided for the design. It is never in the vault, so no grant, tool or export can reach it.
  - `keep gateway channel-key new` generates it and writes it, as 64 hex characters on one line, only to a pipe or file, never a terminal, for `systemd-creds encrypt --name=channel-key --with-key=host+tpm2 --tpm2-pcrs=7 - /etc/keep/gateway/channel-key.cred`. It prints the public key on stderr.
  - The unit loads it with a second `LoadCredentialEncrypted=channel-key:...` line, added in the same drop-in that enables approvals, and the gateway reads it with `unlock::read_credential`, under the same checks as the password.
  - The vault records the channel public key when the first approver is registered. With an approver registered, the gateway refuses to start without the credential or with a different key: the owner relies on the phone for freezes, so it never runs silently cut off from it.
  - A new channel key (a new host, a cleared TPM) means `keep gateway approver reset` and pairing again.
  - The gateway refuses to start if the channel key is a key in the vault keyring. `Grant::validated` refuses a grant that names it in `keys` or `nip44_peers`.
- An approver key is generated on the phone (keep-android keeps it behind the Android Keystore). Registering one is refused if it is the channel key or any key in the vault keyring. `Grant::validated` refuses a grant naming a registered approver key, and a credential whose grant names a key that has since become an approver key is refused at authentication.
- The phone accepts requests only from the channel key it paired with. The gateway accepts decisions only from registered approver keys.

## What needs approval

**Agent requests.** Every `Decision::RequireApproval` from the policy engine:

| Reason | Example |
|---|---|
| `Kind(k)` | Signing kind 0, 3, 5, 62, the NIP-60 and NIP-61 kinds, or any kind from 10000 to 29999 the grant lists |
| `EncryptToOwnKey`, `DecryptOwnPayload` | NIP-44 where the counterparty is one of the grant's own keys |
| `AboveThreshold` | A spend that takes the credential's window total above `approval_above_sats` |

**Management changes** that give agents more power: issuing a credential, unfreezing a credential or the whole gateway, adding or removing an approver. Changes that only take power away (freeze, revoke, delete, a shorter expiry) and reads (status, list, audit) stay on the admin socket alone, as now.

**Never allowed for an agent, approved or not (C1):** signing any of this protocol's kinds (24250 to 24255) with any key, and any use of the channel key. `Grant::validated` refuses a grant that lists those kinds.

## Pairing and the approver set

The first approver is registered by root; later ones need an existing approver's signature.

1. On the gateway host, `keep gateway approver pair --label "Kyle's phone"` (root, or the admin uid for a later approver) asks the gateway for a pairing session: a random 32-byte secret, valid for 10 minutes and one use. The command shows it as a QR code and a URI: `keep-approver:v1?gateway=<channel npub>&secret=<hex>&relay=<url>&relay=<url>`.
2. The phone scans it, generates its approver key, and sends a `pair` message (kind 24254) to the channel key, with `proof = HMAC-SHA256(secret, "keep/approval/pair/v1" || approver_pubkey || channel_pubkey)` and its label. The seal is signed by the approver key, which proves the phone holds it.
3. The gateway checks the proof, that the secret is unused and unexpired, and that the key is neither the channel key nor in the keyring. The command then shows the approver's fingerprint (the first 10 bytes of SHA-256 of its public key, as hex in groups of 4), the phone shows the same, and the operator confirms they match. This stops anyone who saw the QR code from racing the phone.
4. For the first approver, confirming registers it. For a later one, confirming creates an `add_approver` management request, which an existing approver must approve.
5. The gateway answers with a `paired` message carrying the current anchor, the relays and the deadline.

**Removing an approver** is a management change any approver can approve, including the one being removed. Removing the last approver turns approvals off: every request that needs one is refused again, and management goes back to the admin socket alone.

**A lost phone:** root runs `keep gateway approver reset`, accepted only from uid 0, which removes every approver and is audited. Root already controls the host, so this gives it nothing new; the admin uid cannot do it.

## Transport

- **Relays.** The owner names one or more relays with `--approval-relay`. The phone learns them at pairing and uses the same set. Both sides reconnect with the options keep-frost-net already uses.
- **The relay helper.** The gateway keeps no network (its unit has `PrivateNetwork=yes` and only `AF_UNIX`), so a small helper, `keep gateway relay`, talks to the relays for it.
  - The helper runs as its own user, `keep-gateway-relay`, from its own unit, `keep-gateway-relay.service`, with network access and nothing else: no vault, no credential, no key.
  - The gateway listens on a third socket, `/run/keep-gateway-relay/relay.sock`, in a directory owned by `keep-gateway:keep-gateway-relay` with mode 0750 (made by the gateway unit's `ExecStartPre`, like the others), and accepts one connection at a time, only from the uid named by `--relay-user` (default `keep-gateway-relay`), checked with `SO_PEERCRED`.
  - The wire format is one JSON object per line, at most 128 KiB. From the gateway: `{"relays": [urls]}`, `{"subscribe": filter}`, `{"publish": event}`. From the helper: `{"event": event}` and `{"published": id, "ok": bool}`.
  - The helper only ever handles finished gift wraps, so it sees no more than a relay does. A compromised helper is a hostile relay, which this protocol already assumes: it can delay or drop messages, never read, forge or replay them.
  - The gateway unwraps and checks every event itself, outside the state lock, at most 600 per minute; any beyond that are dropped and counted in the status. Each wrap costs it a NIP-44 decryption before it knows the sender, and anyone can send wraps to the channel key, so this bounds what a flood can cost. A flood can still delay a decision until its deadline, which denies.
- **Wrapping.** Every message is a NIP-59 gift wrap (kind 1059) addressed to one recipient: an unsigned rumor of one of the kinds below, from the sender's real key, sealed (kind 13, signed by the sender's real key) and wrapped by a fresh ephemeral key. A relay sees only the recipient's public key, a randomized time and a size. A message to several approvers is wrapped once per approver.
- **Expiry.** Every wrap carries a NIP-40 `expiration` tag: the request's deadline plus 60 seconds for request traffic, one hour for anchors and pairing, one day for freezes. Relays may drop it after that; nothing in the protocol depends on them doing so.
- **Subscriptions.** Each side subscribes to kind 1059 with `#p` its own key, `since` two days back (NIP-59 timestamps are randomized up to two days into the past), and drops duplicates by rumor id.
- **Size.** A rumor, serialized, is at most 24 KiB. Sealed and wrapped, with NIP-44 padding and base64 twice, that stays under 64 KiB, the smallest event size limit common relays set. A request that would not fit (a very large PSBT or event) is refused as too large to approve.
- **Authentication.** A message counts only if the seal's signature verifies, the seal's key equals the rumor's `pubkey`, and that key is the expected peer: the paired channel key for the phone, a registered approver for the gateway (or the pairing session for `pair`).

Rumor kinds, all with JSON content carrying `"v": 1`:

| Kind | Name | From | To |
|---|---|---|---|
| 24250 | request | gateway | each approver |
| 24251 | decision | approver | gateway |
| 24252 | freeze | approver | gateway |
| 24253 | anchor | gateway | each approver |
| 24254 | pairing (`pair`, `paired`) | phone, gateway | gateway, phone |
| 24255 | outcome | gateway | each approver |

These kinds are never published bare; they only appear inside seals.

## Messages

Hex strings are lowercase. Times are Unix seconds on the gateway's calendar clock (the wall clock, never going back; see `keep-agent/src/gateway/daemon/clock.rs`).

### Request (24250)

```json
{
  "v": 1,
  "request_id": "<32 bytes hex, random>",
  "request_hash": "<32 bytes hex>",
  "created_at": 1791580000,
  "expires_at": 1791580120,
  "credential": { "id": "<16 bytes hex>", "name": "writer", "uid": 1001 },
  "op": "sign_nostr_event",
  "key": "<32 bytes hex, or null>",
  "network": null,
  "reason": { "type": "kind", "kind": 0 },
  "payload": { },
  "budget": null,
  "anchor": { "seq": 4210, "head": "<32 bytes hex>", "wallets": [ ] }
}
```

- `op` is one of `sign_nostr_event`, `sign_psbt`, `nip44_encrypt`, `nip44_decrypt`, `management`.
- `reason` is the policy's reason: `{"type": "kind", "kind": k}`, `{"type": "encrypt_to_own_key"}`, `{"type": "decrypt_own_payload"}`, `{"type": "above_threshold", "requested", "spent", "threshold"}`, or `{"type": "management"}`.
- `budget`, for a spend: `{"credential_spent", "credential_window", "wallet_spent", "wallet_window"}` in sats, before this request.
- `payload` depends on `op`:
  - `sign_nostr_event`: `{"event": {"pubkey", "created_at", "kind", "tags", "content"}}`, the exact unsigned event the gateway will sign. The gateway fixes `created_at` before asking and signs this event and no other.
  - `sign_psbt`: `{"unsigned_tx": "<hex>", "prevouts": [{"amount", "script": "<hex>"}], "sighash": [0 or 1 per input], "signing_inputs": [indices], "change_outputs": [indices], "fee", "leaving_wallet"}`. `change_outputs` are the outputs the gateway verified as its own change by re-deriving them; `sighash` is 0 for the default and 1 for `ALL`, the only types the signer accepts. The gateway keeps the PSBT and signs it unchanged.
  - `nip44_encrypt`: `{"peer": "<hex>", "plaintext": "<string>"}`.
  - `nip44_decrypt`: `{"peer": "<hex>", "ciphertext_sha256": "<hex>", "ciphertext_len": n}`. The phone cannot see the plaintext; approving lets it reach the agent and its model provider.
  - `management`: `{"change": { ... }}`, one of the changes listed under Management changes.

### Decision (24251)

```json
{ "v": 1, "request_id": "<hex>", "request_hash": "<hex>", "decision": "approve", "sig": "<64 bytes hex>" }
```

`decision` is `approve` or `deny`; `sig` is defined under Decision signature.

### Freeze (24252)

```json
{ "v": 1, "action": "freeze", "scope": "all", "counter": 17, "sig": "<64 bytes hex>" }
```

- `action` is `freeze` or `unfreeze`; `scope` is `"all"` or `{"credential": "<16 bytes hex>"}`.
- `counter` must be greater than the last counter the gateway accepted from this approver (persisted per approver), so a captured freeze or unfreeze cannot be replayed.
- A freeze takes effect at once, is audited, and is answered with an anchor message. An unfreeze from the phone is itself approver-signed, so it is accepted like an approved `unfreeze` management change.
- `created_at` and wrap expiry play no part in accepting a freeze: a freeze held back by a relay or the helper still freezes when it arrives, and the counter alone stops replays.

### Anchor (24253)

```json
{ "v": 1, "at": 1791580000, "anchor": { "seq": 4210, "head": "<hex>", "wallets": [ { "wallet": "main:<pubkey hex>", "seq": 88, "spent": 40000, "window": 100000 } ] }, "frozen": { "all": false, "credentials": [ "<16 bytes hex>" ] } }
```

Sent every 15 minutes and right after any freeze or unfreeze takes effect, so the phone shows what is frozen and confirms its own freeze arrived. The `anchor` object is also carried in every request; see Audit anchoring. `wallet` is the ledger's name: `main:` or `test:` (the test networks share one ledger) and the wallet's public key.

### Pairing (24254)

From the phone: `{"v": 1, "type": "pair", "label": "<string>", "proof": "<hex>"}`. From the gateway: `{"v": 1, "type": "paired", "approver": "<hex>", "relays": [...], "deadline_secs": 120, "anchor": { ... }}`, or `{"v": 1, "type": "refused", "reason": "<string>"}`.

### Outcome (24255)

```json
{ "v": 1, "request_id": "<hex>", "outcome": "approved", "by": "<approver hex, or null>" }
```

`outcome` is `approved`, `denied`, `expired` or `canceled` (frozen, revoked, gateway stopping). Sent to every approver, so other phones clear the request.

## Request binding

The hash binds a decision to one request, one gateway and one credential. It uses BIP-340 tagged hashes: `tagged(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`.

```
request_hash = tagged("keep/approval/request/v1",
    u8   version            = 1
    32   channel_pubkey     (x-only)
    16   credential_id      (zero for approver management)
    32   request_id         (random, from the gateway)
    u8   op
    32   key                (x-only; zero when the op has no key)
    u8   network
    u32  payload_len        (little-endian)
    ...  payload
)
```

`op`: 1 `sign_nostr_event`, 2 `sign_psbt`, 3 `nip44_encrypt`, 4 `nip44_decrypt`, 16 `management`. Codes 5 to 15 are reserved for keep-7oeou.5 (inject, ssh, reveal).

`network`: 0 none, 1 mainnet, 2 testnet3, 3 testnet4, 4 signet, 5 regtest.

`payload`, by op:

| op | payload |
|---|---|
| 1 | `event_id` (32) `\|\|` `pubkey` (32), where `event_id` is the NIP-01 id of the unsigned event in the request |
| 2 | `u32 len \|\| unsigned_tx` (consensus encoding) `\|\| u32 n \|\|` n × (`u64 amount \|\| u32 len \|\| script \|\| u8 sighash`) `\|\| u32 m \|\|` m × `u32 signing_input` `\|\| u32 c \|\|` c × `u32 change_output` |
| 3 | `peer` (32) `\|\|` SHA-256 of the plaintext's UTF-8 bytes (32) |
| 4 | `peer` (32) `\|\|` SHA-256 of the ciphertext (32) |
| 16 | SHA-256 of the change object serialized with RFC 8785 (JSON Canonicalization Scheme) |

Lists are in ascending index order. All integers are little-endian.

The phone recomputes the hash from the request's fields and refuses the request if it differs from `request_hash`. For `sign_psbt` it also recomputes the txid, each output's address for the network, the fee (prevouts minus outputs) and the total leaving the wallet (outputs not in `change_outputs`, plus the fee), and refuses the request if they differ from the gateway's figures.

## Decision signature

```
sig = BIP340_sign(approver_key, tagged("keep/approval/decision/v1",
    32  request_hash
    u8  decision          (1 approve, 0 deny)
    32  approver_pubkey
    32  channel_pubkey
))
```

The freeze signature is the same construction over `tagged("keep/approval/freeze/v1", channel_pubkey || approver_pubkey || u64 counter || u8 action (1 freeze, 2 unfreeze) || scope)`, where `scope` is `0x00` for all or `0x01 || credential_id`.

The gateway keeps each decision's signature in the audit log, so the log holds a proof of who approved what, verifiable without the relay or the phone.

## The gateway

**Parking a request.**

1. When the policy says `RequireApproval`, the gateway builds the exact object to sign (the unsigned event, the analyzed PSBT, the NIP-44 input), picks a random request id, computes the request hash, audits the request (`AgentApprovalRequested`, with the hash), and sends it to every approver.
2. It then parks it: the request, its hash and its deadline go into a table, and the agent's call waits on a oneshot channel outside the state lock, so a parked request holds no thread and no lock.
3. At most one request per credential is parked at a time (another gets an immediate refusal: an approval is already pending), and at most 16 in all.
4. A spend's budget is not reserved while it waits; it is reserved when the approved request is evaluated again.

**A decision arrives.** The gateway checks that:
- the seal and the approver are valid;
- the request id is parked and the hash matches;
- the gateway's own deadline has not passed.

Then, under the state lock:

1. It takes the parked entry out of the table, so a request is consumed once, by the first valid decision.
2. A deny ends it: the agent gets "denied by the approver".
3. An approve becomes an `Approval`, a value only the code that verified the signature can construct. The gateway checks the credential again (revoked, expired, frozen, the global freeze), then calls `evaluate_approved` with the `Approval`. That runs every hard check and budget again and reserves the spend. Then it signs exactly the parked object, audits the signature with the decision's signature, and answers the agent.
4. Decisions are handled in the order they arrive. A deny that arrives before the request is consumed wins over a later approve, and any decision for a consumed or unknown request is ignored and logged.

**The deadline** is the gateway's: 120 seconds from parking by default, settable from 30 to 120 (the bridge waits 150 seconds for an answer). When it passes, the request is denied as expired, audited, and announced with an `expired` outcome. A restart drops every parked request, and an agent waiting on one gets the bridge's "may have been carried out" answer, which here is safe: nothing was signed.

**Freezing cancels.** A freeze of a credential or of the gateway, from the admin socket or a phone, cancels every parked request it covers, each answered "canceled: frozen".

**Rejections freeze.** Three denials for one credential within 24 hours freeze it, and only an approved unfreeze clears that. Expiries do not count, since a phone may simply be offline.

**Audit entries.** New `AuditEventType` variants:
- `AgentApprovalRequested`: credential, op, reason, request hash.
- `AgentApprovalDecided`: approved, denied, expired or canceled, with the approver key and the decision signature when there is one.
- `AgentApproverAdded`, `AgentApproverRemoved`.

All of them go through the fail-closed agent audit path and count against the agent headroom.

**`evaluate_approved`** changes from a plain function to one that takes an `Approval` by value instead of a request. `Approval` has private fields and no public constructor outside the module that verifies decision signatures, and it carries the parked request the hash was computed over, so `evaluate_approved` evaluates exactly what was approved. A caller bug can neither skip an approval nor pair one with another request.

## Management changes

The admin socket keeps every operation it has. Those that give agents more power stop taking effect directly: the gateway creates a `management` request, sends it to the approvers, and applies the change when one approves, within the deadline. The admin command waits for the outcome and prints it.

| Change object (`payload.change`) | Effect when approved |
|---|---|
| `{"type": "issue_credential", "id", "name", "uid", "expires_at", "grant"}` | Issues the credential; the token goes to the admin as today |
| `{"type": "unfreeze", "scope": "all"}` or `{"type": "unfreeze", "scope": {"credential": id}}` | Clears the freeze, and the credential's audit budget |
| `{"type": "add_approver", "approver", "label", "fingerprint"}` | Registers the paired approver |
| `{"type": "remove_approver", "approver"}` | Removes it |

- The `grant` in `issue_credential` is the validated grant as JSON. The phone renders it field by field: keys, operations, kinds, NIP-44 peers, network, limits and budgets.
- `id` and `expires_at` are fixed by the gateway before asking, so the approved change is exactly what is applied.
- A credential's grant cannot be changed in place today; a new grant is a new credential, approved like any other.

## Audit anchoring

The phone keeps the last anchor it saw from the gateway and alerts (in the app, prominently) when a new one goes backwards. That catches a vault restored from an old backup and a truncated log, which nothing on the host can detect (M2).

- **`seq`, `head`:** each audit entry gets a sequence number, one more than the entry before, kept across retention. `head` is the last entry's hash, `seq` its number.
  - Retention stops re-chaining: it keeps the remaining entries' hashes and sequence numbers, and records the hash the first kept entry links to, so `keep audit verify` checks the kept chain from there.
  - The phone alerts when `seq` decreases, or when `seq` is unchanged but `head` differs.
  - The owner can check the full log against the anchors the phone saw.
- **`wallets`:** for each wallet ledger, its own sequence number (one more on every reservation, never decreasing, not even when a spend ages out or is released), the window's spent total and the wallet's window budget.
  - The phone alerts when a wallet's `seq` decreases, so a rolled-back ledger is caught even without the audit log (a requirement from the policy engine review).
  - `spent` gives the human context for spend approvals.

## The approver (keep-android)

- Requests are reviewed in the app, behind the device credential (biometric or PIN), never approved or denied from a notification action. A notification only says a request is waiting.
- Before showing a request, the app:
  - verifies the seal, the channel key and `request_hash`;
  - for a PSBT, recomputes every figure;
  - refuses one that does not check out, with a warning, and never offers it for approval.
- The app renders parsed, canonical fields:
  - **Nostr:** the kind's name and number, and the signing key.
  - **PSBT:** each output's address and amount, change marked as such, the fee, the total leaving the wallet, and the budget context.
  - **NIP-44:** the counterparty.
  - **Management changes:** each field of the change.
- Anything the agent wrote is shown apart, in a separate area clearly labeled as written by the agent:
  - the event's content and tags, and a NIP-44 plaintext;
  - escaped, truncated to 2,000 characters with the full length stated, with bidi and other control characters removed.
- **Countdown:** a request shows its deadline counting down from when it arrived, never more than `expires_at - created_at`, and cannot be approved once that or `expires_at` on the phone's clock has passed. The gateway's deadline is the one that counts; the phone's only keeps it from offering what the gateway will refuse.
- **Anchors:** the app keeps the last anchor and alerts when one goes backwards, whether it arrives in a request or on its own.
- **Freezing:** the app offers "freeze this agent" and "freeze everything" at all times. They send a freeze with the next counter, and need no device credential, so stopping an agent is never slower than letting it go.
- **Unfreezing:** an unfreeze, from the phone or approving an admin's request, needs the device credential.
- **NIP-44 decrypt:** approving one warns that the plaintext will reach the agent and its model provider.

## The agent

- A tool call that needs an approval waits for it, up to the deadline, and then gets the normal result or an error. The errors read:
  - "denied by the approver";
  - "no approval within 120 seconds";
  - "an approval for this credential is already pending";
  - "canceled: frozen".
- MCP clients must allow tool calls to take as long as the deadline plus a margin, about 130 seconds. Some clients default to 60 seconds; the docs will say how to raise it.
- `get_session_info` reports whether approvals are enabled and the deadline.

## Related decisions for keep-7oeou.4

- **Hard-denied kinds.** 24250 to 24255 are refused for agents under any grant, and `Grant::validated` refuses grants listing them (policy engine review, note 1).
- **Reserved keys.** `Grant::validated` takes the channel key and the registered approver keys and refuses grants naming them, and authentication refuses a stored grant naming one (note 1).
- **Inbound NIP-17** (note 2). A new operation, `nip17_unwrap`, takes a gift wrap addressed to a granted key, unwraps it with that key, and returns the rumor only if the seal's signer is in the grant's `nip44_peers`. It is never a general decrypt: the ephemeral wrap key is never treated as a counterparty. It is built after this protocol, as its own task.
- **Ledgers in the anchor** (note 3), as above.
- **`evaluate_approved` takes an `Approval`** (re-review note), as above.
- **Design correction** (re-review note). The design's budget section says windows use `max(now, last persisted timestamp)`, so a clock jump cannot reset them. That rule alone protects against a clock stepped backward only; a clock stepped forward across a restart would age every spend out. What the merged daemon does instead (`clock.rs`): the budget clock is never the wall clock. It is the start time plus `CLOCK_BOOTTIME`, persisted as a heartbeat; a restart in the same boot continues it by elapsed boot time, and after a reboot it resumes from the latest time the vault has seen, so downtime is never counted and no clock, however wrong, releases a spend early. The design's budget section should say that. This repository does not hold the design text, so the correction goes in the issue's design field.

## Threats and answers

| Threat | Answer |
|---|---|
| An agent approves its own request | It holds no approver key; the channel key is in no grant; the protocol's kinds are hard-denied; approver keys cannot be in a grant |
| A decision replayed, or used for another request | It signs a hash of the gateway, credential, random request id and exact payload; a parked request is consumed once; unknown or consumed ids are ignored |
| A relay changes or forges a message | Seals are signed by the real keys and contents are NIP-44 encrypted; anything that does not verify is dropped |
| A relay withholds a request or decision | The deadline passes and the request is denied |
| A relay learns who talks to whom | It sees recipients, sizes and randomized times; senders, kinds and contents are hidden by the gift wrap |
| The phone is misled by what the agent wrote | Fields are parsed and recomputed on the phone; agent strings are escaped, truncated and set apart |
| A captured freeze or unfreeze replayed | Per-approver monotonic counters |
| An agent floods the phone | One parked request per credential, 16 in all, the grant's request limits, and a freeze after three denials |
| A vault or ledger rolled back | Anchors carry monotonic sequence numbers the phone checks |
| Someone who saw the pairing QR pairs first | The fingerprint is confirmed on both screens before registration |
| A phone is lost | Root resets the approvers; until then, the lost phone can still approve, so reset promptly |
| A compromised relay helper | It handles only finished gift wraps, so it is no more than a hostile relay: it can delay or drop messages, and a delay denies |
| A flood of gift wraps to the channel key | At most 600 are opened per minute, outside the state lock; agents keep working, and a delayed decision denies |
| A remote attacker reaching the vault process | The gateway has no network; only the helper does, as another user without the vault |

## Test plan

- **Unit tests:**
  - every encoding and hash, with fixed test vectors added to this document when they are implemented;
  - signature checks;
  - the consumption rules (one decision, deny before consume wins, late decisions ignored).
- **Gateway tests:** an in-process approver over `MockRelay`, like the multinode tests. They exercise:
  - approve, deny, expiry, one request pending per credential and the cap of 16;
  - freeze canceling a parked request, and auto-freeze after three denials;
  - a decision signed by an unregistered key, and a decision for another request's hash;
  - a replayed decision and a replayed freeze, and a request too large to approve;
  - every management change, and the anchor going backwards.
- **Mutation checks** on every verification step.
- **The root e2e** runs the gateway and the relay helper as their own users, with an approver process and a local relay, and approves a kind 0 and a spend above a threshold end to end.
- **The systemd e2e** boots both units with the channel key as a second sealed credential, and checks that the gateway refuses to start without it once an approver is registered.
- **keep-android** gets the same vectors for its own tests.

## Decisions for the owner

These are the choices this draft makes where the design leaves room. Each is the recommendation unless the owner decides otherwise. Already decided and followed here: phone approvals only, and the channel key sealed like the vault password.

1. **How the gateway reaches relays.** A relay helper as its own user (recommended: the process holding the unlocked vault keeps `PrivateNetwork=yes`, and the TLS and websocket code runs elsewhere), or the gateway connects to relays itself, which needs one unit and user fewer but gives the vault's process a network stack and parsers that face the internet.
2. **Wrapping.** NIP-59 gift wraps (recommended: they hide the sender and kind from relays, and keep-frost-net already wraps duress beacons), or plain NIP-44 content with `p` tags as keep-frost-net's coordination messages use, which shows relays the gateway's and phone's keys talking.
3. **How many approvers must approve.** One (recommended for now: any deny still wins before consumption), or a quorum of m approvers, which this format could add later with a `quorum` field.
4. **A lost phone.** Root resets the approvers (recommended), or a second paired device is required before approvals can be turned on.
5. **Freeze after denials.** Three denials in 24 hours (recommended), or another number.
6. **How agents wait.** A tool call blocks until the decision or the deadline (recommended: stock MCP clients need nothing new), or it returns at once with a pending id and the agent polls a new `get_approval` tool, which suits clients with short timeouts but every agent must learn it.
7. **Deadline.** 120 seconds by default, settable from 30 to 120.
8. **Too large to approve.** Refuse requests whose rumor would exceed 24 KiB (recommended), or split them across several messages.
9. **Retention.** Change audit retention to keep hashes and sequence numbers instead of re-chaining (recommended, needed for anchors that survive retention), or keep re-chaining and have the phone accept a signed "retention happened" notice instead.
