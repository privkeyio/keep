# DKG Relay Transport — Ceremony Spec (v2)

Status: **draft for sign-off** (supersedes the `session_secret`-derived-identity
design in PR #963). Nothing merges until this is agreed.

This is the protocol the entire product rests on: a leaked invite must not be
catastrophic. The v1 transport failed that bar (see Background). This spec fixes
the two blockers and folds in the transport/liveness/hardening items from review.

---

## 1. Background — why v1 is unsafe

v1 derived **every** participant's NIP-44 identity from a single shared
`session_secret` (`derive_dkg_keys(secret, index)`). Two consequences:

- **Blocker 1 (share disclosure).** Round-2 packages carry the secret polynomial
  evaluation `f_i(ℓ)` (verified: `frost-core-3.0.0/src/keys/dkg.rs:507-534`).
  NIP-44's conversation key is ECDH, derivable from *either* side's private key.
  Because any `session_secret` holder can derive *every* participant's private
  key, they can decrypt *every* round-2 package, not just their own. A degree
  `t-1` polynomial is fixed by `t` points; one observer sees `n-1` of them, so
  whenever `n > t` the polynomial interpolates, `f_i(0)` falls out for every `i`,
  and the group secret `Σ f_i(0)` is recovered **passively** — by any
  participant, or by anyone who photographs the invite QR. 2-of-3 (`t=2, n=3`)
  is exactly this case.
- **Blocker 2 (equivocation).** The FROST round-1 PoK challenge binds no session
  context (`challenge()` hashes only `identifier ‖ verifying_key ‖ R`, verified
  at `dkg.rs:401-418`). With v1 authentication a malicious insider can present
  different round-1 polynomials to different victims; each finalizes a *different*
  group key and persists a share for a group the attacker chose.

**Root cause:** a shared *symmetric* secret was asked to provide *asymmetric*
identity. The signing path (`keep-frost-net`) derives transport identities from
`(group_pubkey, identifier)` — fine there, because the group key already exists
and is public and signing traffic is not the secret share — but there is no group
key yet during DKG, and the round-2 payload *is* the secret. Derivation cannot
carry over.

**Decision (kwsantiago):** carry **per-participant public keys in the invite**.
`session_secret` is retained only for channel derivation and as an optional
pre-ECDH MAC — never as participant identity. The round-0-announcement variant
was rejected: a MAC under `session_secret` proves "holds the invite", not
"is participant j", so a QR photographer could claim a slot (setup DoS, or
first-wins makes a stranger a real shareholder).

---

## 2. Threat model / goals

| # | Property | Mechanism |
|---|----------|-----------|
| G1 | A leaked invite (session_secret + all pubkeys) cannot recover the group key or any share | Round-2 encrypted to **self-generated** keys whose private half is never in the invite |
| G2 | A leaked invite cannot let a stranger *participate* | Only holders of an invited private key can produce authenticating events |
| G3 | No single device ever holds the whole key | FROST DKG unchanged; transport never centralizes material |
| G4 | All honest devices agree on the same group key or all abort | Confirmation round over a transcript that binds membership + round-1 commitments + group key, before any persist |
| G5 | A malicious relay cannot break session/round binding or downgrade transport | Local re-checks of `d`/`t`/`#p`/`created_at`, relay cert pinning, proxy, non-default `RelayOptions`, `authors`-scoped filters |
| G6 | Progress/liveness for late-joining devices | Long-lived `subscribe` + notification stream; periodic re-publish with fresh timestamps |

Non-goal: hiding the *existence* of a run from a relay (it sees an opaque channel
tag and `n` opaque pubkeys). Non-goal: protecting against a threshold of
colluding *invited* participants (that is outside FROST's model).

---

## 3. Ceremony overview

```
Setup (out of band, per device)     Transport (over relays, all n online)
─────────────────────────────       ─────────────────────────────────────
 P0  each device generates a          R1  broadcast round-1 package,
     fresh ephemeral keypair;             collect the other n-1
     shows its PUBLIC key           →  R2  send round-2 package f_i(ℓ),
 P0' pubkeys + session_secret +           NIP-44-encrypted per recipient;
     threshold/relays assembled            collect the n-1 addressed to us
     into the INVITE, delivered        R3  broadcast H(transcript); abort
     to every device (QR/scan)             unless all n agree
                                       R4  persist share (only after R3)
```

`P0`/`P0'` are the collection step. It replaces "one QR carries a shared secret"
with "each device contributes a pubkey, and the assembled set is the invite."
DKG already requires all `n` devices online and interacting through both rounds,
so this adds a collection step, not a new kind of ceremony.

---

## 4. Data structures

### 4.1 Invite (assembled at P0', delivered confidentially)

```
Invite {
  group_name:    String,
  threshold:     u16,
  participants:  u16,               // = n = participants_pubkeys.len()
  relays:        Vec<String>,
  session_secret:[u8; 32],          // channel + optional MAC ONLY
  participants_pubkeys: Vec<DkgParticipant>,  // ordered by index 1..=n, unique
}
DkgParticipant { index: u16, pubkey: [u8; 32] }   // x-only secp256k1 (nostr)
```

The invite is confidential (QR at setup). It is **not** secret in the
cryptographic sense any more: leaking it costs G2 nothing beyond what an outsider
already cannot do, and costs G1 nothing (private keys are not in it).

### 4.2 `DkgConfig` (FFI, `types.rs`) — changes

- `session_secret: String` → `session_secret: Vec<u8>` (wipeable, matches
  `import_nsec`; 32 bytes enforced).
- add `participants_pubkeys: Vec<DkgParticipant>` (new `uniffi::Record`).
- **remove** `#[derive(Debug)]`; hand-write a redacting `Debug` (session_secret
  and any per-device secret elided), mirroring `node/mod.rs:671`. Fixes the
  UniFFI-`toString()` leak.
- `our_index` stays (position of this device in the agreed list).

### 4.3 Wire types (`dkg_net.rs`)

```
DkgWire { i: u16, pkg: String }         // unchanged shape; round-1 plaintext,
                                        // round-2 NIP-44-encrypted body
ConfirmWire { t: [u8; 32] }             // R3: this device's transcript hash
```

---

## 5. Key material & identity

- Each device generates a **fresh per-run** ephemeral keypair `(sk_j, pk_j)` at
  `P0`. `sk_j` **never** leaves the device and is **never** derived from
  `session_secret`.
- `pk_j` is published at `P0` and lands in the invite at index `j`.
- **Identity check** (replaces `authenticated_index`'s derived comparison):
  an event claiming index `c` is authenticated iff
  `c != our_index && 1 ≤ c ≤ n && event.pubkey == participants_pubkeys[c].pubkey`.
  The nostr Schnorr signature already binds `event.pubkey`; this ties it to the
  invited identity. This is the load-bearing gate for G2.

**FFI split (secret handling).** Because `sk_j` is created at `P0` but used at
`R2`, `frost_run_dkg` can no longer be a single call. Proposed (recommended
option B — keep `sk_j` in Rust):

```
frost_dkg_begin() -> String            // generates (sk_j,pk_j), stores sk_j in
                                        // DkgSession state, returns pk_j hex
frost_run_dkg(config, name, pass, …)   // pulls sk_j from session state
```

Alternative option A (return `sk_j` to Kotlin as wipeable `Vec<u8>`, pass back
into `run_dkg`) mirrors `import_nsec` but widens the secret's exposure to the
Kotlin boundary. **Recommend B.** Open question flagged in §10.

---

## 6. Channel & MAC derivation (`session_secret`'s only jobs)

Let `pset = concat(sorted_by_index[ index_be(2) ‖ pk (32) ])`.

- **Channel** (public `d` tag):
  `channel = SHA256("keep-frost-dkg-channel-v2" ‖ session_secret ‖ pset)`.
  Binding `pset` means a tampered membership yields a *different* channel: a
  victim handed a doctored invite lands on a channel the honest devices never
  use, sees no peers, and **times out (fail-closed)** rather than being tricked.
- **MAC key** (optional, see §10): `mac_key = SHA256("keep-frost-dkg-mac-v2" ‖
  session_secret)`; each event carries `HMAC-SHA256(mac_key, id_bytes)` in a tag,
  checked before any NIP-44 decrypt.

`session_secret` is zeroized from any retained `DkgConfig`/state after these
derivations (extends the fix already landed in `dkg.rs`).

---

## 7. Rounds

### R1 — round-1 broadcast
- Publish `DkgWire{i, pkg}` (plaintext; round-1 packages are public) to `channel`
  with `t=dkg1`, signed by `sk_our`, fresh tweaked `created_at`, re-published
  periodically until R1 completes for **everyone** (see §8 liveness).
- Collect from the other `n-1` indices via subscription; decode requires the
  §5 identity check. First-wins per index; a second distinct package from an
  index is dropped (equivocation is caught structurally at R3).

### R2 — round-2 per-recipient
- For each recipient `ℓ`, `content = DkgWire{i, pkg=f_i(ℓ)}`, NIP-44-encrypted
  `nip44::encrypt(sk_our, pk_ℓ, …)`. Only the holder of `sk_ℓ` can derive the
  ECDH conversation key. **This closes Blocker 1.**
- Tag `#p = pk_ℓ`, `t=dkg2`. Collect the `n-1` addressed to us.
- **Author check before decrypt:** verify `event.pubkey ∈ invite pubkeys` (and
  the §6 MAC if enabled) *before* `nip44::decrypt`, so a spammer cannot force an
  ECDH per event (fixes the decrypt-before-auth item).

### R3 — confirmation (Blocker 2)
- After `part3` yields `group_pubkey`, compute the transcript (§8) and broadcast
  `ConfirmWire{t=transcript}` (`t=dkgc`), signed by `sk_our`.
- Collect all `n` confirmations (ours + `n-1`). **Abort** unless every
  authenticated confirmation equals our transcript, within the round timeout.
- Only on unanimous agreement proceed to R4. Any mismatch/missing → `Failed`,
  nothing persisted.

### R4 — persist
- Persist the share (see §9 for the persist-after-`Complete` fix).

---

## 8. Transcript definition

```
transcript = SHA256(
  "keep-frost-dkg-transcript-v2"
  ‖ channel                                  (32)
  ‖ threshold_be (2) ‖ participants_be (2)
  ‖ for j in 1..=n:  index_be(2) ‖ pk_j (32)          // membership, ordered
  ‖ for j in 1..=n:  SHA256(round1_pkg_bytes_j)       // commitment per round-1 pkg
  ‖ group_pubkey                              (32)
)
```

Round-2 bytes are **not** in the transcript (secret, and per-recipient).
Including the round-1 packages is what defeats equivocation: a malicious insider
who broadcast package `A` to one victim and `B` to another produces different
`SHA256(round1_pkg)` entries, so the victims' transcripts diverge and R3 aborts.
Membership + `group_pubkey` binding covers the divergent-key attack.

---

## 9. Transport layer

- **Reception:** replace the `fetch_events`/`ExitOnEOSE` poll loop with a
  long-lived `client.subscribe(filter)` + `client.notifications()` stream (the
  signing path, `node/mod.rs:2202+`). Fixes the EOSE spin **and** the
  late-joiner starvation (v1 stopped re-publishing as soon as *we* were done).
  Keep periodic re-publish with fresh timestamps for peers that connect late;
  keep collecting until the round's completion condition, then tear down.
- **Filters:** `kind:24242` + `#d=channel` + `#t=round` (+ `#p` for R2) +
  `.authors(invite_pubkeys)` + a `limit`. `authors` satisfies strict relays and
  scopes us off the shared-kind firehose (kind 24242 is shared with Blossom and
  signing).
- **Local re-checks:** on every received event re-verify `#d`, `#t`, `#p`,
  `created_at` window and author-in-set locally — never trust the relay's
  filtering for session/round binding (G5).
- **Relay hardening:** build the DKG client through `verify_and_pin_relays`
  (`lib.rs:2934`) and the configured SOCKS proxy, with `RelayOptions` matching
  `default_relay_opts()` (`reconnect`, `ping`, `ban_relay_on_mismatch`,
  bounded latency), not `RelayOptions::default()`. A Tor user must not get
  clearnet for DKG.
- **Cleanup:** wrap the client in a guard that `disconnect()`s on **every** exit
  path (success, error, timeout, cancel) — `Client`/`RelayPool`/`Relay` have no
  `Drop`, so v1 leaked a reconnecting socket on early return.
- **Kind:** reuse the exported `keep_frost_net::KFP_EVENT_KIND` instead of a
  private `DKG_EVENT_KIND` duplicate.

---

## 10. Open questions (need a call before/while implementing)

1. **FFI split — option B (sk in Rust) vs A (sk to Kotlin).** Recommend B.
   Confirm the collection UX can call `frost_dkg_begin` then `frost_run_dkg`.
2. **Is the §6 MAC load-bearing?** The §5 author-in-invite check + `authors`
   filter already reject non-members *before* ECDH, which is the "cheap garbage
   drop" goal. The MAC adds protection only against a relay that ignores our
   `authors` filter, and even then the author-set lookup is cheaper than an
   HMAC. Proposal: keep `session_secret` for **channel** derivation (clear value
   — run isolation + membership fail-closed), make the MAC optional and decide
   by measurement. Want it in v2 regardless?
3. **Cancellation.** `frost_run_dkg` blocks with no cancel handle; the only lever
   is `frost_dkg_reset`, which corrupts a live session. Add a cancellation token
   / abort handle so the UI can cancel cleanly. In scope for v2?
4. **Collector variant (future).** One device assembles + re-emits the pubkey
   list to cut n-way scanning. Safe **iff** the assembled list is bound into the
   transcript (§8 already does — `pset` is fixed input), so a malicious collector
   swapping an entry makes every honest device's transcript diverge → R3 abort.
   Defer to a follow-up; note it here so §8 stays compatible.

---

## 11. Concurrency & persistence fixes (fold into v2)

- `frost_run_dkg`: pre-flight `validate_share_name` + `MAX_STORED_SHARES`
  (already landed) **and** close the persist-after-`Complete` window — do not
  fire `DkgProgressUpdate::Complete` until the share is stored; on a storage
  failure after a completed run, surface a retryable error that keeps the
  `share_export` recoverable (peers hold a live group).
- Do **not** unconditionally `session.reset()` in the generic error arm — a
  second concurrent run must not wipe the first. Scope reset to the session that
  failed.
- `DkgSession::start`: take the write lock once (or use a state machine guard) —
  v1 drops the read lock before acquiring the write lock, so two calls can both
  observe `NotStarted` (TOCTOU).

---

## 12. Review-item → section map

| Review item | Resolved in |
|---|---|
| Blocker 1 (shares readable by all) | §5, §7 R2, G1 |
| Blocker 2 (no transcript / equivocation) | §7 R3, §8, G4 |
| EOSE spin / late-joiner starvation | §9 reception |
| Relay pinning + proxy + RelayOptions + local re-checks | §9 hardening/re-checks, G5 |
| `session_secret` Debug leak | §4.2 |
| decrypt-before-author-check | §7 R2 author check |
| persist-after-Complete loss | §11 |
| unconditional reset / start TOCTOU | §11 |
| websocket leak on early return | §9 cleanup |
| discarded publish errors | §9 (surface + retry) |
| filters lacking authors/limit | §9 filters |
| `DKG_EVENT_KIND` duplicates `KFP_EVENT_KIND` | §9 kind |
| no cancellation handle | §10.3 |

---

## 13. Implementation phasing

1. Types + FFI split (`types.rs`, `lib.rs`, `dkg.rs` session state for `sk_j`);
   redacting `Debug`; `session_secret → Vec<u8>`.
2. Identity from invite (`derive_dkg_keys` removed for identity; §5 check);
   round-2 encrypt to invited pubkeys; author-check-before-decrypt.
3. Transport rewrite: subscribe/notifications, filters, local re-checks, relay
   hardening, disconnect guard, reuse `KFP_EVENT_KIND`.
4. Transcript + R3 confirmation round.
5. Concurrency/persistence fixes (§11); cancellation (§10.3) if in scope.
6. Tests: extend the in-memory `full_2of3` pipeline to (a) prove a
   `session_secret`-only holder cannot decrypt a round-2 package, (b) prove an
   equivocating insider trips R3, (c) prove a non-member author is rejected
   before decrypt. Add a fake-transport seam so `collect`/subscribe liveness is
   unit-testable without a live relay.

Each phase builds + `cargo test -p keep-mobile` green before the next.
