# DKG Relay Transport — Ceremony Spec (v2.2)

Status: **signed off — implementing.** §3 identity model approved by kwsantiago
(host-key roster + per-group subkey required, plus C1/C2); Phase 1 (§11) is
cleared to start. Direction: instead of hardening a second, bespoke mobile DKG, we
**extract the DKG coordinator that already exists in `keep-cli` into
`keep-frost-net` and share it** between CLI and mobile.

This is the protocol the entire product rests on: a leaked invite must not be
catastrophic, and every honest device must agree on the same group key or all
abort. This version keeps v2's cryptographic conclusions, drops v2's from-scratch
reimplementation, and adds the ChillDKG properties the review surfaced.

Changelog v2.1 → v2.2 (post-sign-off):
- **§3 signed off:** host-key roster **keyed by a per-group device subkey
  (required, not optional)** — the plaintext kind-21101 announcement would
  otherwise publish an identity/threshold/relay-hint targeting map. `frost_group_id`
  hashes subkey npubs. Consequences **C1** (subkey retained in the same backup
  unit) and **C2** (roster relay-publication opt-in, skipped for mobile, via a
  pluggable `RosterSource`).
- **Phasing amendment:** the roster→subkey change folds into **Phase 1**, not
  later (cheaper before any group exists in the wild).
- Software-DKG UI copy: plain statement, not the CLI's recommend-hardware wording.

Changelog v2 → v2.1:
- **Extract & unify** (§0) — build on `keep_core::frost::dkg::SoftwareDkgSession`
  + the CLI coordinator, not a new mobile DKG.
- **Confirmation upgraded to CertEq** (§6) — Integrity *and* Conditional
  Agreement, with a retained transferable success certificate.
- **MAC dropped**, cancellation in scope, collector deferred (§9).
- Trust-anchor assumption stated explicitly (§2).

---

## 0. Direction: extract & unify

### 0.1 What already exists (verified)

`keep-cli/src/commands/frost_network/dkg.rs` (1729 lines) is a full software DKG
over Nostr relays, built and hardened across #675/#757/#817/#436/#689. It solves
the same problems PR #963's `dkg_net.rs` set out to, and does so correctly:

- **Signed roster** — a kind-21101 announcement pins `index → npub`
  (`fetch_group_roster:144`, `parse_roster_from_event:185`). Real published
  identities in an authenticated artifact — exactly the "identity is not derived
  from a shared secret" move.
- **Author binding on intake** — round 1 (kind 21102) and round 2 (kind 21103)
  both reject any event whose author ≠ the roster npub for the claimed
  `sender_index` (`DkgRoster::authenticates:53`).
- **Group-id hash binding** — `frost_group_id:116` =
  `sha256("frost-group-id-v1" ‖ name ‖ threshold ‖ participants ‖ ordered npubs)`,
  shared between the code that mints the id and the code that verifies a roster
  so they cannot drift; stops a relay writer republishing a rogue kind-21101
  under the same `d` tag.
- **Round-2 confidentiality is already Blocker-1-safe** — kind-21103 shares are
  NIP-44-encrypted *per recipient* to the recipient's roster pubkey (`:655-662`),
  whose private half is that participant's own nsec, never a shared secret. Only
  the addressed recipient can decrypt. **This is the property v2 was rebuilding.**
- **Equivocation confirmation round** — kind-21107, decision extracted as a pure
  function (`accept_group_key_confirmation:92`, #817).
- **Bounded polling** — per-run distinct-event cap (`MAX_DKG_EVENTS_SEEN:18`);
  a flood means a misbehaving relay, so abort rather than grow memory.
- **Tested failure modes** — peer drop, duplicate, self-echo (#436, #689).

Those are the exact bug classes both reviews found in `dkg_net.rs`. The mobile
module reintroduced them because it started from a blank file rather than this
one. **keep-mobile's `dkg.rs` `DkgSession` + `dkg_net.rs` is a second
implementation of `keep_core::SoftwareDkgSession` + this coordinator.**

### 0.2 The seam (verified)

- `SoftwareDkgSession` lives in `keep_core::frost::dkg`
  (`init/round1/round1_peer/round2/finalize`); keep-mobile already depends on
  `keep-core` and `keep-frost-net`. The crypto layer is shared today.
- The coordinator has **zero** `println!`/`stdin`/`dialoguer`; every report goes
  through `out: &Output` (`keep-cli/src/output.rs`). Swap `Output` for a progress
  sink trait and `DkgProgressUpdate` drops straight in.
- The equivocation decision is already a pure function.

### 0.3 The plan

Move roster fetch/parse/verify, `frost_group_id`, and the round coordination out
of `keep-cli` into `keep-frost-net`, parameterized over a **progress-sink trait**
instead of `Output`. `keep-cli` keeps a thin `Output` adapter; keep-mobile's
`dkg_net.rs` becomes a thin adapter emitting `DkgProgressUpdate`; keep-mobile's
bespoke `dkg.rs` DkgSession is deleted. **One DKG to audit, not two.**

PR #963 (`feat/dkg-relay-transport`) is **repurposed** into this extraction work;
the v1 transport is not merged.

---

## 1. Background — why the mobile v1 was unsafe (retained)

v1 derived **every** participant's NIP-44 identity from a single shared
`session_secret` (`derive_dkg_keys(secret, index)`):

- **Blocker 1 (share disclosure).** Round-2 packages carry the secret evaluation
  `f_i(ℓ)` (`frost-core-3.0.0/src/keys/dkg.rs:507-534`). NIP-44's conversation
  key is ECDH, derivable from either side. Any `session_secret` holder could
  derive every participant's private key and decrypt every round-2 package; with
  `n-1 ≥ t` (i.e. `n > t`, so 2-of-3) the polynomial interpolates and the group
  secret is recovered passively — by a participant or a QR photographer.
- **Blocker 2 (equivocation).** FROST's round-1 PoK binds no session context
  (`challenge()`, `dkg.rs:401-418`), so identity/round binding must come from the
  transport; v1 had no transcript agreement before persist.

**Root cause:** a symmetric secret asked to do an asymmetric-identity job. The CLI
never had these bugs because identity is a signed roster of real host keys and
round-2 is encrypted to those keys. Adopting it resolves Blocker 1 structurally;
Blocker 2 is resolved by the confirmation round, upgraded per §6.

---

## 2. Threat model / goals

| # | Property | Mechanism |
|---|----------|-----------|
| G1 | A leaked invite cannot recover the group key or any share | Round-2 NIP-44-encrypted to each participant's own roster key; private halves never shared/derived |
| G2 | A leaked invite cannot let a stranger participate | Signed roster + author-binding gate; only holders of a rostered private key can speak for an index |
| G3 | No single device ever holds the whole key | `SoftwareDkgSession` (FROST part1/2/3); coordinator never centralizes material |
| G4 | All honest devices agree on the group key **or all abort, recoverably** | CertEq confirmation over the §5 transcript with a retained success certificate (§6) |
| G5 | A malicious relay cannot break session/round binding or downgrade transport | Group-id hash-binding, author gate, local re-checks, cert pinning, proxy, non-default `RelayOptions`, `authors` filters, bounded polling |
| G6 | Liveness for late/reconnecting devices | Long-lived `subscribe` + notifications; periodic re-publish; CertEq lets a timed-out peer be re-convinced later |

**Trust anchor (stated explicitly, per ChillDKG).** Every protocol here assumes
participants hold **authentic** copies of each other's host pubkeys — the signed
roster — established out of band. Group-id hash-binding is fail-closed against a
*doctored* roster, but **no protocol can prevent a uniform MITM of the initial
roster exchange**; that authenticity is an assumption, not something the ceremony
provides. This is the same assumption every DKG makes.

Non-goals: hiding a run's existence from a relay; defending against a threshold
of colluding rostered participants (outside FROST's model).

---

## 3. Identity model — SIGNED OFF

**Decision (kwsantiago): signed host-key roster, keyed by a per-group device
subkey — never the user's identity npub.** The roster structure gives the stable
identity CertEq/recovery need (§6) and is already hardened; the subkey is a
**requirement of that design, not an optional privacy add-on**.

The invite *is* the signed roster: per-participant **pubkeys**, each a device's
**stable-per-group subkey**. ChillDKG cites a joint-security result licensing one
keypair for both the event Schnorr signature and the ECDH KEM, so one subkey does
both jobs. It stays stable within the group (so a stuck party is re-convinced
against it), rostered, and retained — recovery intact — while never being the
user's long-term identity.

**Why the subkey is mandatory, not cosmetic.** A kind-21101 announcement is
published to public relays *in the clear* — `cmd_frost_network_group_create`
p-tags carry `[npub, relay_hint, index]`, plus explicit `threshold`/`participants`
tags and a human-readable content string, authored by the coordinator's npub. If
those p-tags were identity npubs, every group would permanently publish a
**targeting map**: who co-holds the key, how many are needed, and where each
connects. Our own threat model prescribes geographic/custodial share separation
against coercion — which only helps while an attacker cannot enumerate the holders.
Subkeys mean `frost_group_id` hashes **subkey** npubs, so the group id stops
leaking identity too.

**Two consequences (build in now):**

- **C1 — retain the subkey with the share, in the same backup unit.** The subkey
  is needed to restore and *use* this device's share — it signs this party's
  per-group events — so a backup that restores the share but not the subkey leaves
  a party unable to participate. Certificate verification does **not** use it:
  `DkgCertificate::verify` checks only the roster and the signed transcript
  confirmations. If a recovering party must prove it holds the subkey, that is a
  separate proof-of-possession step, not part of certificate membership. Same
  encrypted backup, same restore path.
- **C2 — roster relay-publication becomes opt-in, and is skipped for mobile.**
  The mobile invite already carries the full pubkey list, and `frost_group_id`
  hash-binds it, so the roster is a local artifact; publishing it adds nothing and
  creates the public record above. The CLI keeps a relay path *only* behind a
  deliberate flag for its discovery case, and it must never carry identity npubs
  regardless. This makes the **roster source pluggable** (invite-supplied vs
  relay-fetched) behind one verification path — a `RosterSource` alongside
  `DkgProgress`/`DkgTransport` (§4).

---

## 4. Shared coordinator (extraction target)

New in `keep-frost-net` (e.g. `dkg_coordinator.rs`):

```rust
/// Progress sink — the seam replacing keep-cli's `Output`. keep-cli adapts it to
/// its spinner/field UI; keep-mobile adapts it to `DkgProgressUpdate` over FFI.
trait DkgProgress {
    fn phase(&self, p: DkgPhase);            // Connecting, RosterVerified,
                                             // Round1{recv,total}, Round2{…},
                                             // Confirming{…}, Complete, Failed{…}
}

/// Where the verified roster comes from — invite-supplied (mobile) or
/// relay-fetched (CLI discovery, opt-in). Both funnel through the SAME
/// verification (`parse_roster_from_event`/hash-bind), so there is one audited
/// authentication path regardless of source. Pins per-group SUBKEYS (§3).
trait RosterSource {
    async fn load(&self, group_id_hex: &str) -> Result<DkgRoster>;
}

/// One relay-driven software DKG run. Transport-injected so it is unit-testable
/// without a live relay (fake transport for CI).
async fn run_software_dkg(
    session: &mut SoftwareDkgSession,   // keep_core::frost::dkg
    transport: &dyn DkgTransport,       // subscribe/publish/fetch abstraction
    keys: &Keys,                        // this device's per-group subkey
    roster: &DkgRoster,                 // verified roster (invite- or relay-sourced)
    group: &str,                        // group id hex, used as the relay `d` tag
    our_index: u16,                     // participant index, checked against roster
    timeout: Duration,
    cancel: &AtomicBool,                // §9, polled between rounds
    progress: &dyn DkgProgress,
) -> Result<DkgOutcome>;                // share export + success certificate
```

Moved out of keep-cli: `DkgRoster`, `fetch_group_roster`/`parse_roster_from_event`
(behind `RosterSource`), `frost_group_id`, `accept_group_key_confirmation`, the
round-1/2/confirm loops, `MAX_DKG_EVENTS_SEEN`. Event kinds stay
**21101/21102/21103/21107** so CLI and mobile interop on the wire. Per §3+phasing,
Phase 1 also swaps what the roster/`frost_group_id` pin from identity npubs to
per-group subkeys — a deliberate one-time format change made while the code is
already moving, before any group exists in the wild.

---

## 5. Transcript — what v2 contributes and must survive

The CLI confirmation compares **only the group key**
(`accept_group_key_confirmation:98`, `theirs.trim() != ours`). That misses
equivocation where two victims derive the *same* group key from *different*
round-1 sets. v2's transcript is strictly stronger and replaces the group-key
string as the confirmed value:

```text
transcript = SHA256(
  "keep-frost-dkg-transcript-v1"
  ‖ frost_group_id                                   (32)   // name,thr,parts,roster
  ‖ threshold_be (2) ‖ participants_be (2)
  ‖ for j in 1..=n:  index_be(2) ‖ pk_j (32)                // roster, ordered
  ‖ for j in 1..=n:  SHA256(round1_pkg_bytes_j)             // commitment per round-1 pkg
  ‖ group_pubkey                                     (32)
)
```

Round-2 bytes are excluded (secret, per-recipient). Including the round-1 package
commitments is what defeats same-key equivocation. Binding `frost_group_id`
folds in the whole authenticated roster.

**Optional private channel (`session_secret`'s only surviving job, if kept).**
The CLI uses the plaintext group name as the `d` tag (enumerable). Mobile may
derive a private channel id `d = SHA256("keep-frost-dkg-channel-v1" ‖
session_secret ‖ frost_group_id)` so a run is not on a guessable channel. This is
**privacy only** — the roster already provides identity and integrity — so it is
optional and does not gate the design. The **MAC is dropped** (the author gate +
`authors` filter already reject non-members before ECDH).

---

## 6. Confirmation = CertEq (Integrity **and** Conditional Agreement)

The gap (ChillDKG, `../bip-frost-dkg`): the current confirmation
(`while confirmed < expected` + timeout + abort — CLI `:1242`, v2 R3) gives
**Integrity** (success ⇒ all honest inputs equal) but not **Conditional
Agreement** (success for one honest party ⇒ eventually success for all). Over
ephemeral relay events, partial delivery is the expected case: device A collects
all `n` and persists; device B drops one confirmation, times out, aborts — and A
now believes it is in a live group B never joined.

**Fix — retain a transferable success certificate (CertEq):**

1. Each device signs the §5 `transcript` with its roster key and broadcasts it
   (kind 21107, the existing confirmation kind).
2. **Success = collecting all `n` signatures over the identical transcript into a
   certificate**, not merely observing agreement and moving on.
3. The certificate is **retained** and is **transferable**: a device that
   finalized can later present it to a peer that timed out (e.g. attached to the
   first signing request) and convince it to finalize, because each signature
   verifies against the peer's rostered pubkey. "The certificate does not need to
   be sent during a normal run … but can instead be presented to other
   participants later."
4. **Recovering stuck parties / persist ordering (fixes persist-after-Complete):**
   a device must not present the group npub as *ready to use* until it holds a
   complete certificate. Persist the share, but surface "pending confirmation"
   until the certificate is complete or later supplied; never fire
   `DkgProgressUpdate::Complete` before the certificate is in hand.

This is a bounded change made **once** in the shared coordinator; both callers
benefit. Making it twice is how the implementations drift — which is what
produced this situation.

---

## 7. Transport hardening (mobile path — retained from v2 §9)

The mobile client needs these regardless of extraction; the CLI's simpler relay
handling is acceptable for a desktop but not for a phone that may be on Tor:

- **Reception:** long-lived `subscribe` + `notifications()` (signing path,
  `node/mod.rs:2202+`), not an `ExitOnEOSE` `fetch_events` poll loop (which spins
  on ephemeral kinds and starves late joiners). Re-publish with fresh timestamps
  for late peers; collect to the round condition, then tear down.
- **Filters:** `#d` + `#t`/kind + `authors(roster pubkeys)` + `limit`; scopes off
  the shared kind firehose and satisfies strict relays.
- **Local re-checks:** re-verify `#d`, round/kind, `#p`, `created_at`, and
  author-in-roster locally — never trust the relay for binding (G5).
- **Relay hardening:** build the client through `verify_and_pin_relays`
  (`lib.rs:2934`) + the configured SOCKS proxy, `RelayOptions` matching
  `default_relay_opts()` (reconnect/ping/`ban_relay_on_mismatch`/bounded latency).
- **Cleanup:** disconnect guard on **every** exit path (no `Drop` on
  `Client`/`RelayPool`/`Relay`).
- **Author check before `nip44::decrypt`** on round-2 intake (no ECDH per spam
  event).

The shared coordinator takes these via the `DkgTransport` abstraction (§4); the
CLI keeps its current transport, mobile supplies the hardened one.

---

## 8. Mobile FFI & concurrency/persistence

- **FFI split — option B (agreed).** `frost_dkg_begin() -> pubkey_hex` derives/loads
  this device's rostered identity and returns its pubkey for roster assembly;
  `frost_run_dkg(config, …)` runs the shared coordinator. The identity secret
  **never crosses the Kotlin boundary**. Two-call collection UX confirmed
  acceptable.
- `DkgConfig` (`types.rs`): carry the roster (`Vec<DkgParticipant{index,pubkey}>`);
  `session_secret: Vec<u8>` only if the optional private channel (§5) is kept
  (else drop it); **remove `#[derive(Debug)]`**, hand-write a redacting `Debug`
  (mirrors `node/mod.rs:671`) — fixes the UniFFI-`toString()` leak.
- **Persist ordering:** per §6, do not signal `Complete` before the certificate;
  keep `share_export` recoverable on a storage failure. Pre-flight
  `validate_share_name` + `MAX_STORED_SHARES` (already landed) stays.
- **Concurrency:** scope error-path `reset()` to the failing session (no wiping a
  concurrent run); fix the read-then-write-lock TOCTOU in session start (single
  guard).

---

## 9. Resolved decisions & deferrals

- **FFI split:** option B (sk in Rust). ✅
- **MAC:** dropped — author gate + `authors` filter already reject non-members
  pre-ECDH; `session_secret` survives only as the optional private channel id. ✅
- **Cancellation:** in scope — `CancellationToken` through the coordinator; the UI
  gets a clean cancel instead of `frost_dkg_reset` corrupting a live session. ✅
- **Collector variant:** deferred; the §5 transcript binds the full roster, so a
  malicious collector swapping an entry makes every honest transcript diverge →
  CertEq fails. ✅ (door stays open)
- **Identity model (§3):** signed host-key roster + **per-group subkey (required)**;
  `frost_group_id` hashes subkey npubs. ✅ **signed off**
- **Subkey retained in the backup unit (C1)** and **roster relay-publication
  opt-in / skipped for mobile (C2), via `RosterSource`.** ✅ signed off

---

## 10. Product thread (surface separately)

On a phone there is no `--hardware` option, so on-device DKG **is** software DKG.
The CLI warns software DKG "keeps polynomial state in this process's memory for
the duration of the run" and steers production keysets to hardware
(`dkg.rs:851-855`). A Keystore-backed phone is a reasonable share holder, so this
likely does not block the feature. Direction (kwsantiago): the mobile UI should
**not** inherit the CLI's wording — that warning is aimed at someone choosing
between software and `--hardware`, and a phone has no such choice, so a
recommendation reads as noise. Prefer a plain statement at group-creation time of
what the device holds during the ceremony. Draft the copy once the ceremony is
settled. Its own thread, not a code blocker.

---

## 11. Implementation phasing

1. **Extract + the roster/subkey change.** Move `DkgRoster`, roster
   fetch/parse/verify (behind `RosterSource`), `frost_group_id`, round
   coordination, `MAX_DKG_EVENTS_SEEN` into `keep-frost-net` behind `DkgProgress`
   + `DkgTransport`. keep-cli becomes an adapter; its tests (#757/#817/#436/#689)
   stay green. **Fold in §3 now** (kwsantiago's amendment): swap what the roster
   and `frost_group_id` pin from identity npubs to per-group subkeys, add C1
   (subkey in the backup unit) and C2 (`RosterSource`, opt-in relay publication) —
   cheaper as a one-time format change now than migrating a shipped roster later,
   and nothing has shipped that uses it yet. Update the #757/#817 roster tests to
   the subkey format (the only intended behavior change in this phase).
2. **Transcript upgrade** (§5) in the shared coordinator — confirmed value becomes
   the transcript hash, not the group-key string. Both callers benefit.
3. **CertEq** (§6) — retained transferable certificate + persist-ordering /
   recovery rule. Once, shared.
4. **Mobile adapter** — `dkg_net.rs` → transport wiring + §7 hardening;
   `DkgProgressUpdate`; FFI split (§8); cancellation; delete keep-mobile's bespoke
   `DkgSession`. Redacting `Debug`; concurrency/persist fixes.
5. **Tests** — extend the in-memory pipeline: (a) a non-recipient cannot decrypt a
   round-2 share, (b) an equivocating insider (same key, divergent round-1) trips
   the transcript, (c) a non-roster author is rejected before decrypt, (d) a peer
   that missed the live confirmation finalizes from a presented certificate
   (Conditional Agreement). Fake `DkgTransport` for CI. Generate vectors against
   the ChillDKG reference where shapes align.

Each phase builds + `cargo test` (keep-cli, keep-frost-net, keep-mobile) green
before the next.

---

## 12. Review-item → section map

| Review item | Resolved in |
|---|---|
| Blocker 1 (shares readable by all) | §0.1, §1, §2 G1 (per-recipient encryption to roster keys) |
| Blocker 2 (equivocation) | §5 transcript, §6 CertEq |
| Integrity without Conditional Agreement | §6 |
| Ephemeral vs host keys / recovery | §3 |
| Trust-anchor assumption | §2 |
| Two implementations that drift | §0 extract & unify |
| EOSE spin / late-joiner starvation | §7 reception |
| Relay pinning + proxy + RelayOptions + local re-checks | §7, §2 G5 |
| `session_secret` Debug leak | §8 |
| decrypt-before-author-check | §7 |
| persist-after-Complete loss | §6, §8 |
| unconditional reset / start TOCTOU | §8 |
| websocket leak on early return | §7 cleanup |
| filters lacking authors/limit; bounded polling | §7, §0.1 |
| `DKG_EVENT_KIND` duplication | resolved by reusing CLI kinds 21101–21107 |
| no cancellation handle | §8, §9 |
| MAC | dropped, §5/§9 |
| software-DKG-on-mobile warning | §10 |
