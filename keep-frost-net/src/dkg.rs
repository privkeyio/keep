// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Shared DKG coordination primitives, extracted from `keep-cli` so the CLI and
//! keep-mobile drive one audited implementation instead of two (see
//! `docs/DKG_CEREMONY.md`). This module currently holds the roster/authentication
//! layer — the signed kind-31101 group announcement, the `index → pubkey` roster
//! it pins, the author-binding intake gate, the canonical `frost_group_id`, and
//! the equivocation-confirmation decision. The round-1/2/confirm coordination
//! loops move here in later phases.
//!
//! Errors flow as `keep_core::error::Result` (the type the extracted code already
//! used); `FrostNetError` wraps `KeepError` via `#[from]`, so keep-frost-net
//! callers can `?` these directly.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

use nostr_sdk::prelude::*;
use zeroize::Zeroizing;

use keep_core::error::{CryptoError, FrostError, KeepError, NetworkError, Result};
use keep_core::frost::dkg::{
    SoftwareDkgResult, SoftwareDkgSession, SoftwareRound1Wire, SoftwareRound2Wire,
};

/// Upper bound on distinct relay events tracked per software-DKG polling loop.
/// A DKG topic only ever carries a handful of packages; a set this large means
/// the relay is flooding junk, so we abort rather than grow memory unbounded
/// for the timeout window.
pub const MAX_DKG_EVENTS_SEEN: usize = 8192;

/// Signed group announcement (identity/roster). Public relay data.
/// Group announcement kind. **Addressable** (NIP-01 30000-39999), not
/// ephemeral: relays persist the newest event per `(author, kind, d)`, which is
/// exactly the semantics a roster wants and what makes `fetch_group_roster`
/// possible at all. The round kinds below are deliberately ephemeral because
/// they are live coordination traffic, but an announcement that no one can
/// retrieve later is useless, and 21101 was in the ephemeral range so relays
/// dropped it the moment it was forwarded.
pub const DKG_KIND_ANNOUNCE: u16 = 31101;
/// Round-1 package broadcast (public FROST commitment + PoK).
pub const DKG_KIND_ROUND1: u16 = 21102;
/// Round-2 share, NIP-44-encrypted per recipient to the recipient's roster key.
pub const DKG_KIND_ROUND2: u16 = 21103;
/// Group-key / transcript confirmation (equivocation check).
pub const DKG_KIND_CONFIRM: u16 = 21107;

/// (index -> pubkey) roster fetched from a signed kind-21101 group
/// announcement, used to authenticate DKG participants (#674).
///
/// Every DKG event is signed with the participant's per-group subkey (the one
/// whose pubkey appears in the announcement). Round 1 and round 2 intake reject
/// any event whose author does not match the expected pubkey for its
/// `sender_index`, closing the pre-#674 window where an unauthenticated relay
/// writer could hijack a victim's index (DoS) or, with enough participation,
/// silently join a group as a rogue co-generator.
#[derive(Clone, Debug)]
pub struct DkgRoster {
    pub threshold: u8,
    pub participants: u8,
    /// 1-indexed participant number -> announced pubkey.
    pub by_index: BTreeMap<u16, PublicKey>,
    /// The canonical `frost_group_id` this roster hash-binds to (§5). Kept so the
    /// DKG transcript can fold in the authenticated group id without re-deriving
    /// it from a possibly-private `d`-tag channel.
    pub group_id: [u8; 32],
}

impl DkgRoster {
    /// Expected pubkey for the given 1-indexed participant.
    pub fn expected_pubkey(&self, index: u16) -> Result<&PublicKey> {
        self.by_index.get(&index).ok_or_else(|| {
            KeepError::FrostErr(FrostError::invalid_config(format!(
                "roster has no entry for participant index {index}"
            )))
        })
    }

    /// #674: the single audited authentication gate for DKG intake. Returns
    /// `true` only when `author` is exactly the pubkey the roster pins to
    /// `sender_index`; otherwise it warns (with `what` naming the round) and
    /// returns `false` so the caller drops the event. Both rounds on both the
    /// hardware and software paths funnel through here, so a relay writer that
    /// cannot produce the pinned key's signature can never speak for an index.
    pub fn authenticates(&self, sender_index: u16, author: &PublicKey, what: &str) -> bool {
        match self.expected_pubkey(sender_index) {
            Ok(expected) if expected == author => true,
            Ok(expected) => {
                tracing::warn!(
                    sender_index,
                    %author,
                    %expected,
                    "Rejecting {what}: author does not match the roster-pinned key"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    sender_index,
                    error = %e,
                    "Ignoring {what} with unroster'd sender_index"
                );
                false
            }
        }
    }
}

/// Parse a hex-or-bech32 npub / hex pubkey string into a `nostr_sdk::PublicKey`.
pub fn parse_pubkey(s: &str) -> Result<PublicKey> {
    PublicKey::parse(s).map_err(|e| {
        KeepError::InvalidInput(format!("could not parse participant pubkey {s:?}: {e}"))
    })
}

/// Decide one peer's transcript confirmation against our own during the DKG
/// equivocation check. `Ok(true)` when it matches and is a newly-counted peer,
/// `Ok(false)` when that peer was already counted, and `Err` when the peer
/// reports a DIFFERENT transcript, which means the relay handed inconsistent
/// round1 packages and the DKG must abort rather than persist a split keyset.
/// Extracted so the equivocation decision is unit-testable without relay I/O.
///
/// The confirmed value is the §5 [`dkg_transcript`] hash, not just the group
/// key: two victims can derive the *same* group key from *different* round-1
/// sets, and only the transcript (which folds in each round-1 commitment)
/// detects that equivocation.
pub fn accept_group_key_confirmation(
    ours: &str,
    sender_index: u16,
    theirs: &str,
    already_confirmed: &mut HashSet<u16>,
) -> Result<bool> {
    if theirs.trim() != ours {
        return Err(KeepError::FrostErr(FrostError::dkg(format!(
            "participant {sender_index} derived a different DKG transcript than ours; aborting DKG \
             (the relay may have equivocated round1 packages)"
        ))));
    }
    Ok(already_confirmed.insert(sender_index))
}

/// Compute the §5 DKG transcript: the confirmed value each participant signs and
/// compares during the equivocation check. Strictly stronger than comparing the
/// group key alone — folding in the per-round-1 commitments is what defeats
/// same-key equivocation, and binding `group_id` folds in the whole
/// authenticated roster.
///
/// ```text
/// transcript = SHA256(
///   "keep-frost-dkg-transcript-v1"
///   ‖ group_id                                   (32)
///   ‖ threshold_be (2) ‖ participants_be (2)
///   ‖ for j in 1..=n:  index_be(2) ‖ pk_j (32)          // roster, ordered
///   ‖ for j in 1..=n:  SHA256(round1_pkg_bytes_j)       // commitment per round-1 pkg
///   ‖ group_pubkey                               (32)
/// )
/// ```
///
/// `round1_pkgs_by_index` carries the raw FROST round-1 package bytes (the
/// `package.serialize()` output, before any hex/JSON framing) for every
/// participant, ours included. Fails closed if any index in `1..=participants`
/// is absent from either the roster or the round-1 map, so a transcript can
/// never be computed over a partial set.
pub fn dkg_transcript(
    group_id: &[u8; 32],
    threshold: u8,
    participants: u8,
    roster_by_index: &BTreeMap<u16, PublicKey>,
    round1_pkgs_by_index: &BTreeMap<u16, Vec<u8>>,
    group_pubkey: &[u8; 32],
) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"keep-frost-dkg-transcript-v1");
    hasher.update(group_id);
    hasher.update((threshold as u16).to_be_bytes());
    hasher.update((participants as u16).to_be_bytes());
    for idx in 1..=participants as u16 {
        let pk = roster_by_index.get(&idx).ok_or_else(|| {
            KeepError::FrostErr(FrostError::dkg(format!(
                "transcript: roster is missing participant index {idx}"
            )))
        })?;
        hasher.update(idx.to_be_bytes());
        hasher.update(pk.as_bytes());
    }
    for idx in 1..=participants as u16 {
        let pkg = round1_pkgs_by_index.get(&idx).ok_or_else(|| {
            KeepError::FrostErr(FrostError::dkg(format!(
                "transcript: missing round-1 package for participant index {idx}"
            )))
        })?;
        hasher.update(Sha256::digest(pkg));
    }
    hasher.update(group_pubkey);
    Ok(hasher.finalize().into())
}

/// Canonical group_id preimage, the single source of truth for the group
/// identifier:
///
/// ```text
/// sha256("frost-group-id-v3"
///        || len(name) || name
///        || [threshold] || [participants]
///        || len(pubkeys)
///        || for each pubkey in 1..=participants order: len(bech32) || bech32)
/// ```
///
/// Every variable-length field is length-prefixed so the preimage is
/// unambiguous, and each pubkey is canonicalized to bech32 so the same roster
/// written in hex and in bech32 yields one id.
///
/// Both `cmd_frost_network_group_create` (which mints the id) and roster
/// verification (which re-derives it to hash-bind an announcement to its
/// queried `d` tag) MUST call this so the two can never drift: a relay writer
/// who republishes a rogue kind-21101 with the same `d` tag but different
/// p-tags cannot fake a preimage under sha256.
pub fn frost_group_id(
    name: &str,
    threshold: u8,
    participants: u8,
    ordered_npubs: &[String],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    // Every variable-length field is length-prefixed so the preimage is
    // unambiguous. Plain concatenation let a name absorb the start of the first
    // pubkey: ("ab", ["c"]) and ("a", ["bc"]) produced identical group ids, so
    // two different groups could share an id and therefore a roster binding.
    let mut hasher = Sha256::new();
    hasher.update(b"frost-group-id-v3");
    hasher.update((name.len() as u32).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update([threshold]);
    hasher.update([participants]);
    hasher.update((ordered_npubs.len() as u32).to_be_bytes());
    for npub in ordered_npubs {
        // Canonicalize here rather than at the call sites. The same key written
        // as hex and as bech32 must yield the same group id, or a CLI roster and
        // a mobile roster for one group derive different ids, land on different
        // `d`-tag channels, and never see each other. Normalizing inside the
        // hash makes every caller correct by construction. Entries that are not
        // pubkeys at all are hashed verbatim; that only happens in tests, and
        // the length prefix keeps the preimage unambiguous either way.
        let canonical = PublicKey::parse(npub)
            .ok()
            .and_then(|pk| pk.to_bech32().ok())
            .unwrap_or_else(|| npub.clone());
        hasher.update((canonical.len() as u32).to_be_bytes());
        hasher.update(canonical.as_bytes());
    }
    hasher.finalize().into()
}

/// Fetch the kind-21101 group announcement(s) for `group_id_hex` and return
/// the first one that authenticates into a valid roster.
///
/// #674: a relay writer can publish decoy kind-21101 events under the same
/// `d` tag (an attacker-chosen, self-signed `created_at` lets them appear
/// newest). We therefore try candidates newest-first and return the first
/// that fully validates via `parse_roster_from_event`, *skipping* any that
/// fail to parse or hash-bind, instead of latest-then-validate. That denies
/// the attacker a griefing DoS where a single junk event buries the honest
/// announcement and aborts the ceremony for everyone.
pub async fn fetch_group_roster(client: &Client, group_id_hex: &str) -> Result<DkgRoster> {
    let filter = Filter::new()
        .kind(Kind::Custom(DKG_KIND_ANNOUNCE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group_id_hex);

    let events = client
        .fetch_events(filter, std::time::Duration::from_secs(15))
        .await
        .map_err(|e| KeepError::NetworkErr(NetworkError::request(format!("fetch roster: {e}"))))?;

    let mut candidates: Vec<&Event> = events.iter().collect();
    candidates.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let mut last_err: Option<KeepError> = None;
    for ev in candidates {
        match parse_roster_from_event(ev, group_id_hex) {
            Ok(roster) => return Ok(roster),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        KeepError::NetworkErr(NetworkError::timeout(
            "no kind-21101 group announcement found for the requested group id \
             (run `keep frost network group-create` first, or point at the relay it was published on)",
        ))
    }))
}

/// Parse and fully validate one kind-21101 announcement into an authenticated
/// roster, requiring its tags to hash-bind to `group_id_hex`. Returns `Err`
/// (so `fetch_group_roster` can skip to the next candidate) on any anomaly:
/// a missing/duplicate/holed p-tag, a missing `threshold`/`participants` tag,
/// an unparseable pubkey, or a group_id hash mismatch. Pure and network-free
/// so it is unit-testable.
///
/// The roster is only as trustworthy as the event's authorship: this relies
/// on nostr-sdk verifying the event signature (default in nostr-sdk) so that
/// `ev.pubkey` is the authenticated author. Every intake site downstream
/// gates on that pubkey, so if signature verification were ever disabled on
/// the client the whole authentication scheme would collapse.
pub fn parse_roster_from_event(ev: &Event, group_id_hex: &str) -> Result<DkgRoster> {
    let mut threshold: Option<u8> = None;
    let mut participants: Option<u8> = None;
    // 1-indexed participant -> (pubkey, raw string as published). The raw string
    // is kept so we can recompute the group_id preimage byte for byte; index
    // order is imposed below when building `ordered_npubs`.
    let mut by_index: BTreeMap<u16, (PublicKey, String)> = BTreeMap::new();

    for tag in ev.tags.iter() {
        let slice = tag.as_slice();
        let name = match slice.first().map(|s| s.as_str()) {
            Some(n) => n,
            None => continue,
        };
        match name {
            // First occurrence wins so a duplicate garbage tag cannot null a
            // good value; a self-inconsistent candidate just fails hash-bind
            // and is skipped in favor of the next event.
            "threshold" if threshold.is_none() => {
                threshold = slice.get(1).and_then(|v| v.parse::<u8>().ok());
            }
            "participants" if participants.is_none() => {
                participants = slice.get(1).and_then(|v| v.parse::<u8>().ok());
            }
            "p" => {
                if let (Some(npub), Some(idx_str)) = (slice.get(1), slice.get(3)) {
                    let idx: u16 = match idx_str.parse() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let pk = parse_pubkey(npub)?;
                    if by_index.insert(idx, (pk, npub.clone())).is_some() {
                        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
                            "group announcement has duplicate p-tag for index {idx}"
                        ))));
                    }
                }
            }
            _ => {}
        }
    }

    // Distinct indices are not enough: the announcement is attacker-supplied, so
    // nothing stops one key being listed at two indices. That roster hash-binds
    // correctly and authenticates fine, but it hands the holder of the repeated
    // key two of the n shares, which makes a published "2-of-3" spendable by
    // that party alone. Validating this only where we *create* a group would
    // leave the check on the wrong side of the trust boundary, since an attacker
    // publishes the announcement directly rather than running our CLI.
    let mut distinct: HashSet<PublicKey> = HashSet::new();
    for (idx, (pk, _)) in by_index.iter() {
        if !distinct.insert(*pk) {
            return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
                "group announcement repeats one pubkey at index {idx}; every \
                 participant must hold a distinct key"
            ))));
        }
    }

    let threshold = threshold.ok_or_else(|| {
        KeepError::FrostErr(FrostError::invalid_config(
            "group announcement is missing a `threshold` tag".to_string(),
        ))
    })?;
    let participants = participants.ok_or_else(|| {
        KeepError::FrostErr(FrostError::invalid_config(
            "group announcement is missing a `participants` tag".to_string(),
        ))
    })?;
    // Enforce the threshold shape here rather than trusting callers. This is a
    // `pub` function fed an attacker-supplied announcement, and a roster
    // claiming threshold 1 (single-party spendable) or threshold > participants
    // (unsatisfiable) has no legitimate use. Both callers happen to pre-validate
    // today; that is exactly the argument for not leaving the invariant on the
    // far side of the trust boundary.
    if threshold < 2 || threshold > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "group announcement claims threshold {threshold} of {participants}; \
             must satisfy 2 <= threshold <= participants"
        ))));
    }
    if by_index.len() != participants as usize {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "group announcement carries {} p-tags but claims {} participants",
            by_index.len(),
            participants,
        ))));
    }
    // Reject rosters with holes: indexes must be exactly 1..=participants.
    // This also imposes index order on the npubs fed to the group_id hash.
    let mut ordered_npubs: Vec<String> = Vec::with_capacity(participants as usize);
    let mut roster: BTreeMap<u16, PublicKey> = BTreeMap::new();
    for idx in 1..=participants as u16 {
        let (pk, npub) = by_index.get(&idx).ok_or_else(|| {
            KeepError::FrostErr(FrostError::invalid_config(format!(
                "group announcement is missing a p-tag for participant index {idx}"
            )))
        })?;
        ordered_npubs.push(npub.clone());
        roster.insert(idx, *pk);
    }

    // #674: recompute the group_id hash from the announcement's own fields and
    // require it to match the queried `d` tag. This is the strong bind that
    // prevents a relay writer from swapping in a rogue kind-21101 with the same
    // `d` tag but different p-tags (a preimage attack under sha256, infeasible).
    let name = match serde_json::from_str::<serde_json::Value>(&ev.content) {
        Ok(v) => v
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                KeepError::FrostErr(FrostError::invalid_config(
                    "group announcement content is missing a `name` field".to_string(),
                ))
            })?,
        Err(e) => {
            return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
                "group announcement content is not JSON: {e}"
            ))));
        }
    };
    let group_id = frost_group_id(&name, threshold, participants, &ordered_npubs);
    let recomputed = hex::encode(group_id);
    if recomputed != group_id_hex {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "group announcement id {recomputed} does not match the queried d-tag {group_id_hex}; \
             refusing a roster that does not bind to the requested group"
        ))));
    }

    Ok(DkgRoster {
        threshold,
        participants,
        by_index: roster,
        group_id,
    })
}

/// Verify (threshold, participants) from the signed announcement match the
/// caller's declared config, and check `our_index` binds to our key in the
/// roster. Fail closed so a peer `(t, n)` mismatch or a device running under
/// the wrong index surfaces before we produce any round1 material.
pub fn require_roster_matches(
    roster: &DkgRoster,
    identity: &Keys,
    threshold: u8,
    participants: u8,
    our_index: u8,
) -> Result<()> {
    if roster.threshold != threshold {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "signed group announcement pins threshold={} but caller declared {threshold}",
            roster.threshold
        ))));
    }
    if roster.participants != participants {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "signed group announcement pins participants={} but caller declared {participants}",
            roster.participants
        ))));
    }
    let expected = roster.expected_pubkey(our_index as u16)?;
    if identity.public_key() != *expected {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "our key {} does not match the announced participant at index {our_index} ({})",
            identity.public_key(),
            expected,
        ))));
    }
    Ok(())
}

/// `dkg_mode` tag value marking the software-DKG wire, so a hardware-format
/// event sharing the `d` channel is skipped cleanly rather than mis-parsed.
pub const DKG_MODE_SOFTWARE_V1: &str = "software_v1";

type DkgBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Transport seam for the DKG coordinator: publish one event, and poll for the
/// events matching a filter. keep-cli backs this with a plain nostr `Client`
/// ([`ClientTransport`]); keep-mobile supplies a hardened client (cert pinning,
/// proxy, non-default relay options) in a later phase. Futures are not required
/// to be `Send` — both callers drive the coordinator with `block_on`.
pub trait DkgTransport {
    fn send_event<'a>(&'a self, event: &'a Event) -> DkgBoxFuture<'a, Result<()>>;
    fn fetch_events(
        &self,
        filter: Filter,
        timeout: Duration,
    ) -> DkgBoxFuture<'_, Result<Vec<Event>>>;
}

/// Relay options matching the signing path (`node/mod.rs`): reconnect + ping so a
/// phone that drops off Tor recovers, `ban_relay_on_mismatch` so a relay that
/// swaps its advertised info is dropped, and a bounded average latency. The DKG
/// transport and the live signing node share this so the two never drift.
pub fn default_relay_opts() -> RelayOptions {
    RelayOptions::default()
        .reconnect(true)
        .ping(true)
        .retry_interval(Duration::from_secs(10))
        .adjust_retry_interval(true)
        .ban_relay_on_mismatch(true)
        .max_avg_latency(Some(Duration::from_secs(3)))
}

/// Upper bound on live DKG events buffered for one round.
///
/// Strictly greater than [`MAX_DKG_EVENTS_SEEN`], not equal to it. The
/// coordinator aborts on `seen_round.len() > MAX_DKG_EVENTS_SEEN`, counting only
/// events this transport handed it, so a cap at or below that bound makes the
/// abort unsatisfiable: the transport would go quietly deaf and the round would
/// fail as a timeout blaming absent peers instead of reporting the flood. The
/// headroom also covers our own echoed events, which the coordinator discards
/// before counting.
const MAX_BUFFERED_EVENTS: usize = MAX_DKG_EVENTS_SEEN * 2;

/// Enforced at compile time, not by a test: the two were briefly equal, which
/// made the coordinator's `len() > MAX_DKG_EVENTS_SEEN` abort unsatisfiable and
/// turned a reported flood into a silent timeout.
const _: () = assert!(MAX_BUFFERED_EVENTS > MAX_DKG_EVENTS_SEEN);

/// Approximate retained size of a buffered event: content plus every tag value.
/// Tags are the part the content-only accounting missed, and the pinned SDK
/// allows up to 2000 of them per event.
fn event_size(e: &Event) -> usize {
    e.content.len()
        + e.tags
            .iter()
            .map(|t| t.as_slice().iter().map(String::len).sum::<usize>())
            .sum::<usize>()
}

/// How long a single wait on the notification stream blocks before the caller
/// re-checks its deadline and cancellation flag.
const POLL_WAKE: Duration = Duration::from_millis(500);

/// Total buffered event size per round, in bytes, counting tags as well as
/// content. The count cap alone does not bound memory: the pinned SDK sets no
/// per-event size limit (only a 5 MB websocket frame and 2000 tags), so a few
/// thousand maximal events would be tens of gigabytes. Content alone is not
/// enough either, because that budget can be spent entirely on tags. A DKG
/// package is a few KB, so this is generous for the honest path while keeping a
/// hostile relay from exhausting a phone.
const MAX_BUFFERED_BYTES: usize = 16 * 1024 * 1024;

/// A [`DkgTransport`] over a live `nostr_sdk::Client`. The caller connects the
/// client (and applies any relay hardening) before wrapping it.
///
/// DKG kinds are ephemeral (NIP-01 20000-29999), so relays broadcast them to
/// *live* subscribers and never store them. A REQ issued after a peer published
/// therefore returns EOSE with nothing, which is why this cannot be built on
/// `Client::fetch_events`: that exits on EOSE and would only ever see a peer by
/// racing a republish into the instant its subscription happened to be open.
/// Instead we hold a subscription open per round filter and accumulate from the
/// notification stream, the same shape the signing path uses.
pub struct ClientTransport {
    client: Client,
    /// Created before any subscription so no notification is missed.
    notifications: tokio::sync::Mutex<broadcast::Receiver<RelayPoolNotification>>,
    /// Live events for the round currently being collected, bounded by
    /// [`MAX_BUFFERED_EVENTS`] and cleared when the round advances.
    seen: std::sync::Mutex<Vec<Event>>,
    /// The filter `seen` currently holds events for. Rounds are sequential, so a
    /// different filter means the previous round finished and its buffer is
    /// dead weight. Without this the buffer never shrinks: peers republish with
    /// a fresh timestamp (and therefore a fresh event id) on every poll, so
    /// id-dedup does not collapse them and the cap would eventually be reached,
    /// after which the transport silently drops the packages the run is waiting
    /// for.
    buffered_for: std::sync::Mutex<Option<Filter>>,
    /// Round filters already subscribed, kept open for the transport's life.
    subscribed: tokio::sync::Mutex<Vec<Filter>>,
}

impl ClientTransport {
    pub fn new(client: Client) -> Self {
        let notifications = tokio::sync::Mutex::new(client.notifications());
        Self {
            client,
            notifications,
            seen: std::sync::Mutex::new(Vec::new()),
            buffered_for: std::sync::Mutex::new(None),
            subscribed: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Buffer one live event for the current round, applying the cap and
    /// dropping exact repeats. Single insertion point so the cap and the dedupe
    /// rule cannot drift between the drain path and the blocking-recv path.
    fn buffer(&self, filter: &Filter, event: Event) {
        // Only buffer what the round actually asked for. Subscriptions from
        // earlier rounds are never closed, so without this the kind-21102 and
        // kind-21103 streams keep arriving during confirm and spend the single
        // shared cap on events no one will read, starving the round in progress.
        if !filter.match_event(&event, MatchEventOptions::new()) {
            return;
        }
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if seen.len() >= MAX_BUFFERED_EVENTS || seen.iter().any(|e| e.id == event.id) {
            return;
        }
        let used: usize = seen.iter().map(event_size).sum();
        if used.saturating_add(event_size(&event)) > MAX_BUFFERED_BYTES {
            return;
        }
        seen.push(event);
    }

    /// Drop the previous round's events when collection moves to a new filter.
    ///
    /// Without this the buffer only ever grows: peers rebuild and resend their
    /// package on every poll with a fresh timestamp, so each repeat is a
    /// distinct event id that id-dedupe cannot collapse. In a large group that
    /// reaches the cap on the honest path alone, and a full buffer is worse than
    /// a slow one because the transport then silently drops the very packages
    /// the round is waiting on and fails as a timeout blaming absent peers.
    /// Rounds are strictly sequential, so a filter change means the previous
    /// round is done and its events are dead weight.
    fn retarget(&self, filter: &Filter) {
        let mut current = self.buffered_for.lock().unwrap_or_else(|p| p.into_inner());
        if current.as_ref() != Some(filter) {
            self.seen.lock().unwrap_or_else(|p| p.into_inner()).clear();
            *current = Some(filter.clone());
        }
    }

    /// Move every notification currently queued into `seen`. Never blocks.
    fn drain_pending(&self, filter: &Filter, rx: &mut broadcast::Receiver<RelayPoolNotification>) {
        use tokio::sync::broadcast::error::TryRecvError;
        loop {
            match rx.try_recv() {
                Ok(RelayPoolNotification::Event { event, .. }) => self.buffer(filter, *event),
                Ok(_) => continue,
                // Lagged means the buffer overflowed; keep draining what remains
                // rather than treating it as end-of-stream.
                Err(TryRecvError::Lagged(_)) => continue,
                Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => return,
            }
        }
    }

    /// Events buffered so far that satisfy `filter`.
    fn matching(&self, filter: &Filter) -> Vec<Event> {
        let opts = MatchEventOptions::new();
        self.seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|e| filter.match_event(e, opts))
            .cloned()
            .collect()
    }

    /// Build a hardened client over `relays` and wrap it for the DKG coordinator
    /// (§7). Routes through the configured loopback SOCKS `proxy` when set and
    /// applies [`default_relay_opts`] (the same reconnect/ping/ban-on-mismatch
    /// profile the signing node uses), then connects and waits (bounded) for at
    /// least one relay to reach `Connected`.
    ///
    /// The caller pre-verifies and pins each relay's TLS certificate before this
    /// (keep-mobile's `verify_and_pin_relays`); this only opens the connections.
    /// The caller MUST [`disconnect`](Self::disconnect) on every exit path — the
    /// nostr `Client`/`RelayPool` have no `Drop` cleanup, so an early return that
    /// skips it leaks the websocket.
    pub async fn connect_hardened(
        keys: &Keys,
        relays: &[String],
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<Self> {
        let client = match proxy {
            Some(addr) => {
                let connection = Connection::new().proxy(addr).target(ConnectionTarget::All);
                let opts = ClientOptions::new().connection(connection);
                Client::builder().signer(keys.clone()).opts(opts).build()
            }
            None => Client::new(keys.clone()),
        };

        for relay in relays {
            client
                .pool()
                .add_relay(relay, default_relay_opts())
                .await
                .map_err(|e| {
                    KeepError::NetworkErr(NetworkError::relay(format!("add relay {relay}: {e}")))
                })?;
        }
        client.connect().await;

        let connected = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let any_connected = client
                    .relays()
                    .await
                    .values()
                    .any(|r| matches!(r.status(), RelayStatus::Connected));
                if any_connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        if connected.is_err() {
            // The client has no Drop cleanup, so tear down the websocket tasks
            // spawned by connect() before returning rather than leaking them.
            client.disconnect().await;
            return Err(KeepError::NetworkErr(NetworkError::timeout(
                "waiting for relay connection",
            )));
        }

        Ok(Self::new(client))
    }

    /// Tear down the relay connections. Call on every exit path of a DKG run
    /// (success, error, cancel) since the client has no `Drop` cleanup (§7).
    pub async fn disconnect(&self) {
        self.client.disconnect().await;
    }
}

impl DkgTransport for ClientTransport {
    fn send_event<'a>(&'a self, event: &'a Event) -> DkgBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.client
                .send_event(event)
                .await
                .map(|_| ())
                .map_err(|e| KeepError::NetworkErr(NetworkError::publish(e.to_string())))
        })
    }

    /// Return every event seen so far matching `filter`, waiting up to `timeout`
    /// for at least one if none have arrived. Opens a durable subscription for
    /// `filter` on first use and leaves it open, because the DKG kinds are
    /// ephemeral and a relay only ever delivers them to a subscriber that is
    /// already listening.
    fn fetch_events(
        &self,
        filter: Filter,
        timeout: Duration,
    ) -> DkgBoxFuture<'_, Result<Vec<Event>>> {
        Box::pin(async move {
            {
                let mut subscribed = self.subscribed.lock().await;
                if !subscribed.iter().any(|f| f == &filter) {
                    // `None` opts: no auto-close, so it stays open across polls.
                    self.client
                        .subscribe(filter.clone(), None)
                        .await
                        .map_err(|e| KeepError::NetworkErr(NetworkError::request(e.to_string())))?;
                    subscribed.push(filter.clone());
                }
            }

            self.retarget(&filter);

            let deadline = Instant::now() + timeout;
            loop {
                {
                    let mut rx = self.notifications.lock().await;
                    self.drain_pending(&filter, &mut rx);
                }
                let matched = self.matching(&filter);
                if !matched.is_empty() {
                    return Ok(matched);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(Vec::new());
                }
                // Wait for the next notification rather than spinning; a publish
                // by a peer wakes us immediately.
                let mut rx = self.notifications.lock().await;
                match tokio::time::timeout(remaining.min(POLL_WAKE), rx.recv()).await {
                    Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                        self.buffer(&filter, *event)
                    }
                    // The pool dropped its sender, so no further event can ever
                    // arrive on this receiver. Returning what we have beats
                    // spinning on an instantly-returning `recv` until the
                    // deadline; the caller retries and surfaces a timeout.
                    Ok(Err(broadcast::error::RecvError::Closed)) => {
                        return Ok(self.matching(&filter))
                    }
                    // Lagged also returns immediately. We may have missed
                    // notifications, so yield briefly instead of spinning; the
                    // next drain picks up whatever is still queued, and peers
                    // republish each round so a missed package comes back.
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                        drop(rx);
                        tokio::time::sleep(POLL_WAKE.min(remaining)).await;
                    }
                    // Timed out waiting, or a non-event notification: loop and
                    // re-evaluate against the deadline.
                    _ => continue,
                }
            }
        })
    }
}

/// Live progress of a DKG run, surfaced to the caller's UI. keep-cli renders it
/// through its `Output`; keep-mobile maps it to `DkgProgressUpdate` over the FFI.
#[derive(Clone, Debug)]
pub enum DkgPhase {
    /// Waiting on peers' round-1 packages. `received` counts distinct authored
    /// peers so far (excluding us); `total` is the number expected.
    Round1 { received: u16, total: u16 },
    /// Waiting on the round-2 shares addressed to this device.
    Round2 { received: u16, total: u16 },
    /// All shares in; running the final key derivation.
    Finalizing,
    /// Broadcasting/collecting the group-key equivocation confirmation.
    Confirming { confirmed: u16, total: u16 },
    /// DKG succeeded; the group key is agreed across all peers.
    Complete { group_pubkey: [u8; 32] },
}

/// Progress sink — the seam replacing keep-cli's `Output` so the round
/// coordination is shared. Not required to be `Send`/`Sync`.
pub trait DkgProgress {
    fn phase(&self, phase: DkgPhase);
}

/// A CertEq success certificate (§6): all `n` participant signatures over the
/// identical §5 transcript, retained so a device that finalized can later
/// convince a peer that timed out to finalize too (Conditional Agreement).
///
/// Each confirmation is a signed kind-21107 event whose author is the
/// roster-pinned key for its index and whose content is the transcript hex, so
/// the set is **transferable**: a timed-out peer verifies every signature
/// against its own roster and finalizes, trusting the certificate rather than
/// the presenter. Success is *collecting* this whole set, not merely observing
/// agreement and moving on — the gap that let device A believe it was in a live
/// group device B never joined.
#[derive(Clone, Debug)]
pub struct DkgCertificate {
    /// The §5 transcript every confirmation signs over.
    pub transcript: [u8; 32],
    /// 1-indexed participant -> its signed kind-21107 confirmation event, this
    /// device's own included, so the certificate carries all `n` signatures.
    pub confirmations: BTreeMap<u16, Event>,
}

impl DkgCertificate {
    /// Hex of the transcript every confirmation must sign over.
    pub fn transcript_hex(&self) -> String {
        hex::encode(self.transcript)
    }

    /// Verify this is a complete CertEq certificate for `roster` (§6): exactly
    /// one confirmation per rostered index `1..=participants`, each a validly
    /// signed kind-21107 event authored by that index's roster-pinned key and
    /// carrying this certificate's transcript hex. This is the check a
    /// timed-out peer runs when a finalized device presents the certificate
    /// later, so it trusts the roster and the signatures — never the presenter.
    pub fn verify(&self, roster: &DkgRoster) -> Result<()> {
        let want = self.transcript_hex();
        if self.confirmations.len() != roster.participants as usize {
            return Err(KeepError::FrostErr(FrostError::dkg(format!(
                "certificate carries {} confirmations but the roster has {} participants",
                self.confirmations.len(),
                roster.participants
            ))));
        }
        for idx in 1..=roster.participants as u16 {
            let ev = self.confirmations.get(&idx).ok_or_else(|| {
                KeepError::FrostErr(FrostError::dkg(format!(
                    "certificate is missing the confirmation for participant index {idx}"
                )))
            })?;
            let expected = roster.expected_pubkey(idx)?;
            if ev.pubkey != *expected {
                return Err(KeepError::FrostErr(FrostError::dkg(format!(
                    "certificate confirmation for index {idx} is authored by {} not the \
                     roster-pinned key {expected}",
                    ev.pubkey
                ))));
            }
            if ev.kind != Kind::Custom(DKG_KIND_CONFIRM) {
                return Err(KeepError::FrostErr(FrostError::dkg(format!(
                    "certificate confirmation for index {idx} is kind {} not the confirm kind",
                    ev.kind
                ))));
            }
            if ev.content.trim() != want {
                return Err(KeepError::FrostErr(FrostError::dkg(format!(
                    "certificate confirmation for index {idx} signs a different transcript than \
                     the certificate's"
                ))));
            }
            ev.verify().map_err(|e| {
                KeepError::CryptoErr(CryptoError::invalid_signature(format!(
                    "certificate confirmation for index {idx}: {e}"
                )))
            })?;
        }
        Ok(())
    }
}

/// What a finalized software DKG hands back: the finalized share plus the
/// retained CertEq certificate (§6). The caller persists the share and keeps the
/// certificate to re-convince any peer that timed out during confirmation.
pub struct DkgOutcome {
    pub result: SoftwareDkgResult,
    pub certificate: DkgCertificate,
}

/// True when `ev` carries the `dkg_mode=software_v1` tag.
fn is_software_v1(ev: &Event) -> bool {
    ev.tags.iter().any(|t| {
        let slice = t.as_slice();
        slice.first().map(|s| s.as_str()) == Some("dkg_mode")
            && slice.get(1).map(|s| s.as_str()) == Some(DKG_MODE_SOFTWARE_V1)
    })
}

/// Read a `u16` value from the first tag named `key`.
fn u16_tag(ev: &Event, key: &str) -> Option<u16> {
    ev.tags.iter().find_map(|t| {
        let slice = t.as_slice();
        if slice.first().map(|s| s.as_str()) == Some(key) {
            slice.get(1).and_then(|s| s.parse::<u16>().ok())
        } else {
            None
        }
    })
}

/// Drive a full relay-mediated software DKG for one participant and return its
/// finalized share. The crypto lives in [`SoftwareDkgSession`]; this moves the
/// round-1/round-2/confirmation packages over `transport`, authenticating every
/// peer against the pre-verified `roster` (§674) and running the equivocation
/// confirmation before returning, so a divergent or missing peer aborts rather
/// than persisting a split keyset. The caller connects the transport, verifies
/// the roster, and persists the returned result.
///
/// `keys` is this device's per-group key (the one the roster pins for
/// `our_index`); it signs every event and performs the round-2 NIP-44 ECDH.
/// `group` is the `d`-tag channel. Each round independently must complete within
/// `timeout` or the run fails with a timeout error.
///
/// `cancel` is polled between relay fetches; a caller that flips it (the mobile
/// UI's cancel button) aborts the run promptly with a cancelled error instead of
/// waiting out the round timeout, so a live session is torn down cleanly rather
/// than left for a `reset` to corrupt (§8/§9).
#[allow(clippy::too_many_arguments)]
pub async fn run_software_dkg(
    session: &mut SoftwareDkgSession,
    transport: &dyn DkgTransport,
    keys: &Keys,
    roster: &DkgRoster,
    group: &str,
    our_index: u16,
    timeout: Duration,
    cancel: &AtomicBool,
    progress: &dyn DkgProgress,
) -> Result<DkgOutcome> {
    let cancelled = || KeepError::Runtime("DKG cancelled by caller".to_string());
    let our_pubkey = keys.public_key();
    let expected_peers = (roster.participants as u32).saturating_sub(1);
    let total = expected_peers as u16;

    let base_tags = |content_kind: u16| {
        let d = Tag::custom(TagKind::custom("d"), vec![group.to_string()]);
        let sender = Tag::custom(TagKind::custom("sender_index"), vec![our_index.to_string()]);
        let mode = Tag::custom(
            TagKind::custom("dkg_mode"),
            vec![DKG_MODE_SOFTWARE_V1.to_string()],
        );
        (Kind::Custom(content_kind), d, sender, mode)
    };

    // DKG events (kinds 21101-21107) are ephemeral, so relays never store them:
    // a peer that subscribes after our one-shot publish would never see it. We
    // rebuild and resend our outbound event on every poll iteration with a fresh
    // timestamp (hence a new event id) so relays forward it to late subscribers.
    let build_signed = |content_kind: u16, content: &str, extra: &[Tag]| -> Result<Event> {
        let (kind, d, sender, mode) = base_tags(content_kind);
        let mut builder = EventBuilder::new(kind, content)
            .tag(d)
            .tag(sender)
            .tag(mode);
        for t in extra {
            builder = builder.tag(t.clone());
        }
        builder
            .sign_with_keys(keys)
            .map_err(|e| KeepError::CryptoErr(CryptoError::invalid_signature(e.to_string())))
    };

    // --- Round 1: publish our package, collect the other n-1. ---
    let our_round1 = session
        .round1()
        .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("round 1: {e}"))))?;
    // §5 transcript: retain every participant's raw round-1 package bytes
    // (ours + peers') so the equivocation confirmation compares the full
    // transcript, not just the derived group key.
    let mut round1_pkgs: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    round1_pkgs.insert(
        our_index,
        hex::decode(&our_round1.package_hex)
            .map_err(|e| KeepError::Runtime(format!("decode our round1 package: {e}")))?,
    );
    let round1_content = serde_json::to_string(&our_round1)
        .map_err(|e| KeepError::Runtime(format!("serialize round1: {e}")))?;
    progress.phase(DkgPhase::Round1 { received: 0, total });

    let round1_filter = Filter::new()
        .kind(Kind::Custom(DKG_KIND_ROUND1))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());

    let mut participant_pubkeys: HashMap<u16, PublicKey> = HashMap::new();
    let mut round1_done = 0u32;
    let mut seen_round1: HashSet<EventId> = HashSet::new();
    let start = Instant::now();
    while round1_done < expected_peers {
        if cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        if start.elapsed() > timeout {
            return Err(KeepError::NetworkErr(NetworkError::timeout(
                "waiting for peer round1 packages",
            )));
        }
        transport
            .send_event(&build_signed(DKG_KIND_ROUND1, &round1_content, &[])?)
            .await?;
        let events = transport
            .fetch_events(round1_filter.clone(), Duration::from_secs(5))
            .await?;
        for ev in events.iter() {
            if ev.pubkey == our_pubkey || !seen_round1.insert(ev.id) {
                continue;
            }
            if seen_round1.len() > MAX_DKG_EVENTS_SEEN {
                return Err(KeepError::NetworkErr(NetworkError::request(
                    "too many distinct DKG round1 events; aborting to bound memory".to_string(),
                )));
            }
            if !is_software_v1(ev) {
                continue;
            }
            let wire: SoftwareRound1Wire = match serde_json::from_str(&ev.content) {
                Ok(w) => w,
                Err(_) => continue,
            };
            if wire.sender_index == our_index {
                continue;
            }
            // #674: authenticate against the roster BEFORE touching the state
            // machine so a hostile publisher cannot race an index or force a
            // spurious part2/part3 rejection with malformed data.
            if !roster.authenticates(wire.sender_index, &ev.pubkey, "round 1 event") {
                continue;
            }
            if participant_pubkeys.contains_key(&wire.sender_index) {
                continue;
            }
            let peer_pkg = match hex::decode(&wire.package_hex) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            match session.round1_peer(&wire) {
                Ok(_) => {
                    participant_pubkeys.insert(wire.sender_index, ev.pubkey);
                    round1_pkgs.insert(wire.sender_index, peer_pkg);
                    round1_done += 1;
                    progress.phase(DkgPhase::Round1 {
                        received: round1_done as u16,
                        total,
                    });
                }
                Err(e) => tracing::warn!(
                    index = wire.sender_index,
                    error = %e,
                    "Rejected round 1 package"
                ),
            }
        }
        if round1_done < expected_peers {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    // --- Round 2: publish one encrypted share per recipient, collect ours. ---
    let round2_wires = session
        .round2()
        .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("round 2: {e}"))))?;
    progress.phase(DkgPhase::Round2 { received: 0, total });
    // Encrypt each recipient's share once; the ciphertext is reused, but the
    // carrying event is rebuilt with a fresh timestamp on every poll below so
    // late peers still receive it (ephemeral events are not stored by relays).
    let mut round2_outbound: Vec<(u16, String)> = Vec::new();
    for (recipient_index, wire) in round2_wires {
        let recipient_pubkey = participant_pubkeys
            .get(&recipient_index)
            .ok_or_else(|| KeepError::FrostErr(FrostError::unknown_participant(recipient_index)))?;
        // Serialized share is secret until nip44 wraps it; scrub the plaintext.
        let payload = Zeroizing::new(
            serde_json::to_string(&wire)
                .map_err(|e| KeepError::Runtime(format!("serialize round2: {e}")))?,
        );
        let encrypted = nip44::encrypt(
            keys.secret_key(),
            recipient_pubkey,
            payload.as_str(),
            nip44::Version::default(),
        )
        .map_err(|e| KeepError::CryptoErr(CryptoError::encryption(e.to_string())))?;
        round2_outbound.push((recipient_index, encrypted));
    }

    let round2_filter = Filter::new()
        .kind(Kind::Custom(DKG_KIND_ROUND2))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());
    let mut round2_done = 0u32;
    let mut seen_round2: HashSet<EventId> = HashSet::new();
    let start = Instant::now();
    while round2_done < expected_peers {
        if cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        if start.elapsed() > timeout {
            return Err(KeepError::NetworkErr(NetworkError::timeout(
                "waiting for peer round2 shares",
            )));
        }
        for (recipient_index, encrypted) in round2_outbound.iter() {
            let recipient_tag = Tag::custom(
                TagKind::custom("recipient_index"),
                vec![recipient_index.to_string()],
            );
            transport
                .send_event(&build_signed(DKG_KIND_ROUND2, encrypted, &[recipient_tag])?)
                .await?;
        }
        let events = transport
            .fetch_events(round2_filter.clone(), Duration::from_secs(5))
            .await?;
        for ev in events.iter() {
            if ev.pubkey == our_pubkey || !seen_round2.insert(ev.id) {
                continue;
            }
            if seen_round2.len() > MAX_DKG_EVENTS_SEEN {
                return Err(KeepError::NetworkErr(NetworkError::request(
                    "too many distinct DKG round2 events; aborting to bound memory".to_string(),
                )));
            }
            if !is_software_v1(ev) || u16_tag(ev, "recipient_index") != Some(our_index) {
                continue;
            }
            // #674/§7: authenticate on the cleartext `sender_index` tag BEFORE the
            // NIP-44 ECDH, so an unroster'd flood costs a cheap tag lookup instead
            // of one ECDH per spam event. The roster is authoritative for who each
            // index is; the inner `sender_index` is re-checked against this
            // authenticated tag below so a peer cannot claim a different index
            // inside the ciphertext than it signed the event as.
            let sender_idx = match u16_tag(ev, "sender_index") {
                Some(i) => i,
                None => continue,
            };
            if !roster.authenticates(sender_idx, &ev.pubkey, "round 2 share") {
                continue;
            }
            let decrypted = match nip44::decrypt(keys.secret_key(), &ev.pubkey, &ev.content) {
                // Plaintext carries the peer's secret signing share; scrub it.
                Ok(d) => Zeroizing::new(d),
                Err(_) => continue,
            };
            let wire: SoftwareRound2Wire = match serde_json::from_str(&decrypted) {
                Ok(w) => w,
                Err(_) => continue,
            };
            if wire.sender_index != sender_idx {
                tracing::warn!(
                    tag_index = sender_idx,
                    wire_index = wire.sender_index,
                    "Rejecting round 2 share: encrypted sender_index disagrees with the signed tag"
                );
                continue;
            }
            match session.receive_share(&wire) {
                Ok(_) => {
                    round2_done += 1;
                    progress.phase(DkgPhase::Round2 {
                        received: round2_done as u16,
                        total,
                    });
                }
                Err(e) => tracing::warn!(
                    index = wire.sender_index,
                    error = %e,
                    "Rejected round 2 share"
                ),
            }
        }
        if round2_done < expected_peers {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    // --- Finalize + equivocation confirmation (keep-dcnq). ---
    progress.phase(DkgPhase::Finalizing);
    let result = session
        .finalize()
        .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("finalize: {e}"))))?;

    // round1 packages are broadcast through a single relay with no consistency
    // round, so a malicious relay can hand DIFFERENT round1 sets to different
    // participants. Two victims can even derive the SAME group key from
    // DIFFERENT round1 sets, which a bare group-key compare misses. Every
    // participant instead broadcasts the §5 transcript it derived
    // (authenticated, the relay cannot forge) — which folds in each round-1
    // commitment — and requires all peers to report the SAME transcript; a
    // divergence or a peer that never confirms aborts rather than persisting an
    // inconsistent set.
    let our_transcript = dkg_transcript(
        &roster.group_id,
        roster.threshold,
        roster.participants,
        &roster.by_index,
        &round1_pkgs,
        &result.group_pubkey,
    )?;
    let our_transcript_hex = hex::encode(our_transcript);
    progress.phase(DkgPhase::Confirming {
        confirmed: 0,
        total,
    });

    let confirm_filter = Filter::new()
        .kind(Kind::Custom(DKG_KIND_CONFIRM))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());
    let mut confirmed_indices: HashSet<u16> = HashSet::new();
    // §6: retain each peer's signed confirmation, not just the fact it agreed,
    // so the finalized certificate is transferable to a peer that times out.
    let mut peer_confirmations: BTreeMap<u16, Event> = BTreeMap::new();
    let mut seen_confirm: HashSet<EventId> = HashSet::new();
    let start = Instant::now();
    while (confirmed_indices.len() as u32) < expected_peers {
        if cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        if start.elapsed() > timeout {
            return Err(KeepError::NetworkErr(NetworkError::timeout(
                "waiting for peer group-key confirmations (possible relay equivocation)",
            )));
        }
        transport
            .send_event(&build_signed(DKG_KIND_CONFIRM, &our_transcript_hex, &[])?)
            .await?;
        let events = transport
            .fetch_events(confirm_filter.clone(), Duration::from_secs(5))
            .await?;
        for ev in events.iter() {
            if ev.pubkey == our_pubkey || !seen_confirm.insert(ev.id) {
                continue;
            }
            if seen_confirm.len() > MAX_DKG_EVENTS_SEEN {
                return Err(KeepError::NetworkErr(NetworkError::request(
                    "too many distinct DKG confirm events; aborting to bound memory".to_string(),
                )));
            }
            if !is_software_v1(ev) {
                continue;
            }
            let sender_idx = match u16_tag(ev, "sender_index") {
                Some(i) => i,
                None => continue,
            };
            if !roster.authenticates(sender_idx, &ev.pubkey, "group-key confirmation") {
                continue;
            }
            if accept_group_key_confirmation(
                &our_transcript_hex,
                sender_idx,
                &ev.content,
                &mut confirmed_indices,
            )? {
                peer_confirmations.insert(sender_idx, ev.clone());
                progress.phase(DkgPhase::Confirming {
                    confirmed: confirmed_indices.len() as u16,
                    total,
                });
            }
        }
        if (confirmed_indices.len() as u32) < expected_peers {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    // §6/CertEq: success is holding all `n` signatures over the identical
    // transcript, so fold our own confirmation in and verify the assembled
    // certificate before signalling Complete. Never surface the group as ready
    // without the certificate in hand — that ordering is the fix for a device
    // finalizing into a group a timed-out peer never joined.
    let mut confirmations = peer_confirmations;
    confirmations.insert(
        our_index,
        build_signed(DKG_KIND_CONFIRM, &our_transcript_hex, &[])?,
    );
    let certificate = DkgCertificate {
        transcript: our_transcript,
        confirmations,
    };
    certificate.verify(roster)?;

    progress.phase(DkgPhase::Complete {
        group_pubkey: result.group_pubkey,
    });
    Ok(DkgOutcome {
        result,
        certificate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pubkey(seed: u8) -> (String, PublicKey) {
        let secp = nostr_sdk::secp256k1::Secp256k1::new();
        let sk = nostr_sdk::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let (xonly, _) = sk.x_only_public_key(&secp);
        let hex = hex::encode(xonly.serialize());
        (hex.clone(), PublicKey::parse(&hex).unwrap())
    }

    fn make_identity_keys(seed: u8) -> Keys {
        let sk = nostr_sdk::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        Keys::new(sk.into())
    }

    /// #674: `require_roster_matches` catches every published-vs-caller drift
    /// path: threshold mismatch, participants mismatch, and identity/index
    /// mismatch.
    #[test]
    fn require_roster_matches_catches_every_mismatch() {
        let (_n1, pk1) = make_pubkey(1);
        let (_n2, pk2) = make_pubkey(2);
        let (_n3, pk3) = make_pubkey(3);

        let mut by_index = BTreeMap::new();
        by_index.insert(1, pk1);
        by_index.insert(2, pk2);
        by_index.insert(3, pk3);
        let roster = DkgRoster {
            threshold: 2,
            participants: 3,
            by_index,
            group_id: [0u8; 32],
        };

        let ident1 = make_identity_keys(1);

        // Correct config passes.
        require_roster_matches(&roster, &ident1, 2, 3, 1).unwrap();

        // Threshold mismatch refused.
        assert!(require_roster_matches(&roster, &ident1, 3, 3, 1).is_err());
        // Participants mismatch refused.
        assert!(require_roster_matches(&roster, &ident1, 2, 5, 1).is_err());
        // Wrong index for this identity: identity 1 claims index 2.
        assert!(require_roster_matches(&roster, &ident1, 2, 3, 2).is_err());
        // Out-of-range index refused.
        assert!(require_roster_matches(&roster, &ident1, 2, 3, 42).is_err());
    }

    /// #674: `DkgRoster::authenticates` is the single audited author-binding
    /// gate all four intake paths (hardware/software x round1/round2) funnel
    /// through, so cover its accept/reject branches directly.
    #[test]
    fn authenticates_binds_author_to_the_roster_pinned_index() {
        let (_n1, pk1) = make_pubkey(1);
        let (_n2, pk2) = make_pubkey(2);
        let (_n3, pk3) = make_pubkey(3);
        let mut by_index = BTreeMap::new();
        by_index.insert(1, pk1);
        by_index.insert(2, pk2);
        let roster = DkgRoster {
            threshold: 2,
            participants: 2,
            by_index,
            group_id: [0u8; 32],
        };

        // The pinned pubkey for its own index is accepted.
        assert!(roster.authenticates(1, &pk1, "round 1 event"));
        assert!(roster.authenticates(2, &pk2, "round 2 share"));
        // A roster member authoring for a DIFFERENT index is rejected: a relay
        // writer cannot make participant 2's key speak for index 1.
        assert!(!roster.authenticates(1, &pk2, "round 1 event"));
        // A pubkey not on the roster at all is rejected.
        assert!(!roster.authenticates(2, &pk3, "round 2 share"));
        // An index with no roster entry is rejected (unroster'd sender_index).
        assert!(!roster.authenticates(9, &pk1, "round 1 event"));
    }

    /// #674: `frost_group_id` is the single source of truth shared by
    /// group-create and roster verification, so pin its exact bytes against an
    /// independent inline reference. If either caller drifts, this fails.
    #[test]
    fn frost_group_id_matches_reference() {
        let (npub1, _) = make_pubkey(1);
        let (npub2, _) = make_pubkey(2);
        let (npub3, _) = make_pubkey(3);
        let name = "test-group";
        let npubs = vec![npub1, npub2, npub3];

        // Reference: reproduce the preimage inline, independent of the impl.
        let expected = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"frost-group-id-v3");
            h.update((name.len() as u32).to_be_bytes());
            h.update(name.as_bytes());
            h.update([2u8]);
            h.update([3u8]);
            h.update((npubs.len() as u32).to_be_bytes());
            for n in &npubs {
                // Mirror the canonicalization the hash performs: a pubkey is
                // hashed in its bech32 form whatever encoding it arrived in.
                let c = PublicKey::parse(n).unwrap().to_bech32().unwrap();
                h.update((c.len() as u32).to_be_bytes());
                h.update(c.as_bytes());
            }
            <[u8; 32]>::from(h.finalize())
        };
        assert_eq!(frost_group_id(name, 2, 3, &npubs), expected);
    }

    /// A CLI roster written in bech32 and a mobile roster written in hex
    /// describe the same group, so they must derive the same id. Before
    /// canonicalization they did not, and the two sides silently landed on
    /// different `d`-tag channels and never met.
    #[test]
    fn group_id_is_independent_of_pubkey_encoding() {
        let (_, pk1) = make_pubkey(1);
        let (_, pk2) = make_pubkey(2);
        // `make_pubkey` hands back hex, so bech32 has to be produced explicitly
        // here; comparing hex against hex would pass without canonicalization
        // and prove nothing.
        let hex = vec![pk1.to_hex(), pk2.to_hex()];
        let bech32 = vec![pk1.to_bech32().unwrap(), pk2.to_bech32().unwrap()];
        assert_ne!(hex, bech32, "fixture must actually differ in encoding");
        assert_eq!(
            frost_group_id("g", 2, 2, &bech32),
            frost_group_id("g", 2, 2, &hex)
        );
    }

    fn ev_of_kind(kind: u16, seed: u8, d: &str) -> Event {
        let keys = make_identity_keys(seed);
        EventBuilder::new(Kind::Custom(kind), "x")
            .tag(Tag::custom(TagKind::custom("d"), vec![d.to_string()]))
            .sign_with_keys(&keys)
            .unwrap()
    }

    /// Events for another round must not consume this round's budget. Earlier
    /// subscriptions are never closed, so kind-21102 traffic keeps arriving
    /// during round 2; buffering it would starve the round in progress.
    #[test]
    fn buffer_rejects_events_outside_the_current_filter() {
        let t = ClientTransport::new(Client::new(make_identity_keys(9)));
        let filter = Filter::new()
            .kind(Kind::Custom(DKG_KIND_ROUND2))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), "chan");

        t.buffer(&filter, ev_of_kind(DKG_KIND_ROUND1, 1, "chan"));
        assert!(t.matching(&filter).is_empty(), "wrong kind was buffered");

        t.buffer(&filter, ev_of_kind(DKG_KIND_ROUND2, 2, "other-chan"));
        assert!(t.matching(&filter).is_empty(), "wrong channel was buffered");

        let good = ev_of_kind(DKG_KIND_ROUND2, 3, "chan");
        t.buffer(&filter, good.clone());
        assert_eq!(t.matching(&filter).len(), 1, "matching event was dropped");

        // Exact repeats collapse.
        t.buffer(&filter, good);
        assert_eq!(t.matching(&filter).len(), 1, "duplicate id was buffered");
    }

    /// Moving to the next round drops the previous round's events. Without this
    /// the buffer only grows: peers republish with a fresh timestamp each poll,
    /// so id-dedup cannot collapse the repeats.
    #[test]
    fn retarget_clears_the_previous_round() {
        let t = ClientTransport::new(Client::new(make_identity_keys(10)));
        let r1 = Filter::new()
            .kind(Kind::Custom(DKG_KIND_ROUND1))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), "chan");
        let r2 = Filter::new()
            .kind(Kind::Custom(DKG_KIND_ROUND2))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), "chan");

        t.retarget(&r1);
        t.buffer(&r1, ev_of_kind(DKG_KIND_ROUND1, 1, "chan"));
        assert_eq!(t.matching(&r1).len(), 1);

        t.retarget(&r2);
        assert!(
            t.seen.lock().unwrap().is_empty(),
            "round 1 events survived into round 2"
        );

        // Re-targeting the same filter must NOT clear, or every poll would
        // discard what the round has collected so far.
        t.buffer(&r2, ev_of_kind(DKG_KIND_ROUND2, 2, "chan"));
        t.retarget(&r2);
        assert_eq!(t.matching(&r2).len(), 1, "same-filter retarget cleared");
    }

    /// A frozen vector over fixed inputs. The neighbouring reference test
    /// recomputes the preimage with the same rules as the implementation, so it
    /// silently follows any future change; this one does not. If it fails, the
    /// group id wire format changed and the domain tag must be bumped, because
    /// every published roster binds to this hash.
    #[test]
    fn frost_group_id_is_frozen() {
        let (n1, _) = make_pubkey(1);
        let (n2, _) = make_pubkey(2);
        assert_eq!(
            hex::encode(frost_group_id("frozen", 2, 2, &[n1, n2])),
            "4c476c3803a7c6b8669849756961f5832deb99075a38b6c20aa2d232aba90885",
            "group id preimage changed; bump the domain tag and update this vector"
        );
    }

    /// The v1 preimage concatenated variable-length fields with no delimiter, so
    /// a name could absorb the head of the first pubkey and two different groups
    /// could share an id (and therefore a roster binding). Length prefixes make
    /// the preimage unambiguous.
    #[test]
    fn group_id_is_unambiguous_across_field_boundaries() {
        let a = frost_group_id("ab", 2, 2, &["c".to_string(), "d".to_string()]);
        let b = frost_group_id("a", 2, 2, &["bc".to_string(), "d".to_string()]);
        assert_ne!(
            a, b,
            "a name must not be able to absorb the start of the first pubkey"
        );
    }

    /// Order of npubs matters for the hash (index order): swapping two
    /// participants must change the group_id.
    #[test]
    fn group_id_hash_is_order_sensitive() {
        let (a, _) = make_pubkey(1);
        let (b, _) = make_pubkey(2);
        let id_ab = frost_group_id("g", 2, 2, &[a.clone(), b.clone()]);
        let id_ba = frost_group_id("g", 2, 2, &[b, a]);
        assert_ne!(id_ab, id_ba);
    }

    /// Build a kind-21101 announcement mirroring `cmd_frost_network_group_create`'s
    /// tag layout, signed by an arbitrary key (the roster binds on the hash,
    /// not on who signed the announcement). `d_tag_override` lets a test forge
    /// the `d` tag while leaving the p-tags honest.
    fn build_announcement(
        name: &str,
        threshold: u8,
        participants: u8,
        npubs: &[String],
        d_tag_override: Option<&str>,
    ) -> Event {
        let group_id_hex = hex::encode(frost_group_id(name, threshold, participants, npubs));
        let d_tag = d_tag_override.unwrap_or(&group_id_hex).to_string();
        let mut tags = vec![
            Tag::custom(TagKind::custom("d"), vec![d_tag]),
            Tag::custom(TagKind::custom("threshold"), vec![threshold.to_string()]),
            Tag::custom(
                TagKind::custom("participants"),
                vec![participants.to_string()],
            ),
        ];
        for (i, npub) in npubs.iter().enumerate() {
            tags.push(Tag::custom(
                TagKind::custom("p"),
                vec![npub.clone(), String::new(), (i + 1).to_string()],
            ));
        }
        let content = serde_json::json!({ "name": name, "description": "x" }).to_string();
        let mut builder = EventBuilder::new(Kind::Custom(DKG_KIND_ANNOUNCE), &content);
        for tag in tags {
            builder = builder.tag(tag);
        }
        builder.sign_with_keys(&make_identity_keys(0x42)).unwrap()
    }

    /// #674: an honest announcement parses into a roster that hash-binds to its
    /// own `d` tag.
    #[test]
    fn parse_roster_accepts_honest_announcement() {
        let (n1, pk1) = make_pubkey(1);
        let (n2, pk2) = make_pubkey(2);
        let npubs = vec![n1, n2];
        let group_id = hex::encode(frost_group_id("g", 2, 2, &npubs));
        let ev = build_announcement("g", 2, 2, &npubs, None);

        let roster = parse_roster_from_event(&ev, &group_id).unwrap();
        assert_eq!(roster.threshold, 2);
        assert_eq!(roster.participants, 2);
        assert_eq!(*roster.expected_pubkey(1).unwrap(), pk1);
        assert_eq!(*roster.expected_pubkey(2).unwrap(), pk2);
    }

    /// #674: a decoy announcement whose p-tags do not hash to the queried `d`
    /// tag is rejected (the relay-writer roster-substitution the fix closes).
    #[test]
    fn parse_roster_rejects_hash_mismatch() {
        let (n1, _) = make_pubkey(1);
        let (n2, _) = make_pubkey(2);
        // Honest roster, but the `d` tag claims a different group's id.
        let honest = vec![n1, n2];
        let other = vec![make_pubkey(7).0, make_pubkey(8).0];
        let queried = hex::encode(frost_group_id("g", 2, 2, &other));
        let ev = build_announcement("g", 2, 2, &honest, Some(&queried));

        assert!(parse_roster_from_event(&ev, &queried).is_err());
    }

    /// #674: a duplicate p-tag for the same index is refused (ambiguous roster).
    #[test]
    fn parse_roster_rejects_duplicate_index() {
        let (n1, _) = make_pubkey(1);
        let (n2, _) = make_pubkey(2);
        let npubs = vec![n1.clone(), n2];
        let group_id = hex::encode(frost_group_id("g", 2, 2, &npubs));
        let ev = build_announcement("g", 2, 2, &npubs, Some(&group_id));
        // Append a second p-tag reusing index 1.
        let mut tags: Vec<Tag> = ev.tags.iter().cloned().collect();
        tags.push(Tag::custom(
            TagKind::custom("p"),
            vec![n1, String::new(), "1".to_string()],
        ));
        let mut builder = EventBuilder::new(Kind::Custom(DKG_KIND_ANNOUNCE), &ev.content);
        for tag in tags {
            builder = builder.tag(tag);
        }
        let ev = builder.sign_with_keys(&make_identity_keys(0x42)).unwrap();

        assert!(parse_roster_from_event(&ev, &group_id).is_err());
    }

    /// One key listed at two distinct indices must be refused. Such a roster
    /// hash-binds correctly and authenticates, but it hands the holder of the
    /// repeated key two of the n shares, making a published "2-of-3" spendable
    /// by that party alone. The announcement is attacker-supplied, so this has
    /// to be enforced here on the verifying side, not only where we mint a
    /// group.
    #[test]
    fn parse_roster_rejects_one_pubkey_at_two_indices() {
        let (n1, _) = make_pubkey(1);
        // Both participants are the same key, at indices 1 and 2.
        let npubs = vec![n1.clone(), n1];
        let group_id = hex::encode(frost_group_id("g", 2, 2, &npubs));
        let ev = build_announcement("g", 2, 2, &npubs, Some(&group_id));

        let err = parse_roster_from_event(&ev, &group_id)
            .expect_err("a roster repeating one pubkey must be rejected");
        assert!(
            err.to_string().contains("distinct key"),
            "unexpected error: {err}"
        );
    }

    /// #674: too few p-tags for the claimed `participants` (a short roster) is
    /// refused by the count check.
    #[test]
    fn parse_roster_rejects_short_count() {
        let (n1, _) = make_pubkey(1);
        // Claim 2 participants but publish only index 1.
        let one = vec![n1];
        let ev = build_announcement("g", 2, 2, &one, Some("deadbeef"));
        assert!(parse_roster_from_event(&ev, "deadbeef").is_err());
    }

    /// #674: a roster whose p-tag count matches `participants` but skips an
    /// index (e.g. {1, 3} for participants=2) is refused by the hole check,
    /// not accepted as a partial roster.
    #[test]
    fn parse_roster_rejects_hole() {
        let (n1, _) = make_pubkey(1);
        let (n3, _) = make_pubkey(3);
        let tags = vec![
            Tag::custom(TagKind::custom("d"), vec!["deadbeef".to_string()]),
            Tag::custom(TagKind::custom("threshold"), vec!["2".to_string()]),
            Tag::custom(TagKind::custom("participants"), vec!["2".to_string()]),
            Tag::custom(
                TagKind::custom("p"),
                vec![n1, String::new(), "1".to_string()],
            ),
            Tag::custom(
                TagKind::custom("p"),
                vec![n3, String::new(), "3".to_string()],
            ),
        ];
        let content = serde_json::json!({ "name": "g", "description": "x" }).to_string();
        let mut builder = EventBuilder::new(Kind::Custom(DKG_KIND_ANNOUNCE), &content);
        for tag in tags {
            builder = builder.tag(tag);
        }
        let ev = builder.sign_with_keys(&make_identity_keys(0x42)).unwrap();
        assert!(parse_roster_from_event(&ev, "deadbeef").is_err());
    }

    /// DkgRoster::expected_pubkey refuses out-of-range indexes cleanly.
    #[test]
    fn expected_pubkey_refuses_out_of_range() {
        let (_, pk) = make_pubkey(5);
        let mut by_index = BTreeMap::new();
        by_index.insert(1, pk);
        let roster = DkgRoster {
            threshold: 2,
            participants: 1,
            by_index,
            group_id: [0u8; 32],
        };
        assert!(roster.expected_pubkey(1).is_ok());
        assert!(roster.expected_pubkey(2).is_err());
    }

    #[test]
    fn group_key_confirmation_accepts_matching_and_counts_each_peer_once() {
        let ours = "aabb";
        let mut seen = HashSet::new();
        // A matching peer is counted once.
        assert!(accept_group_key_confirmation(ours, 2, "aabb", &mut seen).unwrap());
        // The same peer confirming again is not double-counted.
        assert!(!accept_group_key_confirmation(ours, 2, "aabb", &mut seen).unwrap());
        // A different peer is counted.
        assert!(accept_group_key_confirmation(ours, 3, "aabb", &mut seen).unwrap());
        assert_eq!(seen.len(), 2);
        // Surrounding whitespace in the wire content does not cause a false abort.
        assert!(accept_group_key_confirmation(ours, 4, "  aabb\n", &mut seen).unwrap());
    }

    #[test]
    fn group_key_confirmation_aborts_on_divergent_key() {
        let ours = "aabb";
        let mut seen = HashSet::new();
        // A peer that derived a different transcript is an equivocation: abort.
        assert!(accept_group_key_confirmation(ours, 2, "ccdd", &mut seen).is_err());
        // The divergent peer is not counted as confirmed.
        assert!(seen.is_empty());
    }

    /// `(group_id, roster_by_index, round1_pkgs_by_index, group_pubkey)`.
    type TranscriptFixture = (
        [u8; 32],
        BTreeMap<u16, PublicKey>,
        BTreeMap<u16, Vec<u8>>,
        [u8; 32],
    );

    fn transcript_fixture() -> TranscriptFixture {
        let (_, pk1) = make_pubkey(1);
        let (_, pk2) = make_pubkey(2);
        let mut roster = BTreeMap::new();
        roster.insert(1, pk1);
        roster.insert(2, pk2);
        let mut pkgs = BTreeMap::new();
        pkgs.insert(1u16, vec![0xaa; 40]);
        pkgs.insert(2u16, vec![0xbb; 40]);
        ([7u8; 32], roster, pkgs, [9u8; 32])
    }

    /// §5: the transcript pins its exact bytes against an independent inline
    /// reference. If the field order or framing drifts, this fails.
    #[test]
    fn dkg_transcript_matches_reference() {
        let (group_id, roster, pkgs, group_pubkey) = transcript_fixture();
        let got = dkg_transcript(&group_id, 2, 2, &roster, &pkgs, &group_pubkey).unwrap();

        let expected = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"keep-frost-dkg-transcript-v1");
            h.update(group_id);
            h.update(2u16.to_be_bytes());
            h.update(2u16.to_be_bytes());
            for idx in 1..=2u16 {
                h.update(idx.to_be_bytes());
                h.update(roster.get(&idx).unwrap().as_bytes());
            }
            for idx in 1..=2u16 {
                h.update(Sha256::digest(pkgs.get(&idx).unwrap()));
            }
            h.update(group_pubkey);
            <[u8; 32]>::from(h.finalize())
        };
        assert_eq!(got, expected);
    }

    /// §5: same group key but a DIFFERENT round-1 package changes the transcript.
    /// This is the same-key equivocation the bare group-key compare missed.
    #[test]
    fn dkg_transcript_detects_same_key_round1_divergence() {
        let (group_id, roster, pkgs, group_pubkey) = transcript_fixture();
        let base = dkg_transcript(&group_id, 2, 2, &roster, &pkgs, &group_pubkey).unwrap();

        let mut other = pkgs.clone();
        other.insert(2u16, vec![0xcc; 40]);
        let divergent = dkg_transcript(&group_id, 2, 2, &roster, &other, &group_pubkey).unwrap();
        assert_ne!(base, divergent);
    }

    /// Build a 2-of-2 roster and a matching certificate whose two confirmations
    /// are signed by the roster-pinned keys over `transcript`. Returned with the
    /// roster so tests can tamper with individual confirmations.
    fn cert_fixture(transcript: [u8; 32]) -> (DkgRoster, DkgCertificate) {
        let k1 = make_identity_keys(1);
        let k2 = make_identity_keys(2);
        let mut by_index = BTreeMap::new();
        by_index.insert(1u16, k1.public_key());
        by_index.insert(2u16, k2.public_key());
        let roster = DkgRoster {
            threshold: 2,
            participants: 2,
            by_index,
            group_id: [0u8; 32],
        };
        let hex = hex::encode(transcript);
        let sign = |keys: &Keys| {
            EventBuilder::new(Kind::Custom(DKG_KIND_CONFIRM), &hex)
                .sign_with_keys(keys)
                .unwrap()
        };
        let mut confirmations = BTreeMap::new();
        confirmations.insert(1u16, sign(&k1));
        confirmations.insert(2u16, sign(&k2));
        (
            roster,
            DkgCertificate {
                transcript,
                confirmations,
            },
        )
    }

    /// §6: a certificate carrying all n roster-signed confirmations over the
    /// same transcript verifies — the transferable success case.
    #[test]
    fn certificate_verifies_full_roster_agreement() {
        let (roster, cert) = cert_fixture([0x11; 32]);
        cert.verify(&roster).unwrap();
    }

    /// §6: a missing confirmation (a peer that never signed) is not a complete
    /// certificate, so verification fails rather than presenting partial CertEq.
    #[test]
    fn certificate_rejects_missing_confirmation() {
        let (roster, mut cert) = cert_fixture([0x22; 32]);
        cert.confirmations.remove(&2);
        assert!(cert.verify(&roster).is_err());
    }

    /// §6: a confirmation signed by a key that is not the roster-pinned one for
    /// its index is rejected — a presenter cannot forge agreement from a
    /// non-member (or from the wrong member) to convince a timed-out peer.
    #[test]
    fn certificate_rejects_wrong_author() {
        let transcript = [0x33; 32];
        let (roster, mut cert) = cert_fixture(transcript);
        // Re-sign index 2's confirmation with a non-rostered key.
        let rogue = make_identity_keys(9);
        cert.confirmations.insert(
            2,
            EventBuilder::new(Kind::Custom(DKG_KIND_CONFIRM), hex::encode(transcript))
                .sign_with_keys(&rogue)
                .unwrap(),
        );
        assert!(cert.verify(&roster).is_err());
    }

    /// §6: a confirmation over a DIFFERENT transcript than the certificate's is
    /// rejected — the whole point is all n signed the *identical* transcript.
    #[test]
    fn certificate_rejects_divergent_transcript() {
        let (roster, mut cert) = cert_fixture([0x44; 32]);
        let k2 = make_identity_keys(2);
        cert.confirmations.insert(
            2,
            EventBuilder::new(Kind::Custom(DKG_KIND_CONFIRM), hex::encode([0xaa; 32]))
                .sign_with_keys(&k2)
                .unwrap(),
        );
        assert!(cert.verify(&roster).is_err());
    }

    /// §5: a missing round-1 package for any index fails closed rather than
    /// hashing over a partial set.
    #[test]
    fn dkg_transcript_fails_on_missing_round1_package() {
        let (group_id, roster, pkgs, group_pubkey) = transcript_fixture();
        let mut short = pkgs.clone();
        short.remove(&2);
        assert!(dkg_transcript(&group_id, 2, 2, &roster, &short, &group_pubkey).is_err());
    }

    // ---- Phase 5: in-memory pipeline over a fake DkgTransport (keep-xaj) ----

    use std::sync::{Arc, Mutex as StdMutex};

    /// A shared in-memory relay for CI: every participant publishes to and reads
    /// from one event log, so `run_software_dkg` runs to completion without a
    /// live relay (§4 "transport-injected so it is unit-testable"). Filtering
    /// reuses nostr's own `match_event`, so the kind/`#d` scoping the coordinator
    /// relies on behaves as it would on a real relay.
    #[derive(Clone, Default)]
    struct MeshBus {
        events: Arc<StdMutex<Vec<Event>>>,
    }

    impl MeshBus {
        /// Seed an event that is not produced by any honest run (e.g. an
        /// impostor's forged share) so every fetch observes it.
        fn preload(&self, ev: Event) {
            self.events.lock().unwrap().push(ev);
        }
    }

    /// One participant's view of the shared [`MeshBus`].
    struct MeshTransport {
        bus: MeshBus,
    }

    impl DkgTransport for MeshTransport {
        fn send_event<'a>(&'a self, event: &'a Event) -> DkgBoxFuture<'a, Result<()>> {
            let event = event.clone();
            Box::pin(async move {
                self.bus.events.lock().unwrap().push(event);
                Ok(())
            })
        }

        fn fetch_events(
            &self,
            filter: Filter,
            _timeout: Duration,
        ) -> DkgBoxFuture<'_, Result<Vec<Event>>> {
            Box::pin(async move {
                let events = self.bus.events.lock().unwrap();
                Ok(events
                    .iter()
                    .filter(|ev| filter.match_event(ev, MatchEventOptions::new()))
                    .cloned()
                    .collect())
            })
        }
    }

    struct NoopProgress;
    impl DkgProgress for NoopProgress {
        fn phase(&self, _phase: DkgPhase) {}
    }

    /// One roster key per 1-indexed participant. The pubkeys are what the roster
    /// pins, so each running session signs with the key its index expects.
    fn mesh_keys(participants: u16) -> Vec<Keys> {
        (1..=participants)
            .map(|i| make_identity_keys(0x30 + i as u8))
            .collect()
    }

    fn mesh_roster(keys: &[Keys], threshold: u8, group_id: [u8; 32]) -> DkgRoster {
        let mut by_index = BTreeMap::new();
        for (i, k) in keys.iter().enumerate() {
            by_index.insert((i + 1) as u16, k.public_key());
        }
        DkgRoster {
            threshold,
            participants: keys.len() as u8,
            by_index,
            group_id,
        }
    }

    /// Drive one participant's full `run_software_dkg` over a shared bus.
    async fn run_party(
        bus: &MeshBus,
        keys: &Keys,
        roster: &DkgRoster,
        group: &str,
        our_index: u16,
        timeout: Duration,
    ) -> Result<DkgOutcome> {
        let mut session = SoftwareDkgSession::init(
            roster.threshold as u16,
            roster.participants as u16,
            our_index,
        )
        .unwrap();
        let transport = MeshTransport { bus: bus.clone() };
        let cancel = AtomicBool::new(false);
        let progress = NoopProgress;
        run_software_dkg(
            &mut session,
            &transport,
            keys,
            roster,
            group,
            our_index,
            timeout,
            &cancel,
            &progress,
        )
        .await
    }

    /// A 2-of-2 DKG runs end to end over the fake transport: both parties agree
    /// on the group key, and each retains a CertEq certificate that verifies
    /// against the shared roster (§6). This is the pipeline backbone the fault
    /// cases below perturb.
    #[tokio::test(start_paused = true)]
    async fn full_pipeline_two_party_completes_and_certificate_verifies() {
        let keys = mesh_keys(2);
        let roster = mesh_roster(&keys, 2, [0x5a; 32]);
        let bus = MeshBus::default();
        let to = Duration::from_secs(300);

        let (r1, r2) = tokio::join!(
            run_party(&bus, &keys[0], &roster, "g", 1, to),
            run_party(&bus, &keys[1], &roster, "g", 2, to),
        );
        let (o1, o2) = (r1.unwrap(), r2.unwrap());

        assert_eq!(o1.result.group_pubkey, o2.result.group_pubkey);
        assert_eq!(o1.certificate.transcript, o2.certificate.transcript);
        // Each side collected both signatures over the identical transcript, so
        // either certificate is transferable to a peer that never confirmed.
        o1.certificate.verify(&roster).unwrap();
        o2.certificate.verify(&roster).unwrap();
        assert_eq!(o1.certificate.confirmations.len(), 2);
    }

    /// Phase 5(a): a round-2 share is per-recipient encrypted to the recipient's
    /// roster key (Blocker 1 / §2 G1), so a non-recipient participant cannot
    /// decrypt it even though the ciphertext is broadcast on the shared topic.
    #[tokio::test(start_paused = true)]
    async fn round2_share_is_readable_only_by_its_recipient() {
        let keys = mesh_keys(3);
        let roster = mesh_roster(&keys, 2, [0x5b; 32]);
        let bus = MeshBus::default();
        let to = Duration::from_secs(300);

        let (r1, r2, r3) = tokio::join!(
            run_party(&bus, &keys[0], &roster, "g", 1, to),
            run_party(&bus, &keys[1], &roster, "g", 2, to),
            run_party(&bus, &keys[2], &roster, "g", 3, to),
        );
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();

        // Pull party 1's round-2 share addressed to party 2 off the wire.
        let events = bus.events.lock().unwrap();
        let share = events
            .iter()
            .find(|ev| {
                ev.kind == Kind::Custom(DKG_KIND_ROUND2)
                    && ev.pubkey == keys[0].public_key()
                    && u16_tag(ev, "recipient_index") == Some(2)
            })
            .expect("party 1 -> party 2 round-2 share");

        // The intended recipient (party 2) recovers the plaintext share.
        assert!(
            nip44::decrypt(keys[1].secret_key(), &keys[0].public_key(), &share.content).is_ok()
        );
        // A rostered non-recipient (party 3) cannot: the share is encrypted to
        // party 2's key, not readable by all as the pre-fix broadcast was.
        assert!(
            nip44::decrypt(keys[2].secret_key(), &keys[0].public_key(), &share.content).is_err()
        );
    }

    /// Phase 5(b): an equivocating insider makes two honest peers derive
    /// divergent §5 transcripts (here via a divergent roster binding, which the
    /// transcript folds in exactly as it folds each round-1 commitment). The
    /// full run must abort at the confirmation step rather than finalize into an
    /// inconsistent group — the equivocation Blocker 2 closes.
    #[tokio::test(start_paused = true)]
    async fn divergent_transcript_aborts_the_full_run() {
        let keys = mesh_keys(2);
        // Same pinned pubkeys (so author checks pass and the rounds complete)
        // but a divergent binding, so the two confirmations sign different
        // transcripts — the same divergence a same-key round-1 equivocation
        // produces downstream.
        let roster_a = mesh_roster(&keys, 2, [0x11; 32]);
        let roster_b = mesh_roster(&keys, 2, [0x22; 32]);
        let bus = MeshBus::default();
        let to = Duration::from_secs(300);

        let (r1, r2) = tokio::join!(
            run_party(&bus, &keys[0], &roster_a, "g", 1, to),
            run_party(&bus, &keys[1], &roster_b, "g", 2, to),
        );
        // Neither side may believe it finalized a live group the other joined.
        assert!(r1.is_err(), "party 1 must abort on a divergent transcript");
        assert!(r2.is_err(), "party 2 must abort on a divergent transcript");
    }

    /// Phase 5(c): a round-2 event authored by a key that is not on the roster
    /// is rejected on the cheap `sender_index`/author check before any NIP-44
    /// ECDH (§7 "author check before decrypt"), so a flooded impostor cannot
    /// derail the run. The honest 2-of-2 still completes on the genuine share.
    #[tokio::test(start_paused = true)]
    async fn non_roster_round2_author_is_rejected_before_decrypt() {
        let keys = mesh_keys(2);
        let roster = mesh_roster(&keys, 2, [0x5c; 32]);
        let bus = MeshBus::default();
        let to = Duration::from_secs(300);

        // An off-roster key forges a round-2 share to party 1, claiming to be
        // participant 2. The ciphertext is validly addressed to party 1, so only
        // the roster author gate — not a decrypt failure — can reject it.
        let impostor = make_identity_keys(0x99);
        let ciphertext = nip44::encrypt(
            impostor.secret_key(),
            &keys[0].public_key(),
            "{\"software_dkg_version\":1,\"sender_index\":2,\"package_hex\":\"00\"}",
            nip44::Version::default(),
        )
        .unwrap();
        let forged = EventBuilder::new(Kind::Custom(DKG_KIND_ROUND2), &ciphertext)
            .tag(Tag::custom(TagKind::custom("d"), vec!["g".to_string()]))
            .tag(Tag::custom(
                TagKind::custom("sender_index"),
                vec!["2".to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("dkg_mode"),
                vec![DKG_MODE_SOFTWARE_V1.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("recipient_index"),
                vec!["1".to_string()],
            ))
            .sign_with_keys(&impostor)
            .unwrap();
        bus.preload(forged);

        let (r1, r2) = tokio::join!(
            run_party(&bus, &keys[0], &roster, "g", 1, to),
            run_party(&bus, &keys[1], &roster, "g", 2, to),
        );
        let (o1, o2) = (r1.unwrap(), r2.unwrap());
        // The forged share was ignored; the run finalized on the honest one.
        assert_eq!(o1.result.group_pubkey, o2.result.group_pubkey);
    }

    /// Phase 5(d): the CertEq certificate a finalized device retains is
    /// transferable (§6 Conditional Agreement) — a peer that missed the live
    /// confirmation verifies it against the roster it already holds and accepts
    /// the group, trusting the signatures rather than the presenter. A partial
    /// presentation (a dropped confirmation) is refused.
    #[tokio::test(start_paused = true)]
    async fn certificate_convinces_a_peer_that_missed_confirmation() {
        let keys = mesh_keys(3);
        let roster = mesh_roster(&keys, 2, [0x5d; 32]);
        let bus = MeshBus::default();
        let to = Duration::from_secs(300);

        let (r1, r2, r3) = tokio::join!(
            run_party(&bus, &keys[0], &roster, "g", 1, to),
            run_party(&bus, &keys[1], &roster, "g", 2, to),
            run_party(&bus, &keys[2], &roster, "g", 3, to),
        );
        let cert = r1.unwrap().certificate;
        r2.unwrap();
        r3.unwrap();

        // A peer holding only the (identical) roster finalizes from the
        // presented certificate without having collected any confirmation live.
        cert.verify(&roster).unwrap();
        assert_eq!(cert.confirmations.len(), 3);

        // A certificate missing a signature is not Conditional Agreement and is
        // refused, so a presenter cannot pass off partial CertEq.
        let mut partial = cert.clone();
        partial.confirmations.remove(&3);
        assert!(partial.verify(&roster).is_err());
    }
}
