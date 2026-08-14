// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Shared DKG coordination primitives, extracted from `keep-cli` so the CLI and
//! keep-mobile drive one audited implementation instead of two (see
//! `docs/DKG_CEREMONY.md`). This module currently holds the roster/authentication
//! layer — the signed kind-21101 group announcement, the `index → pubkey` roster
//! it pins, the author-binding intake gate, the canonical `frost_group_id`, and
//! the equivocation-confirmation decision. The round-1/2/confirm coordination
//! loops move here in later phases.
//!
//! Errors flow as `keep_core::error::Result` (the type the extracted code already
//! used); `FrostNetError` wraps `KeepError` via `#[from]`, so keep-frost-net
//! callers can `?` these directly.

use std::collections::{BTreeMap, HashSet};

use nostr_sdk::prelude::*;

use keep_core::error::{FrostError, KeepError, NetworkError, Result};

/// Upper bound on distinct relay events tracked per software-DKG polling loop.
/// A DKG topic only ever carries a handful of packages; a set this large means
/// the relay is flooding junk, so we abort rather than grow memory unbounded
/// for the timeout window.
pub const MAX_DKG_EVENTS_SEEN: usize = 8192;

/// Signed group announcement (identity/roster). Public relay data.
pub const DKG_KIND_ANNOUNCE: u16 = 21101;
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

/// Decide one peer's group-key confirmation against our own during the DKG
/// equivocation check. `Ok(true)` when it matches and is a newly-counted peer,
/// `Ok(false)` when that peer was already counted, and `Err` when the peer
/// reports a DIFFERENT group key, which means the relay handed inconsistent
/// round1 packages and the DKG must abort rather than persist a split keyset.
/// Extracted so the equivocation decision is unit-testable without relay I/O.
pub fn accept_group_key_confirmation(
    ours: &str,
    sender_index: u16,
    theirs: &str,
    already_confirmed: &mut HashSet<u16>,
) -> Result<bool> {
    if theirs.trim() != ours {
        return Err(KeepError::FrostErr(FrostError::dkg(format!(
            "participant {sender_index} derived a different group key than ours; aborting DKG \
             (the relay may have equivocated round1 packages)"
        ))));
    }
    Ok(already_confirmed.insert(sender_index))
}

/// Canonical group_id preimage, the single source of truth for the group
/// identifier: `sha256("frost-group-id-v1" || name || [threshold] ||
/// [participants] || each raw pubkey string in 1..=participants order)`.
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
    let mut hasher = Sha256::new();
    hasher.update(b"frost-group-id-v1");
    hasher.update(name.as_bytes());
    hasher.update([threshold]);
    hasher.update([participants]);
    for npub in ordered_npubs {
        hasher.update(npub.as_bytes());
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
    let recomputed = hex::encode(frost_group_id(
        &name,
        threshold,
        participants,
        &ordered_npubs,
    ));
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
            h.update(b"frost-group-id-v1");
            h.update(name.as_bytes());
            h.update([2u8]);
            h.update([3u8]);
            for n in &npubs {
                h.update(n.as_bytes());
            }
            <[u8; 32]>::from(h.finalize())
        };
        assert_eq!(frost_group_id(name, 2, 3, &npubs), expected);
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
        // A peer that derived a different group key is an equivocation: abort.
        assert!(accept_group_key_confirmation(ours, 2, "ccdd", &mut seen).is_err());
        // The divergent peer is not counted as confirmed.
        assert!(seen.is_empty());
    }
}
