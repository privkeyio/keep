// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::{BTreeMap, HashMap, HashSet};

use nostr_sdk::prelude::*;

use keep_core::error::{CryptoError, FrostError, KeepError, NetworkError, Result};
use keep_core::Keep;

use crate::output::Output;
use crate::signer::HardwareSigner;

/// Upper bound on distinct relay events tracked per software-DKG polling loop.
/// A DKG topic only ever carries a handful of packages; a set this large means
/// the relay is flooding junk, so we abort rather than grow memory unbounded
/// for the 300s timeout window.
const MAX_DKG_EVENTS_SEEN: usize = 8192;

/// (index -> npub) roster fetched from a signed kind-21101 group
/// announcement, used to authenticate DKG participants (#674).
///
/// Every DKG event is signed with the participant's identity nsec (the one
/// whose npub appears in the announcement). Round 1 and round 2 intake
/// reject any event whose author does not match the expected npub for its
/// `sender_index`, closing the pre-#674 window where an unauthenticated
/// relay writer could hijack a victim's index (DoS) or, with enough
/// participation, silently join a group as a rogue co-generator.
#[derive(Clone)]
struct DkgRoster {
    threshold: u8,
    participants: u8,
    /// 1-indexed participant number -> announced identity pubkey.
    by_index: BTreeMap<u16, PublicKey>,
}

impl DkgRoster {
    /// Expected identity pubkey for the given 1-indexed participant.
    fn expected_pubkey(&self, index: u16) -> Result<&PublicKey> {
        self.by_index.get(&index).ok_or_else(|| {
            KeepError::FrostErr(FrostError::invalid_config(format!(
                "roster has no entry for participant index {index}"
            )))
        })
    }

    /// #674: the single audited authentication gate for DKG intake. Returns
    /// `true` only when `author` is exactly the npub the roster pins to
    /// `sender_index`; otherwise it warns (with `what` naming the round) and
    /// returns `false` so the caller drops the event. Both rounds on both the
    /// hardware and software paths funnel through here, so a relay writer that
    /// cannot produce the pinned nsec's signature can never speak for an index.
    fn authenticates(
        &self,
        sender_index: u16,
        author: &PublicKey,
        out: &Output,
        what: &str,
    ) -> bool {
        match self.expected_pubkey(sender_index) {
            Ok(expected) if expected == author => true,
            Ok(expected) => {
                out.warn(&format!(
                    "Rejecting {what}: sender_index {sender_index} authored by {author} \
                     but roster expects {expected}"
                ));
                false
            }
            Err(e) => {
                out.warn(&format!(
                    "Ignoring {what} with unroster'd sender_index {sender_index}: {e}"
                ));
                false
            }
        }
    }
}

/// Parse a hex-or-bech32 npub / hex pubkey string into a `nostr_sdk::PublicKey`.
fn parse_pubkey(s: &str) -> Result<PublicKey> {
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
fn accept_group_key_confirmation(
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
/// [participants] || each raw npub string in 1..=participants order)`.
///
/// Both `cmd_frost_network_group_create` (which mints the id) and roster
/// verification (which re-derives it to hash-bind an announcement to its
/// queried `d` tag) MUST call this so the two can never drift: a relay writer
/// who republishes a rogue kind-21101 with the same `d` tag but different
/// p-tags cannot fake a preimage under sha256.
fn frost_group_id(
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
async fn fetch_group_roster(client: &Client, group_id_hex: &str) -> Result<DkgRoster> {
    let filter = Filter::new()
        .kind(Kind::Custom(21101))
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
fn parse_roster_from_event(ev: &Event, group_id_hex: &str) -> Result<DkgRoster> {
    let mut threshold: Option<u8> = None;
    let mut participants: Option<u8> = None;
    // 1-indexed participant -> (identity pubkey, raw npub string as published).
    // The raw string is kept so we can recompute the group_id preimage byte
    // for byte; index order is imposed below when building `ordered_npubs`.
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

/// Load an identity keypair from the Keep vault, converted to
/// `nostr_sdk::Keys` for signing DKG events. Uses the named key when
/// `identity_name` is `Some`; otherwise falls back to the vault's primary.
fn load_identity_keys(keep: &Keep, identity_name: Option<&str>) -> Result<Keys> {
    let slot = if let Some(name) = identity_name {
        keep.keyring().get_by_name(name).ok_or_else(|| {
            KeepError::KeyNotFound(format!(
                "identity key {name:?} not found in vault; add one with `keep import` or omit --identity to use the primary"
            ))
        })?
    } else {
        keep.keyring().get_primary().ok_or_else(|| {
            KeepError::KeyNotFound(
                "vault has no primary identity key; add one with `keep generate` \
                 or pass --identity <name>"
                    .into(),
            )
        })?
    };
    let kp = slot.to_nostr_keypair()?;
    let sk = nostr_sdk::secp256k1::SecretKey::from_slice(kp.secret_bytes()).map_err(|e| {
        KeepError::CryptoErr(CryptoError::invalid_key(format!(
            "identity key is not a valid secp256k1 secret: {e}"
        )))
    })?;
    Ok(Keys::new(sk.into()))
}

/// Verify (threshold, participants) from the signed announcement match the
/// caller's CLI flags, and check our declared `our_index` binds to our
/// identity key in the roster. Fail closed so a peer `(t, n)` mismatch or
/// an operator running under the wrong index surfaces before we produce
/// any round1 material.
fn require_roster_matches(
    roster: &DkgRoster,
    identity: &Keys,
    threshold: u8,
    participants: u8,
    our_index: u8,
) -> Result<()> {
    if roster.threshold != threshold {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "signed group announcement pins threshold={} but --threshold was {threshold}",
            roster.threshold
        ))));
    }
    if roster.participants != participants {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "signed group announcement pins participants={} but --participants was {participants}",
            roster.participants
        ))));
    }
    let expected = roster.expected_pubkey(our_index as u16)?;
    if identity.public_key() != *expected {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "identity npub {} does not match the announced participant at index {our_index} \
             ({}); pass --identity <name> to select the correct vault key",
            identity.public_key(),
            expected,
        ))));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(out))]
pub fn cmd_frost_network_dkg(
    out: &Output,
    group: &str,
    threshold: u8,
    participants: u8,
    our_index: u8,
    relay: &str,
    hardware: Option<&str>,
    vault_path: Option<&std::path::Path>,
    identity_name: Option<&str>,
) -> Result<()> {
    // #674: both paths now require a vault path to load the identity nsec
    // that signs DKG events. Without authentication a relay writer can DoS
    // or (with enough participation) join a group as a rogue co-generator.
    let vault_path = vault_path.ok_or_else(|| {
        KeepError::InvalidInput(
            "keep frost network dkg requires --path <vault> to load an authenticated \
             identity key for signing DKG events (#674)."
                .into(),
        )
    })?;
    match hardware {
        Some(hw) => cmd_frost_network_dkg_hardware(
            out,
            group,
            threshold,
            participants,
            our_index,
            relay,
            hw,
            vault_path,
            identity_name,
        ),
        None => cmd_frost_network_dkg_software(
            out,
            group,
            threshold,
            participants,
            our_index,
            relay,
            vault_path,
            identity_name,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(out))]
fn cmd_frost_network_dkg_hardware(
    out: &Output,
    group: &str,
    threshold: u8,
    participants: u8,
    our_index: u8,
    relay: &str,
    hardware: &str,
    vault_path: &std::path::Path,
    identity_name: Option<&str>,
) -> Result<()> {
    use secrecy::ExposeSecret;

    out.newline();
    out.header("FROST Distributed Key Generation");
    out.field("Group", group);
    out.field("Threshold", &format!("{threshold}-of-{participants}"));
    out.field("Our index", &our_index.to_string());
    out.field("Relay", relay);
    out.field("Hardware", hardware);
    out.field("Vault", &vault_path.display().to_string());
    out.newline();

    if threshold < 2 || threshold > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "must be 2 <= threshold ({threshold}) <= participants ({participants})"
        ))));
    }

    if our_index < 1 || our_index > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_share(format!(
            "index must be 1..={participants}, got {our_index}"
        ))));
    }

    // #674: load our identity nsec from the vault BEFORE the hardware is
    // touched. A stale hardware DKG state (from a prior interrupted run)
    // is much easier to reset than "we already connected to hardware but
    // then errored on missing vault identity".
    let spinner = out.spinner("Opening vault...");
    let mut keep = Keep::open(vault_path)?;
    let password = super::get_password("Enter password")?;
    keep.unlock(password.expose_secret())?;
    let identity = load_identity_keys(&keep, identity_name)?;
    spinner.finish();
    out.field(
        "Identity npub",
        &identity.public_key().to_bech32().unwrap_or_default(),
    );

    let spinner = out.spinner("Connecting to hardware...");
    let mut signer = HardwareSigner::new(hardware)
        .map_err(|e| KeepError::NetworkErr(NetworkError::connection(format!("hardware: {e}"))))?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer.ping().map_err(|e| {
        KeepError::NetworkErr(NetworkError::connection(format!("hardware ping: {e}")))
    })?;
    spinner.finish();
    out.field("Hardware version", &version);

    let spinner = out.spinner("Initializing DKG...");
    signer
        .dkg_init(group, threshold, participants, our_index)
        .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("init: {e}"))))?;
    spinner.finish();

    let spinner = out.spinner("Starting DKG round 1...");
    let round1_data = signer
        .dkg_round1()
        .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("round 1: {e}"))))?;
    spinner.finish();

    let our_package = round1_data.to_json();

    out.success("DKG Round 1 complete");
    out.field("Our package", &our_package);
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    rt.block_on(async {
        let keys = identity.clone();
        let client = Client::new(keys.clone());
        client
            .add_relay(relay)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::relay(e.to_string())))?;
        client.connect().await;

        out.info("Connected to relay");
        out.field(
            "Signer npub",
            &keys.public_key().to_bech32().unwrap_or_default(),
        );
        out.newline();

        // #674: fetch the signed roster and require it to match our CLI
        // args + identity before we emit any DKG material.
        let spinner = out.spinner("Fetching signed group roster...");
        let roster = fetch_group_roster(&client, group).await?;
        spinner.finish();
        require_roster_matches(&roster, &keys, threshold, participants, our_index)?;
        out.success(&format!(
            "Roster verified ({} participants pinned by signed announcement)",
            roster.participants,
        ));
        out.newline();

        let round1_content = serde_json::json!({
            "package": our_package,
            "sender_index": our_index,
        })
        .to_string();

        let round1_event = EventBuilder::new(Kind::Custom(21102), &round1_content)
            .tag(Tag::custom(TagKind::custom("d"), vec![group.to_string()]))
            .tag(Tag::custom(
                TagKind::custom("sender_index"),
                vec![our_index.to_string()],
            ))
            .sign_with_keys(&keys)
            .map_err(|e| KeepError::CryptoErr(CryptoError::invalid_signature(e.to_string())))?;

        let spinner = out.spinner("Publishing round 1 package...");
        client
            .send_event(&round1_event)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::publish(e.to_string())))?;
        spinner.finish();

        let expected_peers = participants - 1;
        out.info(&format!(
            "Waiting for {expected_peers} other round 1 packages..."
        ));

        let filter = Filter::new()
            .kind(Kind::Custom(21102))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());

        let mut received_packages: HashMap<u8, String> = HashMap::new();
        let mut participant_pubkeys: HashMap<u8, PublicKey> = HashMap::new();
        let mut seen_round1: HashSet<EventId> = HashSet::new();
        let timeout = std::time::Duration::from_secs(300);
        let start = std::time::Instant::now();

        while received_packages.len() < expected_peers as usize {
            if start.elapsed() > timeout {
                return Err(KeepError::NetworkErr(NetworkError::timeout(
                    "waiting for peer packages",
                )));
            }

            let events = client
                .fetch_events(filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| KeepError::NetworkErr(NetworkError::request(e.to_string())))?;

            for ev in events.iter() {
                if ev.pubkey == keys.public_key() {
                    continue;
                }
                // Bound decoy-flood work: a hostile relay can spam junk round1
                // events during the 300s window; dedupe so each id is parsed
                // once and abort past a cap so the set cannot grow unbounded
                // (mirrors the software path).
                if !seen_round1.insert(ev.id) {
                    continue;
                }
                if seen_round1.len() > MAX_DKG_EVENTS_SEEN {
                    return Err(KeepError::NetworkErr(NetworkError::request(
                        "too many distinct DKG round1 events; aborting to bound memory".to_string(),
                    )));
                }

                if let Ok(content) = serde_json::from_str::<serde_json::Value>(&ev.content) {
                    let sender_idx = content
                        .get("sender_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u8;

                    if sender_idx > 0
                        && sender_idx <= participants
                        && sender_idx != our_index
                        && !received_packages.contains_key(&sender_idx)
                    {
                        // #674: enforce authenticated participants. An event
                        // claiming `sender_index = k` MUST be signed by the
                        // npub the roster pins to k, otherwise a relay writer
                        // could hijack the index and DoS the group.
                        if !roster.authenticates(
                            sender_idx as u16,
                            &ev.pubkey,
                            out,
                            "round 1 event",
                        ) {
                            continue;
                        }
                        if let Some(pkg) = content.get("package").and_then(|p| p.as_str()) {
                            signer.dkg_round1_peer(sender_idx, pkg).map_err(|e| {
                                KeepError::FrostErr(FrostError::dkg(format!(
                                    "process package from {sender_idx}: {e}"
                                )))
                            })?;

                            received_packages.insert(sender_idx, pkg.to_string());
                            participant_pubkeys.insert(sender_idx, ev.pubkey);
                            out.success(&format!(
                                "Received round 1 package from participant {sender_idx}"
                            ));
                        }
                    }
                }
            }

            if received_packages.len() < expected_peers as usize {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        out.newline();
        out.success("All round 1 packages received");

        let spinner = out.spinner("Generating round 2 shares...");
        let shares_for_others = signer
            .dkg_round2()
            .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("round 2: {e}"))))?;
        spinner.finish();

        for share in &shares_for_others {
            let recipient_pubkey =
                participant_pubkeys
                    .get(&share.recipient_index)
                    .ok_or_else(|| {
                        KeepError::FrostErr(FrostError::unknown_participant(
                            share.recipient_index as u16,
                        ))
                    })?;
            let encrypted_content = nip44::encrypt(
                keys.secret_key(),
                recipient_pubkey,
                serde_json::json!({
                    "sender_index": our_index,
                    "share": share.share,
                })
                .to_string(),
                nip44::Version::default(),
            )
            .map_err(|e| KeepError::CryptoErr(CryptoError::encryption(e.to_string())))?;

            let share_event = EventBuilder::new(Kind::Custom(21103), &encrypted_content)
                .tag(Tag::custom(TagKind::custom("d"), vec![group.to_string()]))
                .tag(Tag::custom(
                    TagKind::custom("sender_index"),
                    vec![our_index.to_string()],
                ))
                .tag(Tag::custom(
                    TagKind::custom("recipient_index"),
                    vec![share.recipient_index.to_string()],
                ))
                .sign_with_keys(&keys)
                .map_err(|e| {
                    KeepError::CryptoErr(CryptoError::invalid_signature(format!(
                        "share event: {e}"
                    )))
                })?;

            client
                .send_event(&share_event)
                .await
                .map_err(|e| KeepError::NetworkErr(NetworkError::publish(format!("share: {e}"))))?;

            out.info(&format!(
                "Published encrypted share for participant {}",
                share.recipient_index
            ));
        }

        out.newline();
        out.info(&format!(
            "Waiting for {} shares from other participants...",
            participants - 1
        ));

        let share_filter = Filter::new()
            .kind(Kind::Custom(21103))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());

        let mut received_from_peers: HashSet<u8> = HashSet::new();
        let mut seen_round2: HashSet<EventId> = HashSet::new();
        let start = std::time::Instant::now();

        while received_from_peers.len() < expected_peers as usize {
            if start.elapsed() > timeout {
                return Err(KeepError::NetworkErr(NetworkError::timeout(
                    "waiting for peer shares",
                )));
            }

            let events = client
                .fetch_events(share_filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| {
                    KeepError::NetworkErr(NetworkError::request(format!("fetch shares: {e}")))
                })?;

            for ev in events.iter() {
                if ev.pubkey == keys.public_key() {
                    continue;
                }
                // Bound decoy-flood work as in round1: dedupe on event id and
                // abort past a cap so a flooded relay cannot grow the set
                // without limit (mirrors the software path).
                if !seen_round2.insert(ev.id) {
                    continue;
                }
                if seen_round2.len() > MAX_DKG_EVENTS_SEEN {
                    return Err(KeepError::NetworkErr(NetworkError::request(
                        "too many distinct DKG round2 events; aborting to bound memory".to_string(),
                    )));
                }

                let recipient_idx_tag = ev.tags.iter().find_map(|t| {
                    let tag = t.as_slice();
                    if tag.first()? == "recipient_index" {
                        tag.get(1).and_then(|s| s.parse::<u8>().ok())
                    } else {
                        None
                    }
                });

                if recipient_idx_tag != Some(our_index) {
                    continue;
                }

                let decrypted = match nip44::decrypt(keys.secret_key(), &ev.pubkey, &ev.content) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                if let Ok(content) = serde_json::from_str::<serde_json::Value>(&decrypted) {
                    let sender_idx = content
                        .get("sender_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u8;

                    if sender_idx > 0
                        && sender_idx <= participants
                        && !received_from_peers.contains(&sender_idx)
                    {
                        // #674: round2 share must also be authored by the
                        // roster-pinned npub for its sender_index.
                        if !roster.authenticates(
                            sender_idx as u16,
                            &ev.pubkey,
                            out,
                            "round 2 share",
                        ) {
                            continue;
                        }
                        if let Some(share_hex) = content.get("share").and_then(|s| s.as_str()) {
                            match signer.dkg_receive_share(sender_idx, share_hex) {
                                Ok(()) => {
                                    received_from_peers.insert(sender_idx);
                                    out.success(&format!(
                                        "Received share from participant {sender_idx}"
                                    ));
                                }
                                Err(e) => {
                                    out.warn(&format!(
                                        "Failed to process share from {sender_idx}: {e}"
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            if received_from_peers.len() < expected_peers as usize {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        out.newline();
        let spinner = out.spinner("Finalizing DKG...");
        let result = signer
            .dkg_finalize()
            .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("finalize: {e}"))))?;
        spinner.finish();

        out.newline();
        out.success("DKG Complete!");
        out.field("Group public key", &result.group_pubkey);
        out.field("Our index", &result.our_index.to_string());
        out.newline();
        out.info("Share has been stored on the hardware device.");
        out.info(&format!(
            "Group '{group}' is now ready for threshold signing."
        ));

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

/// Run software DKG (#454): every step of the FROST-secp256k1-tr protocol
/// happens in this process, and the finalized share is persisted to
/// `vault_path` encrypted under the vault's data key. Peers speak a
/// software-only wire format keyed on `software_dkg_version = 1`; hardware
/// peers do not decode it (and vice versa), so a mixed group DKG fails
/// obviously instead of silently mis-mixing.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(out))]
fn cmd_frost_network_dkg_software(
    out: &Output,
    group: &str,
    threshold: u8,
    participants: u8,
    our_index: u8,
    relay: &str,
    vault_path: &std::path::Path,
    identity_name: Option<&str>,
) -> Result<()> {
    use keep_core::frost::dkg::{SoftwareDkgSession, SoftwareRound1Wire, SoftwareRound2Wire};
    use secrecy::ExposeSecret;
    use zeroize::Zeroizing;

    out.newline();
    out.header("FROST Distributed Key Generation (software)");
    out.field("Group", group);
    out.field("Threshold", &format!("{threshold}-of-{participants}"));
    out.field("Our index", &our_index.to_string());
    out.field("Relay", relay);
    out.field("Vault", &vault_path.display().to_string());
    out.newline();
    out.warn("Software DKG keeps polynomial state in this process's memory for the duration");
    out.warn("of the run. For production keysets prefer `--hardware <device>`; software DKG is");
    out.warn(
        "intended for testing (#436) and users without hardware. See #454 for the trade-offs.",
    );
    out.newline();

    let mut session =
        SoftwareDkgSession::init(threshold as u16, participants as u16, our_index as u16)
            .map_err(|e| KeepError::FrostErr(FrostError::invalid_config(e.to_string())))?;

    // `group` is stored as the share name at finalize and used verbatim as the
    // relay `d` tag every peer filters on, so validate it as-is (no trim, which
    // would diverge from what is published) rather than failing after every
    // network round only for the store to reject it.
    if group.is_empty() || group.chars().count() > 64 {
        return Err(KeepError::FrostErr(FrostError::invalid_config(
            "group name must be 1..=64 characters".to_string(),
        )));
    }

    let spinner = out.spinner("Opening vault...");
    let mut keep = Keep::open(vault_path)?;
    let password = super::get_password("Enter password")?;
    keep.unlock(password.expose_secret())?;
    // #674: load our identity nsec here so a wrong --identity fails BEFORE
    // any DKG state is created; we would otherwise emit our round1 package
    // under an authenticated key that later intake rejects on mismatch.
    let identity = load_identity_keys(&keep, identity_name)?;
    spinner.finish();
    out.field(
        "Identity npub",
        &identity.public_key().to_bech32().unwrap_or_default(),
    );

    let spinner = out.spinner("Generating DKG round 1 package...");
    let our_round1 = session
        .round1()
        .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("round 1: {e}"))))?;
    spinner.finish();
    out.success("Round 1 package generated");
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    rt.block_on(async {
        let keys = identity.clone();
        let client = Client::new(keys.clone());
        client
            .add_relay(relay)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::relay(e.to_string())))?;
        client.connect().await;

        out.info("Connected to relay");
        out.field(
            "Signer npub",
            &keys.public_key().to_bech32().unwrap_or_default(),
        );
        out.newline();

        // #674: fetch the signed roster and require it to match our CLI
        // args + identity before we publish our own round1 package. Fail
        // closed so a wrong --index or a stale --threshold surfaces before
        // co-signers see any DKG material from us.
        let spinner = out.spinner("Fetching signed group roster...");
        let roster = fetch_group_roster(&client, group).await?;
        spinner.finish();
        require_roster_matches(&roster, &keys, threshold, participants, our_index)?;
        out.success(&format!(
            "Roster verified ({} participants pinned by signed announcement)",
            roster.participants,
        ));
        out.newline();

        let round1_content = serde_json::to_string(&our_round1)
            .map_err(|e| KeepError::Runtime(format!("serialize round1: {e}")))?;

        let round1_event = EventBuilder::new(Kind::Custom(21102), &round1_content)
            .tag(Tag::custom(TagKind::custom("d"), vec![group.to_string()]))
            .tag(Tag::custom(
                TagKind::custom("sender_index"),
                vec![our_index.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("dkg_mode"),
                vec!["software_v1".to_string()],
            ))
            .sign_with_keys(&keys)
            .map_err(|e| KeepError::CryptoErr(CryptoError::invalid_signature(e.to_string())))?;

        let spinner = out.spinner("Publishing round 1 package...");
        client
            .send_event(&round1_event)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::publish(e.to_string())))?;
        spinner.finish();

        let expected_peers = participants - 1;
        out.info(&format!(
            "Waiting for {expected_peers} other round 1 packages..."
        ));

        let filter = Filter::new()
            .kind(Kind::Custom(21102))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());

        // Keyed on the u16 wire index (not a truncated u8) so the map cannot
        // alias two participants if the index type ever widens past 255.
        let mut participant_pubkeys: HashMap<u16, PublicKey> = HashMap::new();
        let timeout = std::time::Duration::from_secs(300);
        let start = std::time::Instant::now();
        let mut round1_done = 0u32;
        // Events already examined this round, so a relay re-serving the same
        // event (or a permanently-rejected one) is not reprocessed every poll.
        let mut seen_round1: HashSet<EventId> = HashSet::new();

        while round1_done < expected_peers as u32 {
            if start.elapsed() > timeout {
                return Err(KeepError::NetworkErr(NetworkError::timeout(
                    "waiting for peer round1 packages",
                )));
            }

            let events = client
                .fetch_events(filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| KeepError::NetworkErr(NetworkError::request(e.to_string())))?;

            for ev in events.iter() {
                if ev.pubkey == keys.public_key() {
                    continue;
                }
                if !seen_round1.insert(ev.id) {
                    continue;
                }
                if seen_round1.len() > MAX_DKG_EVENTS_SEEN {
                    return Err(KeepError::NetworkErr(NetworkError::request(
                        "too many distinct DKG round1 events; aborting to bound memory".to_string(),
                    )));
                }
                // Software-only wire: skip hardware-format events cleanly.
                let is_software = ev.tags.iter().any(|t| {
                    let slice = t.as_slice();
                    slice.first().map(|s| s.as_str()) == Some("dkg_mode")
                        && slice.get(1).map(|s| s.as_str()) == Some("software_v1")
                });
                if !is_software {
                    continue;
                }
                let wire: SoftwareRound1Wire = match serde_json::from_str(&ev.content) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                if wire.sender_index == our_index as u16 {
                    continue;
                }
                // #674: authenticate the sender against the roster BEFORE
                // touching the state machine so a hostile publisher cannot
                // race the honest peer for its index or force a spurious
                // rejection at part2/part3 by feeding malformed data.
                if !roster.authenticates(wire.sender_index, &ev.pubkey, out, "round 1 event") {
                    continue;
                }
                if participant_pubkeys.contains_key(&wire.sender_index) {
                    continue;
                }
                match session.round1_peer(&wire) {
                    Ok(_) => {
                        participant_pubkeys.insert(wire.sender_index, ev.pubkey);
                        round1_done += 1;
                        out.success(&format!(
                            "Received round 1 package from participant {}",
                            wire.sender_index
                        ));
                    }
                    Err(e) => {
                        out.warn(&format!(
                            "Rejected round 1 package from participant {}: {e}",
                            wire.sender_index
                        ));
                    }
                }
            }

            if round1_done < expected_peers as u32 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        out.newline();
        out.success("All round 1 packages received");

        let spinner = out.spinner("Generating round 2 shares...");
        let round2_wires = session
            .round2()
            .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("round 2: {e}"))))?;
        spinner.finish();

        for (recipient_index, wire) in round2_wires {
            let recipient_pubkey = participant_pubkeys.get(&recipient_index).ok_or_else(|| {
                KeepError::FrostErr(FrostError::unknown_participant(recipient_index))
            })?;
            // Serialized share is secret until nip44 wraps it; scrub the plaintext.
            let payload = Zeroizing::new(
                serde_json::to_string(&wire)
                    .map_err(|e| KeepError::Runtime(format!("serialize round2: {e}")))?,
            );
            let encrypted_content = nip44::encrypt(
                keys.secret_key(),
                recipient_pubkey,
                payload.as_str(),
                nip44::Version::default(),
            )
            .map_err(|e| KeepError::CryptoErr(CryptoError::encryption(e.to_string())))?;

            let share_event = EventBuilder::new(Kind::Custom(21103), &encrypted_content)
                .tag(Tag::custom(TagKind::custom("d"), vec![group.to_string()]))
                .tag(Tag::custom(
                    TagKind::custom("sender_index"),
                    vec![our_index.to_string()],
                ))
                .tag(Tag::custom(
                    TagKind::custom("recipient_index"),
                    vec![recipient_index.to_string()],
                ))
                .tag(Tag::custom(
                    TagKind::custom("dkg_mode"),
                    vec!["software_v1".to_string()],
                ))
                .sign_with_keys(&keys)
                .map_err(|e| {
                    KeepError::CryptoErr(CryptoError::invalid_signature(format!(
                        "share event: {e}"
                    )))
                })?;

            client
                .send_event(&share_event)
                .await
                .map_err(|e| KeepError::NetworkErr(NetworkError::publish(format!("share: {e}"))))?;

            out.info(&format!(
                "Published encrypted round 2 share for participant {recipient_index}"
            ));
        }

        out.newline();
        out.info(&format!(
            "Waiting for {expected_peers} round 2 shares from peers..."
        ));

        let share_filter = Filter::new()
            .kind(Kind::Custom(21103))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());

        let start = std::time::Instant::now();
        let mut round2_done = 0u32;
        let mut seen_round2: HashSet<EventId> = HashSet::new();
        while round2_done < expected_peers as u32 {
            if start.elapsed() > timeout {
                return Err(KeepError::NetworkErr(NetworkError::timeout(
                    "waiting for peer round2 shares",
                )));
            }

            let events = client
                .fetch_events(share_filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| {
                    KeepError::NetworkErr(NetworkError::request(format!("fetch shares: {e}")))
                })?;

            for ev in events.iter() {
                if ev.pubkey == keys.public_key() {
                    continue;
                }
                if !seen_round2.insert(ev.id) {
                    continue;
                }
                if seen_round2.len() > MAX_DKG_EVENTS_SEEN {
                    return Err(KeepError::NetworkErr(NetworkError::request(
                        "too many distinct DKG round2 events; aborting to bound memory".to_string(),
                    )));
                }
                let is_software = ev.tags.iter().any(|t| {
                    let slice = t.as_slice();
                    slice.first().map(|s| s.as_str()) == Some("dkg_mode")
                        && slice.get(1).map(|s| s.as_str()) == Some("software_v1")
                });
                if !is_software {
                    continue;
                }
                let recipient_idx_tag = ev.tags.iter().find_map(|t| {
                    let slice = t.as_slice();
                    if slice.first().map(|s| s.as_str()) == Some("recipient_index") {
                        slice.get(1).and_then(|s| s.parse::<u16>().ok())
                    } else {
                        None
                    }
                });
                if recipient_idx_tag != Some(our_index as u16) {
                    continue;
                }
                let decrypted = match nip44::decrypt(keys.secret_key(), &ev.pubkey, &ev.content) {
                    // Plaintext carries the peer's secret signing share; scrub
                    // it from the heap once this iteration drops it.
                    Ok(d) => Zeroizing::new(d),
                    Err(_) => continue,
                };
                let wire: SoftwareRound2Wire = match serde_json::from_str(&decrypted) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                // #674: the roster is now authoritative for who each index
                // is. `participant_pubkeys` came from the (already-authed)
                // round1 pass, but check against the roster directly so a
                // future refactor cannot re-introduce the pre-#674 gap by
                // populating that map without an author check.
                if !roster.authenticates(wire.sender_index, &ev.pubkey, out, "round 2 share") {
                    continue;
                }
                match session.receive_share(&wire) {
                    Ok(_) => {
                        round2_done += 1;
                        out.success(&format!(
                            "Received round 2 share from participant {}",
                            wire.sender_index
                        ));
                    }
                    Err(e) => {
                        out.warn(&format!(
                            "Rejected round 2 share from participant {}: {e}",
                            wire.sender_index
                        ));
                    }
                }
            }
            if round2_done < expected_peers as u32 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        out.newline();
        let spinner = out.spinner("Finalizing DKG...");
        let result = session
            .finalize()
            .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("finalize: {e}"))))?;
        spinner.finish();

        // Equivocation check (keep-dcnq): round1 packages are broadcast through a
        // single relay with no consistency round, so a malicious relay can hand
        // DIFFERENT round1 sets to different participants, who then finalize
        // DIFFERENT group keys with nothing in the base protocol to catch it.
        // Before persisting, every participant broadcasts the group key it derived
        // (an authenticated event the relay cannot forge) and requires all peers to
        // report the SAME key. A divergence, or a peer that never confirms, aborts
        // the DKG instead of storing an inconsistent keyset.
        let our_group_hex = hex::encode(result.group_pubkey);
        let confirm_event = EventBuilder::new(Kind::Custom(21107), &our_group_hex)
            .tag(Tag::custom(TagKind::custom("d"), vec![group.to_string()]))
            .tag(Tag::custom(
                TagKind::custom("sender_index"),
                vec![our_index.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("dkg_mode"),
                vec!["software_v1".to_string()],
            ))
            .sign_with_keys(&keys)
            .map_err(|e| {
                KeepError::CryptoErr(CryptoError::invalid_signature(format!(
                    "confirm event: {e}"
                )))
            })?;
        client
            .send_event(&confirm_event)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::publish(format!("confirm: {e}"))))?;

        out.newline();
        out.info(&format!(
            "Confirming the group key matches across {expected_peers} peers..."
        ));
        let confirm_filter = Filter::new()
            .kind(Kind::Custom(21107))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());
        let start = std::time::Instant::now();
        let mut confirmed_indices: HashSet<u16> = HashSet::new();
        let mut seen_confirm: HashSet<EventId> = HashSet::new();
        while (confirmed_indices.len() as u32) < expected_peers as u32 {
            if start.elapsed() > timeout {
                return Err(KeepError::NetworkErr(NetworkError::timeout(
                    "waiting for peer group-key confirmations (possible relay equivocation)",
                )));
            }
            let events = client
                .fetch_events(confirm_filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| {
                    KeepError::NetworkErr(NetworkError::request(format!("fetch confirm: {e}")))
                })?;
            for ev in events.iter() {
                if ev.pubkey == keys.public_key() {
                    continue;
                }
                if !seen_confirm.insert(ev.id) {
                    continue;
                }
                if seen_confirm.len() > MAX_DKG_EVENTS_SEEN {
                    return Err(KeepError::NetworkErr(NetworkError::request(
                        "too many distinct DKG confirm events; aborting to bound memory"
                            .to_string(),
                    )));
                }
                let is_software = ev.tags.iter().any(|t| {
                    let slice = t.as_slice();
                    slice.first().map(|s| s.as_str()) == Some("dkg_mode")
                        && slice.get(1).map(|s| s.as_str()) == Some("software_v1")
                });
                if !is_software {
                    continue;
                }
                let sender_idx = ev.tags.iter().find_map(|t| {
                    let slice = t.as_slice();
                    if slice.first().map(|s| s.as_str()) == Some("sender_index") {
                        slice.get(1).and_then(|s| s.parse::<u16>().ok())
                    } else {
                        None
                    }
                });
                let sender_idx = match sender_idx {
                    Some(i) => i,
                    None => continue,
                };
                if !roster.authenticates(sender_idx, &ev.pubkey, out, "group-key confirmation") {
                    continue;
                }
                if accept_group_key_confirmation(
                    &our_group_hex,
                    sender_idx,
                    &ev.content,
                    &mut confirmed_indices,
                )? {
                    out.success(&format!(
                        "Participant {sender_idx} confirmed the same group key"
                    ));
                }
            }
            if (confirmed_indices.len() as u32) < expected_peers as u32 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        let spinner = out.spinner("Storing share in vault...");
        keep.frost_store_dkg_share(&result, threshold as u16, participants as u16, group)?;
        spinner.finish();

        out.newline();
        out.success("DKG Complete!");
        out.field("Group public key", &hex::encode(result.group_pubkey));
        out.field("Our index", &result.our_index.to_string());
        out.newline();
        out.info("Share stored in vault (software DKG).");
        out.info(&format!(
            "Group '{group}' is now ready for threshold signing."
        ));

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out))]
pub fn cmd_frost_network_group_create(
    out: &Output,
    name: &str,
    threshold: u8,
    participants: u8,
    relays: &[String],
    participant_npubs: &[String],
) -> Result<()> {
    out.newline();
    out.header("FROST Group Announcement (Kind 21101)");
    out.field("Name", name);
    out.field("Threshold", &format!("{threshold}-of-{participants}"));
    out.newline();

    if threshold < 2 || threshold > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "must be 2 <= threshold ({threshold}) <= participants ({participants})"
        ))));
    }

    if participant_npubs.len() != participants as usize {
        return Err(KeepError::InvalidInput(format!(
            "expected {} participant npubs, got {}",
            participants,
            participant_npubs.len()
        )));
    }

    let group_id = frost_group_id(name, threshold, participants, participant_npubs);

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    rt.block_on(async {
        let keys = Keys::generate();
        let client = Client::new(keys.clone());

        for relay in relays {
            client
                .add_relay(relay)
                .await
                .map_err(|e| KeepError::NetworkErr(NetworkError::relay(format!("{relay}: {e}"))))?;
        }
        client.connect().await;

        out.info("Connected to relays");
        out.field(
            "Coordinator pubkey",
            &keys.public_key().to_bech32().unwrap_or_default(),
        );
        out.newline();

        let mut tags = vec![
            Tag::custom(TagKind::custom("d"), vec![hex::encode(group_id)]),
            Tag::custom(TagKind::custom("threshold"), vec![threshold.to_string()]),
            Tag::custom(
                TagKind::custom("participants"),
                vec![participants.to_string()],
            ),
        ];

        for (i, npub) in participant_npubs.iter().enumerate() {
            let relay_hint = relays.first().map(|s| s.as_str()).unwrap_or("");
            tags.push(Tag::custom(
                TagKind::custom("p"),
                vec![npub.clone(), relay_hint.to_string(), (i + 1).to_string()],
            ));
        }

        for relay in relays {
            tags.push(Tag::custom(TagKind::custom("relay"), vec![relay.clone()]));
        }

        let content = serde_json::json!({
            "name": name,
            "description": format!("{}-of-{} FROST threshold signing group", threshold, participants),
        })
        .to_string();

        let mut builder = EventBuilder::new(Kind::Custom(21101), &content);
        for tag in tags {
            builder = builder.tag(tag);
        }

        let event = builder
            .sign_with_keys(&keys)
            .map_err(|e| KeepError::CryptoErr(CryptoError::invalid_signature(e.to_string())))?;

        let spinner = out.spinner("Publishing group announcement...");
        client
            .send_event(&event)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::publish(e.to_string())))?;
        spinner.finish();

        out.newline();
        out.success("Group announcement published!");
        out.field("Event ID", &event.id.to_hex());
        out.field("Group ID", &hex::encode(group_id));
        out.newline();

        for (i, npub) in participant_npubs.iter().enumerate() {
            out.info(&format!("Participant {}: {}", i + 1, npub));
        }

        Ok::<_, KeepError>(())
    })?;

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

    /// #674: `require_roster_matches` catches every published-vs-CLI drift
    /// path: threshold mismatch, participants mismatch, and identity/index
    /// mismatch.
    #[test]
    fn require_roster_matches_catches_every_mismatch() {
        let (npub1, pk1) = make_pubkey(1);
        let (npub2, pk2) = make_pubkey(2);
        let (npub3, pk3) = make_pubkey(3);
        let _ = (npub1, npub2, npub3);

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
        let out = Output::new();

        // The pinned pubkey for its own index is accepted.
        assert!(roster.authenticates(1, &pk1, &out, "round 1 event"));
        assert!(roster.authenticates(2, &pk2, &out, "round 2 share"));
        // A roster member authoring for a DIFFERENT index is rejected: a relay
        // writer cannot make participant 2's npub speak for index 1.
        assert!(!roster.authenticates(1, &pk2, &out, "round 1 event"));
        // A pubkey not on the roster at all is rejected.
        assert!(!roster.authenticates(2, &pk3, &out, "round 2 share"));
        // An index with no roster entry is rejected (unroster'd sender_index).
        assert!(!roster.authenticates(9, &pk1, &out, "round 1 event"));
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
        let mut builder = EventBuilder::new(Kind::Custom(21101), &content);
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
        let mut ev = build_announcement("g", 2, 2, &npubs, Some(&group_id));
        // Append a second p-tag reusing index 1.
        let mut tags: Vec<Tag> = ev.tags.iter().cloned().collect();
        tags.push(Tag::custom(
            TagKind::custom("p"),
            vec![n1, String::new(), "1".to_string()],
        ));
        let mut builder = EventBuilder::new(Kind::Custom(21101), &ev.content);
        for tag in tags {
            builder = builder.tag(tag);
        }
        ev = builder.sign_with_keys(&make_identity_keys(0x42)).unwrap();

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
        // participants=2, p-tags at indexes 1 and 3: count 2 == 2 (passes the
        // count check) but index 2 is missing, so the hole check must reject.
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
        let mut builder = EventBuilder::new(Kind::Custom(21101), &content);
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
