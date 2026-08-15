// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};

use nostr_sdk::prelude::*;
use zeroize::Zeroizing;

use keep_core::error::{CryptoError, FrostError, KeepError, NetworkError, Result};
use keep_core::Keep;
use keep_frost_net::dkg::{
    fetch_group_roster, frost_group_id, parse_pubkey, require_roster_matches, run_software_dkg,
    ClientTransport, DkgPhase, DkgProgress, DKG_KIND_ANNOUNCE, MAX_DKG_EVENTS_SEEN,
};

use crate::output::Output;
use crate::signer::HardwareSigner;

/// Renders the shared coordinator's [`DkgPhase`] updates through the CLI's
/// `Output`, so the round coordination lives in keep-frost-net while the console
/// UX stays here.
struct CliDkgProgress<'a> {
    out: &'a Output,
}

impl DkgProgress for CliDkgProgress<'_> {
    fn phase(&self, phase: DkgPhase) {
        match phase {
            DkgPhase::Round1 { received, total } => self.out.info(&format!(
                "Round 1: {received}/{total} peer packages received"
            )),
            DkgPhase::Round2 { received, total } => self
                .out
                .info(&format!("Round 2: {received}/{total} peer shares received")),
            DkgPhase::Finalizing => self.out.info("Finalizing DKG..."),
            DkgPhase::Confirming { confirmed, total } => self.out.info(&format!(
                "Confirming group key: {confirmed}/{total} peers agreed"
            )),
            DkgPhase::Complete { .. } => {}
        }
    }
}

/// Load this device's per-group DKG signing subkey (§3) from the vault as
/// `nostr_sdk::Keys`, returned with its raw secret so the caller can retain it
/// with the finalized share (C1). The subkey — never the identity nsec — is what
/// the signed roster pins, so the kind-31101 announcement never publishes a map
/// of identities. Errors if the group has no enrolled subkey: the participant
/// must run `keep frost network group-subkey --group <name>` first and hand its
/// pubkey to the coordinator so it appears in the roster.
fn load_group_subkey(keep: &Keep, group: &str) -> Result<(Keys, Zeroizing<[u8; 32]>)> {
    let secret = Zeroizing::new(keep.frost_group_subkey_secret(group)?.ok_or_else(|| {
        KeepError::KeyNotFound(format!(
            "no per-group signing subkey enrolled for group {group:?}; run \
             `keep frost network group-subkey --group {group}` first and give the \
             printed pubkey to the coordinator so it appears in the signed roster (§3)"
        ))
    })?);
    let sk = nostr_sdk::secp256k1::SecretKey::from_slice(&*secret).map_err(|e| {
        KeepError::CryptoErr(CryptoError::invalid_key(format!(
            "stored per-group subkey is not a valid secp256k1 secret: {e}"
        )))
    })?;
    Ok((Keys::new(sk.into()), secret))
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
) -> Result<()> {
    // §3/#674: both paths require a vault path to load the per-group signing
    // subkey that signs DKG events. Without authentication a relay writer can DoS
    // or (with enough participation) join a group as a rogue co-generator.
    let vault_path = vault_path.ok_or_else(|| {
        KeepError::InvalidInput(
            "keep frost network dkg requires --path <vault> to load the per-group \
             signing subkey for DKG events (§3/#674)."
                .into(),
        )
    })?;
    match hardware {
        // The hardware path predates the shared coordinator and has not been
        // migrated: it has no equivocation-confirmation round (a malicious relay
        // can equivocate round-1 packages), no relay certificate pinning or
        // proxy, and decrypts round-2 events before authenticating the sender.
        // Refuse to run it rather than generate a key over an unhardened transport
        // until it is ported to run_software_dkg. See cmd_frost_network_dkg_hardware.
        Some(_) => Err(KeepError::InvalidInput(
            "hardware DKG over relays is not yet supported: the hardware path has \
             not been migrated to the hardened DKG coordinator (no equivocation \
             confirmation, no relay pinning). Use the software DKG path (omit \
             --hardware) to create a group for now."
                .into(),
        )),
        None => cmd_frost_network_dkg_software(
            out,
            group,
            threshold,
            participants,
            our_index,
            relay,
            vault_path,
        ),
    }
}

// Retained for the pending migration to the hardened shared coordinator; the
// dispatcher above refuses to invoke it until then (unhardened transport).
#[allow(dead_code)]
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

    // §3/#674: load our per-group signing subkey from the vault BEFORE the
    // hardware is touched. A stale hardware DKG state (from a prior interrupted
    // run) is much easier to reset than "we already connected to hardware but
    // then errored on a missing per-group subkey".
    let spinner = out.spinner("Opening vault...");
    let mut keep = Keep::open(vault_path)?;
    let password = super::get_password("Enter password")?;
    keep.unlock(password.expose_secret())?;
    let (subkey, _subkey_secret) = load_group_subkey(&keep, group)?;
    spinner.finish();
    out.field(
        "Subkey npub",
        &subkey.public_key().to_bech32().unwrap_or_default(),
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
        let keys = subkey.clone();
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
        // args + subkey before we emit any DKG material.
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
                        if !roster.authenticates(sender_idx as u16, &ev.pubkey, "round 1 event") {
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
                        if !roster.authenticates(sender_idx as u16, &ev.pubkey, "round 2 share") {
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
) -> Result<()> {
    use keep_core::frost::dkg::SoftwareDkgSession;
    use secrecy::ExposeSecret;

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
    // §3/#674: load our per-group signing subkey here so a group with no enrolled
    // subkey fails BEFORE any DKG state is created; we would otherwise emit our
    // round1 package under a key the roster does not pin and later intake rejects.
    let (subkey, subkey_secret) = load_group_subkey(&keep, group)?;
    spinner.finish();
    out.field(
        "Subkey npub",
        &subkey.public_key().to_bech32().unwrap_or_default(),
    );

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    let outcome = rt.block_on(async {
        let keys = subkey.clone();
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

        // #674: fetch the signed roster and require it to match our CLI args +
        // subkey before we emit any DKG material. Fail closed so a wrong
        // --index or a stale --threshold surfaces before co-signers see us.
        let spinner = out.spinner("Fetching signed group roster...");
        let roster = fetch_group_roster(&client, group).await?;
        spinner.finish();
        require_roster_matches(&roster, &keys, threshold, participants, our_index)?;
        out.success(&format!(
            "Roster verified ({} participants pinned by signed announcement)",
            roster.participants,
        ));
        out.newline();

        // The round coordination (publish/collect for all three rounds, roster
        // authentication, and the equivocation confirmation) is the shared
        // implementation in keep-frost-net, driven here with an `Output`-backed
        // progress sink.
        let progress = CliDkgProgress { out };
        let transport = ClientTransport::new(client);
        // The CLI runs the DKG to completion in the foreground with no cancel
        // button, so it hands the coordinator a flag it never sets; mobile flips
        // its own flag from the UI (§8/§9).
        let cancel = std::sync::atomic::AtomicBool::new(false);
        run_software_dkg(
            &mut session,
            &transport,
            &keys,
            &roster,
            group,
            our_index as u16,
            std::time::Duration::from_secs(300),
            &cancel,
            &progress,
        )
        .await
    })?;

    // §6: the coordinator only returns once it holds the complete CertEq
    // certificate (all n signatures over the transcript), so reaching here means
    // the group is genuinely agreed — persist the share after, never before.
    let result = &outcome.result;
    let spinner = out.spinner("Storing share in vault...");
    keep.frost_store_dkg_share(
        result,
        threshold as u16,
        participants as u16,
        group,
        Some(*subkey_secret),
    )?;
    spinner.finish();

    out.newline();
    out.success("DKG Complete!");
    out.field("Group public key", &hex::encode(result.group_pubkey));
    out.field("Our index", &result.our_index.to_string());
    out.field(
        "Confirmation certificate",
        &format!(
            "{} signatures retained",
            outcome.certificate.confirmations.len()
        ),
    );
    out.newline();
    out.info("Share stored in vault (software DKG).");
    out.info(&format!(
        "Group '{group}' is now ready for threshold signing."
    ));

    Ok(())
}

/// Assemble the signed kind-31101 roster for a group.
///
/// §3: the per-participant pubkeys are each device's **per-group signing
/// subkey** (printed by `keep frost network group-subkey`), never an identity
/// npub — the announcement is public, so identity p-tags would publish a
/// targeting map of who co-holds the key. `frost_group_id` therefore hashes the
/// subkeys.
///
/// C2: relay publication is **opt-in** (`publish`). By default the roster is a
/// local artifact — the group id and pubkey list are printed for the coordinator
/// to hand to participants out of band (the same shape mobile carries in its
/// invite), and nothing is written to a relay. `--publish` opts into the CLI's
/// relay-discovery path, which each participant's `dkg` then fetches.
#[tracing::instrument(skip(out))]
pub fn cmd_frost_network_group_create(
    out: &Output,
    name: &str,
    threshold: u8,
    participants: u8,
    relays: &[String],
    participant_subkeys: &[String],
    publish: bool,
) -> Result<()> {
    out.newline();
    out.header("FROST Group Announcement (Kind 31101)");
    out.field("Name", name);
    out.field("Threshold", &format!("{threshold}-of-{participants}"));
    out.newline();

    if threshold < 2 || threshold > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "must be 2 <= threshold ({threshold}) <= participants ({participants})"
        ))));
    }

    if participant_subkeys.len() != participants as usize {
        return Err(KeepError::InvalidInput(format!(
            "expected {} participant subkeys, got {}",
            participants,
            participant_subkeys.len()
        )));
    }

    // Normalize before hashing. The raw CLI strings may be hex or bech32 and may
    // differ in case, so two coordinators typing the same roster differently
    // would derive different group ids and silently fail to find each other.
    // Parsing also rejects a malformed key here rather than at round 1, and the
    // duplicate check closes a real attack: repeating one participant's subkey
    // gives that holder two of the n shares, so a 2-of-3 becomes single-party
    // spendable by them.
    let mut normalized: Vec<String> = Vec::with_capacity(participant_subkeys.len());
    let mut seen: HashSet<PublicKey> = HashSet::new();
    for (i, raw) in participant_subkeys.iter().enumerate() {
        let pk = parse_pubkey(raw).map_err(|e| {
            KeepError::InvalidInput(format!("participant {} subkey is invalid: {e}", i + 1))
        })?;
        if !seen.insert(pk) {
            return Err(KeepError::InvalidInput(format!(
                "participant {} repeats a subkey already used by an earlier participant; \
                 every participant must hold a distinct key",
                i + 1
            )));
        }
        normalized.push(pk.to_bech32().map_err(|e| {
            KeepError::InvalidInput(format!("participant {} subkey is unencodable: {e}", i + 1))
        })?);
    }
    let participant_subkeys: &[String] = &normalized;

    let group_id = frost_group_id(name, threshold, participants, participant_subkeys);

    // C2: default is a local roster artifact — print the group id and the subkey
    // list for out-of-band distribution and skip the relay entirely, so a group
    // never leaves a public record unless the coordinator asks for one.
    if !publish {
        out.success("Group roster assembled (local, not published).");
        out.field("Group ID", &hex::encode(group_id));
        out.newline();
        for (i, subkey) in participant_subkeys.iter().enumerate() {
            out.info(&format!("Participant {}: {}", i + 1, subkey));
        }
        out.newline();
        out.info(
            "Distribute the group id + subkeys to participants out of band, or re-run with \
             --publish to announce on the relay for the CLI discovery path.",
        );
        return Ok(());
    }

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

        for (i, subkey) in participant_subkeys.iter().enumerate() {
            let relay_hint = relays.first().map(|s| s.as_str()).unwrap_or("");
            tags.push(Tag::custom(
                TagKind::custom("p"),
                vec![subkey.clone(), relay_hint.to_string(), (i + 1).to_string()],
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

        let mut builder = EventBuilder::new(Kind::Custom(DKG_KIND_ANNOUNCE), &content);
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

        for (i, subkey) in participant_subkeys.iter().enumerate() {
            out.info(&format!("Participant {}: {}", i + 1, subkey));
        }

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

/// Enroll this device's per-group DKG signing subkey (§3) and print its pubkey.
///
/// Each participant runs this once per group before the coordinator builds the
/// roster, then hands the printed pubkey to the coordinator so it lands in the
/// signed kind-31101 announcement (and thus in `frost_group_id`). The secret is
/// stored in the vault keyed by group name and retained with the finalized share
/// (C1); `keep frost network dkg` looks it up to sign DKG events. Idempotent:
/// re-running prints the same subkey rather than minting a divergent one.
#[tracing::instrument(skip(out))]
pub fn cmd_frost_network_group_subkey(
    out: &Output,
    group: &str,
    vault_path: &std::path::Path,
) -> Result<()> {
    use secrecy::ExposeSecret;

    out.newline();
    out.header("FROST Per-Group Signing Subkey (§3)");
    out.field("Group", group);
    out.field("Vault", &vault_path.display().to_string());
    out.newline();

    let spinner = out.spinner("Opening vault...");
    let mut keep = Keep::open(vault_path)?;
    let password = super::get_password("Enter password")?;
    keep.unlock(password.expose_secret())?;
    let pubkey = keep.frost_group_subkey_ensure(group)?;
    spinner.finish();

    let npub = keep_core::keys::bytes_to_npub(&pubkey);
    out.success("Subkey ready.");
    out.field("Subkey npub", &npub);
    out.field("Subkey pubkey (hex)", &hex::encode(pubkey));
    out.newline();
    out.info(
        "Give this pubkey to the group coordinator so it appears in the signed roster. \
         The secret stays in this vault and is retained with your share (C1).",
    );

    Ok(())
}
