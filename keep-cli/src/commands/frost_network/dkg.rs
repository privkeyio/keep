// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, HashSet};

use nostr_sdk::prelude::*;

use keep_core::error::{CryptoError, FrostError, KeepError, NetworkError, Result};

use crate::output::Output;
use crate::signer::HardwareSigner;

#[tracing::instrument(skip(out))]
pub fn cmd_frost_network_dkg(
    out: &Output,
    group: &str,
    threshold: u8,
    participants: u8,
    our_index: u8,
    relay: &str,
    hardware: &str,
) -> Result<()> {
    out.newline();
    out.header("FROST Distributed Key Generation");
    out.field("Group", group);
    out.field("Threshold", &format!("{}-of-{}", threshold, participants));
    out.field("Our index", &our_index.to_string());
    out.field("Relay", relay);
    out.field("Hardware", hardware);
    out.newline();

    if threshold < 2 || threshold > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "must be 2 <= threshold ({}) <= participants ({})",
            threshold, participants
        ))));
    }

    if our_index < 1 || our_index > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_share(format!(
            "index must be 1..={}, got {}",
            participants, our_index
        ))));
    }

    let spinner = out.spinner("Connecting to hardware...");
    let mut signer = HardwareSigner::new(hardware)
        .map_err(|e| KeepError::NetworkErr(NetworkError::connection(format!("hardware: {}", e))))?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer.ping().map_err(|e| {
        KeepError::NetworkErr(NetworkError::connection(format!("hardware ping: {}", e)))
    })?;
    spinner.finish();
    out.field("Hardware version", &version);

    let spinner = out.spinner("Initializing DKG...");
    signer
        .dkg_init(group, threshold, participants, our_index)
        .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("init: {}", e))))?;
    spinner.finish();

    let spinner = out.spinner("Starting DKG round 1...");
    let round1_data = signer
        .dkg_round1()
        .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("round 1: {}", e))))?;
    spinner.finish();

    let our_package = round1_data.to_json();

    out.success("DKG Round 1 complete");
    out.field("Our package", &our_package);
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;

    rt.block_on(async {
        let keys = Keys::generate();
        let client = Client::new(keys.clone());
        client
            .add_relay(relay)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::relay(e.to_string())))?;
        client.connect().await;

        out.info("Connected to relay");
        out.field(
            "Node pubkey",
            &keys.public_key().to_bech32().unwrap_or_default(),
        );
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
            "Waiting for {} other round 1 packages...",
            expected_peers
        ));

        let filter = Filter::new()
            .kind(Kind::Custom(21102))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());

        let mut received_packages: HashMap<u8, String> = HashMap::new();
        let mut participant_pubkeys: HashMap<u8, PublicKey> = HashMap::new();
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
                        if let Some(pkg) = content.get("package").and_then(|p| p.as_str()) {
                            signer.dkg_round1_peer(sender_idx, pkg).map_err(|e| {
                                KeepError::FrostErr(FrostError::dkg(format!(
                                    "process package from {}: {}",
                                    sender_idx, e
                                )))
                            })?;

                            received_packages.insert(sender_idx, pkg.to_string());
                            participant_pubkeys.insert(sender_idx, ev.pubkey);
                            out.success(&format!(
                                "Received round 1 package from participant {}",
                                sender_idx
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
            .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("round 2: {}", e))))?;
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
                        "share event: {}",
                        e
                    )))
                })?;

            client.send_event(&share_event).await.map_err(|e| {
                KeepError::NetworkErr(NetworkError::publish(format!("share: {}", e)))
            })?;

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
                    KeepError::NetworkErr(NetworkError::request(format!("fetch shares: {}", e)))
                })?;

            for ev in events.iter() {
                if ev.pubkey == keys.public_key() {
                    continue;
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
                        if let Some(share_hex) = content.get("share").and_then(|s| s.as_str()) {
                            match signer.dkg_receive_share(sender_idx, share_hex) {
                                Ok(()) => {
                                    received_from_peers.insert(sender_idx);
                                    out.success(&format!(
                                        "Received share from participant {}",
                                        sender_idx
                                    ));
                                }
                                Err(e) => {
                                    out.warn(&format!(
                                        "Failed to process share from {}: {}",
                                        sender_idx, e
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
            .map_err(|e| KeepError::FrostErr(FrostError::dkg(format!("finalize: {}", e))))?;
        spinner.finish();

        out.newline();
        out.success("DKG Complete!");
        out.field("Group public key", &result.group_pubkey);
        out.field("Our index", &result.our_index.to_string());
        out.newline();
        out.info("Share has been stored on the hardware device.");
        out.info(&format!(
            "Group '{}' is now ready for threshold signing.",
            group
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
    use sha2::{Digest, Sha256};

    out.newline();
    out.header("FROST Group Announcement (Kind 21101)");
    out.field("Name", name);
    out.field("Threshold", &format!("{}-of-{}", threshold, participants));
    out.newline();

    if threshold < 2 || threshold > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
            "must be 2 <= threshold ({}) <= participants ({})",
            threshold, participants
        ))));
    }

    if participant_npubs.len() != participants as usize {
        return Err(KeepError::InvalidInput(format!(
            "expected {} participant npubs, got {}",
            participants,
            participant_npubs.len()
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"frost-group-id-v1");
    hasher.update(name.as_bytes());
    hasher.update([threshold]);
    hasher.update([participants]);
    for npub in participant_npubs {
        hasher.update(npub.as_bytes());
    }
    let group_id: [u8; 32] = hasher.finalize().into();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;

    rt.block_on(async {
        let keys = Keys::generate();
        let client = Client::new(keys.clone());

        for relay in relays {
            client
                .add_relay(relay)
                .await
                .map_err(|e| KeepError::NetworkErr(NetworkError::relay(format!("{}: {}", relay, e))))?;
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
