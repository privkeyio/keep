// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;

use nostr_sdk::prelude::*;
use secrecy::ExposeSecret;
use tracing::debug;

use keep_core::error::{KeepError, Result};
use keep_core::Keep;

use crate::output::Output;
use crate::signer::{HardwareSigner, NonceStore};

use super::get_password;

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_network_serve(
    out: &Output,
    path: &Path,
    group_npub: &str,
    relay: &str,
    share_index: Option<u16>,
) -> Result<()> {
    debug!(group = group_npub, relay, share = ?share_index, "starting FROST network node");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };
    let threshold = share.metadata.threshold;
    let share_index = share.metadata.identifier;
    let total_shares = share.metadata.total_shares;

    out.newline();
    out.header("FROST Network Node");
    out.field("Group", group_npub);
    out.field("Share", &share_index.to_string());
    out.field("Threshold", &format!("{}-of-{}", threshold, total_shares));
    out.field("Relay", relay);
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

    rt.block_on(async {
        out.info("Starting FROST coordination node...");

        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let npub = node.pubkey().to_bech32().unwrap_or_default();
        out.field("Node pubkey", &npub);
        out.newline();
        out.info("Listening for FROST messages... (Ctrl+C to stop)");

        let mut event_rx = node.subscribe();
        let event_task = tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(keep_frost_net::KfpNodeEvent::PeerDiscovered { share_index, name }) => {
                        let name_str = name.unwrap_or_else(|| "unnamed".to_string());
                        tracing::info!(share_index, name = name_str, "peer discovered");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::SignatureComplete {
                        session_id,
                        signature,
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        let sig = hex::encode(signature);
                        tracing::info!(session, signature = sig, "signature complete");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::SigningFailed { session_id, error }) => {
                        let session = hex::encode(&session_id[..8]);
                        tracing::error!(session, error, "signing failed");
                    }
                    Err(_) => break,
                    _ => {}
                }
            }
        });

        node.run()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        event_task.abort();

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_network_peers(
    out: &Output,
    path: &Path,
    group_npub: &str,
    relay: &str,
) -> Result<()> {
    debug!(group = group_npub, relay, "checking FROST peers");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;

    let share = keep.frost_get_share(&group_pubkey)?;

    out.newline();
    out.header("FROST Network Peers");
    out.field("Group", group_npub);
    out.field("Relay", relay);
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

    rt.block_on(async {
        let spinner = out.spinner("Connecting and discovering peers...");

        let node = std::sync::Arc::new(
            keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?,
        );

        node.announce()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let node_handle = tokio::spawn({
            let node = node.clone();
            async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        spinner.finish();
        node_handle.abort();

        let status = node.peer_status();

        if status.is_empty() {
            out.info("No peers discovered yet.");
            out.info("Run 'keep frost network serve' on other devices first.");
        } else {
            out.table_header(&[("SHARE", 8), ("STATUS", 10), ("NAME", 20)]);

            for (share_index, peer_status, name) in status {
                let status_str = match peer_status {
                    keep_frost_net::PeerStatus::Online => "Online",
                    keep_frost_net::PeerStatus::Offline => "Offline",
                    keep_frost_net::PeerStatus::Unknown => "Unknown",
                };
                let name_str = name.unwrap_or_else(|| "-".to_string());
                out.table_row(&[
                    (&share_index.to_string(), 8, false),
                    (status_str, 10, false),
                    (&name_str, 20, false),
                ]);
            }
        }

        out.newline();
        out.info(&format!("{} peer(s) online", node.online_peers()));

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out, warden_url), fields(path = %path.display()))]
#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_sign(
    out: &Output,
    path: &Path,
    group_npub: &str,
    message: &str,
    relay: &str,
    share_index: Option<u16>,
    hardware: Option<&str>,
    warden_url: Option<&str>,
    threshold: Option<u16>,
    participants: Option<u16>,
) -> Result<()> {
    if let Some(device) = hardware {
        let (threshold, participants) = match (threshold, participants) {
            (Some(t), Some(p)) => (t, p),
            _ => {
                let mut signer = HardwareSigner::new(device)
                    .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
                let info = signer
                    .get_share_info(group_npub)
                    .map_err(|e| KeepError::Other(format!("Failed to get share info: {}", e)))?;
                (
                    threshold.unwrap_or(info.threshold),
                    participants.unwrap_or(info.participants),
                )
            }
        };
        if threshold < 2 || threshold > participants {
            return Err(KeepError::Other(format!(
                "Invalid threshold: must be 2 <= threshold ({}) <= participants ({})",
                threshold, participants
            )));
        }
        return cmd_frost_network_sign_hardware(
            out,
            path,
            group_npub,
            message,
            relay,
            device,
            threshold,
            participants,
        );
    }

    #[cfg(feature = "warden")]
    if let Some(url) = warden_url {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;
        rt.block_on(super::frost::check_warden_policy(
            out, url, group_npub, message,
        ))?;
    }

    #[cfg(not(feature = "warden"))]
    if warden_url.is_some() {
        return Err(KeepError::Other(
            "Warden support not compiled. Rebuild with --features warden".into(),
        ));
    }

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let share = if let Some(idx) = share_index {
        keep.frost_get_share_by_index(&group_pubkey, idx)?
    } else {
        keep.frost_get_share(&group_pubkey)?
    };

    out.newline();
    out.header("FROST Network Sign");
    out.field("Group", group_npub);
    out.field(
        "Share",
        &format!("{} ({})", share.metadata.identifier, share.metadata.name),
    );
    out.field(
        "Threshold",
        &format!(
            "{}-of-{}",
            share.metadata.threshold, share.metadata.total_shares
        ),
    );
    out.field("Relay", relay);
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;
    rt.block_on(async {
        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        out.info("Starting FROST coordination node...");
        out.field(
            "Node pubkey",
            &node.pubkey().to_bech32().unwrap_or_default(),
        );
        out.newline();

        let node = std::sync::Arc::new(node);
        let node_clone = node.clone();
        let _handle = tokio::spawn(async move {
            let _ = node_clone.run().await;
        });

        out.info("Discovering peers...");
        for i in 0..12 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if node.online_peers() > 0 {
                break;
            }
            if i < 11 {
                out.info(&format!("  Waiting for peers... ({}/12)", i + 1));
            }
        }

        if node.online_peers() == 0 {
            return Err(KeepError::Frost("No peers online after 24s.".into()));
        }

        out.success(&format!("Found {} online peer(s)", node.online_peers()));
        out.newline();

        out.info("Waiting for peers to discover us...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let spinner = out.spinner("Requesting signature from network...");
        let signature = node
            .request_signature(message.as_bytes().to_vec(), "raw")
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        out.newline();
        out.success("Signature complete!");
        out.field("Signature", &hex::encode(signature));
        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_frost_network_sign_hardware(
    out: &Output,
    path: &Path,
    group_npub: &str,
    message: &str,
    relay: &str,
    device: &str,
    threshold: u16,
    participants: u16,
) -> Result<()> {
    let message_bytes =
        hex::decode(message).map_err(|_| KeepError::Other("Invalid message hex".into()))?;

    if message_bytes.len() != 32 {
        return Err(KeepError::Other(
            "Message must be 32 bytes (64 hex chars)".into(),
        ));
    }

    let mut message_arr = [0u8; 32];
    message_arr.copy_from_slice(&message_bytes);

    let session_id: [u8; 32] = rand::random();

    out.newline();
    out.header("FROST Hardware Sign via Relay");
    out.field("Device", device);
    out.field("Group", group_npub);
    out.field("Message", message);
    out.field("Relay", relay);
    out.newline();

    let mut nonce_store = NonceStore::open(path)
        .map_err(|e| KeepError::Other(format!("Failed to open nonce store: {}", e)))?;
    let (available, used) = nonce_store.nonce_stats(group_npub);
    out.info(&format!(
        "Nonce status: {} available, {} used",
        available, used
    ));

    let spinner = out.spinner("Connecting to hardware...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer
        .ping()
        .map_err(|e| KeepError::Other(format!("Ping failed: {}", e)))?;
    spinner.finish();
    out.field("Hardware version", &version);

    let spinner = out.spinner("Creating commitment (round 1)...");
    let (commitment, our_index) = signer
        .frost_commit(group_npub, &session_id, &message_arr)
        .map_err(|e| KeepError::Other(format!("Commitment failed: {}", e)))?;
    spinner.finish();

    let commitment_hex = hex::encode(&commitment);

    if nonce_store.is_nonce_used(group_npub, &commitment_hex) {
        return Err(KeepError::Other(
            "SECURITY: Nonce has already been used. Aborting to prevent key compromise.".into(),
        ));
    }

    nonce_store
        .add_nonce(group_npub, &commitment_hex)
        .map_err(|e| KeepError::Other(format!("Failed to track nonce: {}", e)))?;

    if our_index == 0 || our_index > participants {
        return Err(KeepError::Other(format!(
            "Hardware returned invalid share index {}, expected 1..={}",
            our_index, participants
        )));
    }

    out.field("Share index", &our_index.to_string());
    out.field("Commitment", &commitment_hex);
    out.field("Session ID", &hex::encode(session_id));
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

    rt.block_on(async {
        let keys = Keys::generate();
        let client = Client::new(keys.clone());
        client
            .add_relay(relay)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to add relay: {}", e)))?;
        client.connect().await;

        out.info("Connected to relay");
        out.field(
            "Node pubkey",
            &keys.public_key().to_bech32().unwrap_or_default(),
        );
        out.newline();

        let request_content = serde_json::json!({
            "message_type": "raw",
            "payload": message,
            "request_id": hex::encode(session_id),
        })
        .to_string();

        let request_event = EventBuilder::new(Kind::Custom(21104), &request_content)
            .tag(Tag::custom(
                TagKind::custom("d"),
                vec![group_npub.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("request_id"),
                vec![hex::encode(session_id)],
            ))
            .tag(Tag::custom(
                TagKind::custom("message_type"),
                vec!["raw".to_string()],
            ))
            .sign_with_keys(&keys)
            .map_err(|e| KeepError::Other(format!("Failed to sign request: {}", e)))?;

        let spinner = out.spinner("Publishing sign request (Kind 21104)...");
        client
            .send_event(&request_event)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to publish request: {}", e)))?;
        spinner.finish();
        out.field("Request Event ID", &request_event.id.to_hex());

        let response_content = serde_json::json!({
            "request_id": hex::encode(session_id),
            "participant_index": our_index,
            "commitment": hex::encode(&commitment),
        })
        .to_string();

        let response_event = EventBuilder::new(Kind::Custom(21105), &response_content)
            .tag(Tag::custom(
                TagKind::custom("e"),
                vec![
                    request_event.id.to_hex(),
                    relay.to_string(),
                    "reply".to_string(),
                ],
            ))
            .tag(Tag::custom(
                TagKind::custom("request_id"),
                vec![hex::encode(session_id)],
            ))
            .tag(Tag::custom(
                TagKind::custom("participant_index"),
                vec![our_index.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("status"),
                vec!["commitment".to_string()],
            ))
            .sign_with_keys(&keys)
            .map_err(|e| KeepError::Other(format!("Failed to sign response: {}", e)))?;

        let spinner = out.spinner("Publishing our commitment (Kind 21105)...");
        client
            .send_event(&response_event)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to publish commitment: {}", e)))?;
        spinner.finish();

        let filter = Filter::new().kind(Kind::Custom(21105)).custom_tag(
            SingleLetterTag::lowercase(Alphabet::E),
            request_event.id.to_hex(),
        );

        out.info("Waiting for peer commitments...");
        out.field("Threshold", &format!("{}-of-{}", threshold, participants));
        let mut peer_commitments: std::collections::HashMap<u16, String> =
            std::collections::HashMap::new();
        peer_commitments.insert(our_index, hex::encode(&commitment));

        let timeout = std::time::Duration::from_secs(120);
        let start = std::time::Instant::now();

        while peer_commitments.len() < threshold as usize {
            if start.elapsed() > timeout {
                return Err(KeepError::Other(
                    "Timeout waiting for peer commitments".into(),
                ));
            }

            let events = client
                .fetch_events(filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| KeepError::Other(format!("Fetch failed: {}", e)))?;

            let our_session_id_hex = hex::encode(session_id);
            for ev in events.iter() {
                if ev.pubkey == keys.public_key() {
                    continue;
                }

                if let Ok(content) = serde_json::from_str::<serde_json::Value>(&ev.content) {
                    let peer_request_id = content
                        .get("request_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if peer_request_id != our_session_id_hex {
                        continue;
                    }

                    let peer_idx = content
                        .get("participant_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u16;
                    let peer_commitment = content
                        .get("commitment")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if peer_idx == 0 || peer_idx > participants {
                        continue;
                    }
                    if peer_commitment.is_empty() || hex::decode(peer_commitment).is_err() {
                        continue;
                    }
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        peer_commitments.entry(peer_idx)
                    {
                        e.insert(peer_commitment.to_string());
                        out.success(&format!(
                            "Received commitment from participant {}",
                            peer_idx
                        ));
                    }
                }
            }

            if peer_commitments.len() < threshold as usize {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        out.newline();
        out.success(&format!(
            "Collected {} commitments, proceeding to round 2",
            peer_commitments.len()
        ));

        let all_commitments_hex: String = peer_commitments
            .iter()
            .map(|(idx, c)| format!("{}:{}", idx, c))
            .collect::<Vec<_>>()
            .join(",");

        let spinner = out.spinner("Generating signature share (round 2)...");
        let (sig_share, _) = signer
            .frost_sign(group_npub, &session_id, &all_commitments_hex)
            .map_err(|e| KeepError::Other(format!("Sign failed: {}", e)))?;
        spinner.finish();

        let sig_share_hex = hex::encode(&sig_share);
        out.field("Our signature share", &sig_share_hex);

        let sig_response = serde_json::json!({
            "request_id": hex::encode(session_id),
            "participant_index": our_index,
            "signature_share": sig_share_hex,
        })
        .to_string();

        let sig_event = EventBuilder::new(Kind::Custom(21105), &sig_response)
            .tag(Tag::custom(
                TagKind::custom("e"),
                vec![
                    request_event.id.to_hex(),
                    relay.to_string(),
                    "reply".to_string(),
                ],
            ))
            .tag(Tag::custom(
                TagKind::custom("request_id"),
                vec![hex::encode(session_id)],
            ))
            .tag(Tag::custom(
                TagKind::custom("participant_index"),
                vec![our_index.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("status"),
                vec!["signature_share".to_string()],
            ))
            .sign_with_keys(&keys)
            .map_err(|e| KeepError::Other(format!("Failed to sign: {}", e)))?;

        let spinner = out.spinner("Publishing signature share...");
        client
            .send_event(&sig_event)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to publish: {}", e)))?;
        spinner.finish();

        out.newline();
        out.success("Signature share published!");
        out.info("Waiting for coordinator to aggregate final signature...");

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out))]
#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_sign_event(
    out: &Output,
    _path: &Path,
    _group_npub: &str,
    _kind: u16,
    _content: &str,
    _relay: &str,
    _share_index: Option<u16>,
    _hardware: Option<&str>,
) -> Result<()> {
    out.newline();
    out.error("FROST network event signing not yet implemented");
    out.info("Use 'keep frost network sign' to sign raw messages instead.");
    Err(KeepError::Other("Not implemented".into()))
}

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
        return Err(KeepError::Other(format!(
            "Invalid threshold: must be 2 <= threshold ({}) <= participants ({})",
            threshold, participants
        )));
    }

    if our_index < 1 || our_index > participants {
        return Err(KeepError::Other(format!(
            "Invalid index: must be 1..={}, got {}",
            participants, our_index
        )));
    }

    let spinner = out.spinner("Connecting to hardware...");
    let mut signer = HardwareSigner::new(hardware)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer
        .ping()
        .map_err(|e| KeepError::Other(format!("Ping failed: {}", e)))?;
    spinner.finish();
    out.field("Hardware version", &version);

    let spinner = out.spinner("Initializing DKG...");
    signer
        .dkg_init(group, threshold, participants, our_index)
        .map_err(|e| KeepError::Other(format!("DKG init failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Starting DKG round 1...");
    let round1_data = signer
        .dkg_round1()
        .map_err(|e| KeepError::Other(format!("DKG round 1 failed: {}", e)))?;
    spinner.finish();

    let our_package = round1_data.to_json();

    out.success("DKG Round 1 complete");
    out.field("Our package", &our_package);
    out.newline();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

    rt.block_on(async {
        let keys = Keys::generate();
        let client = Client::new(keys.clone());
        client
            .add_relay(relay)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to add relay: {}", e)))?;
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
            .map_err(|e| KeepError::Other(format!("Failed to sign: {}", e)))?;

        let spinner = out.spinner("Publishing round 1 package...");
        client
            .send_event(&round1_event)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to publish: {}", e)))?;
        spinner.finish();

        let expected_peers = participants - 1;
        out.info(&format!(
            "Waiting for {} other round 1 packages...",
            expected_peers
        ));

        let filter = Filter::new()
            .kind(Kind::Custom(21102))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), group.to_string());

        let mut received_packages: std::collections::HashMap<u8, String> =
            std::collections::HashMap::new();
        let mut participant_pubkeys: std::collections::HashMap<u8, PublicKey> =
            std::collections::HashMap::new();
        let timeout = std::time::Duration::from_secs(300);
        let start = std::time::Instant::now();

        while received_packages.len() < expected_peers as usize {
            if start.elapsed() > timeout {
                return Err(KeepError::Other("Timeout waiting for peer packages".into()));
            }

            let events = client
                .fetch_events(filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| KeepError::Other(format!("Fetch failed: {}", e)))?;

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
                        && sender_idx != our_index
                        && !received_packages.contains_key(&sender_idx)
                    {
                        if let Some(pkg) = content.get("package").and_then(|p| p.as_str()) {
                            signer.dkg_round1_peer(sender_idx, pkg).map_err(|e| {
                                KeepError::Other(format!(
                                    "Failed to process package from {}: {}",
                                    sender_idx, e
                                ))
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
            .map_err(|e| KeepError::Other(format!("DKG round 2 failed: {}", e)))?;
        spinner.finish();

        for share in &shares_for_others {
            let recipient_pubkey =
                participant_pubkeys
                    .get(&share.recipient_index)
                    .ok_or_else(|| {
                        KeepError::Other(format!(
                            "Missing pubkey for participant {}",
                            share.recipient_index
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
            .map_err(|e| KeepError::Other(format!("Encryption failed: {}", e)))?;

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
                .map_err(|e| KeepError::Other(format!("Failed to sign share event: {}", e)))?;

            client
                .send_event(&share_event)
                .await
                .map_err(|e| KeepError::Other(format!("Failed to publish share: {}", e)))?;

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

        let mut received_from_peers: std::collections::HashSet<u8> =
            std::collections::HashSet::new();
        let start = std::time::Instant::now();

        while received_from_peers.len() < expected_peers as usize {
            if start.elapsed() > timeout {
                return Err(KeepError::Other("Timeout waiting for peer shares".into()));
            }

            let events = client
                .fetch_events(share_filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| KeepError::Other(format!("Fetch shares failed: {}", e)))?;

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

                    if sender_idx > 0 && !received_from_peers.contains(&sender_idx) {
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
            .map_err(|e| KeepError::Other(format!("DKG finalize failed: {}", e)))?;
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
        return Err(KeepError::Other(format!(
            "Invalid threshold: must be 2 <= threshold ({}) <= participants ({})",
            threshold, participants
        )));
    }

    if participant_npubs.len() != participants as usize {
        return Err(KeepError::Other(format!(
            "Expected {} participant npubs, got {}",
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

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

    rt.block_on(async {
        let keys = Keys::generate();
        let client = Client::new(keys.clone());

        for relay in relays {
            client
                .add_relay(relay)
                .await
                .map_err(|e| KeepError::Other(format!("Failed to add relay {}: {}", relay, e)))?;
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
            .map_err(|e| KeepError::Other(format!("Failed to sign event: {}", e)))?;

        let spinner = out.spinner("Publishing group announcement...");
        client
            .send_event(&event)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to publish: {}", e)))?;
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

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_network_nonce_precommit(
    out: &Output,
    path: &Path,
    group: &str,
    relay: &str,
    device: &str,
    count: u32,
) -> Result<()> {
    out.newline();
    out.header("FROST Nonce Pre-commitment (Kind 21106)");
    out.warn(
        "EXPERIMENTAL: Pre-generated nonces require hardware signer message-binding enforcement",
    );
    out.field("Group", group);
    out.field("Relay", relay);
    out.field("Device", device);
    out.field("Nonce count", &count.to_string());
    out.newline();

    let mut nonce_store = NonceStore::open(path)
        .map_err(|e| KeepError::Other(format!("Failed to open nonce store: {}", e)))?;

    let (available, used) = nonce_store.nonce_stats(group);
    if available > 0 {
        out.info(&format!(
            "Existing nonces: {} available, {} used",
            available, used
        ));
    }

    let spinner = out.spinner("Connecting to hardware...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::Other(format!("Connection failed: {}", e)))?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer
        .ping()
        .map_err(|e| KeepError::Other(format!("Ping failed: {}", e)))?;
    spinner.finish();
    out.field("Hardware version", &version);

    let (_pubkey_hex, share_index) = signer
        .get_share_pubkey(group)
        .map_err(|e| KeepError::Other(format!("Failed to get share pubkey: {}", e)))?;
    out.field("Share index", &share_index.to_string());
    out.newline();

    let spinner = out.spinner(&format!("Generating {} nonce commitments...", count));
    let mut nonces = Vec::new();
    let mut commitments_hex = Vec::new();
    for i in 0..count {
        let dummy_session: [u8; 32] = rand::random();
        let dummy_message: [u8; 32] = rand::random();
        let (commitment, _) = signer
            .frost_commit(group, &dummy_session, &dummy_message)
            .map_err(|e| KeepError::Other(format!("Commitment {} failed: {}", i, e)))?;
        let commitment_hex = hex::encode(&commitment);
        commitments_hex.push(commitment_hex.clone());
        nonces.push(serde_json::json!({
            "index": i,
            "commitment": commitment_hex,
        }));
    }
    spinner.finish();

    let spinner = out.spinner("Storing nonces locally...");
    for commitment_hex in &commitments_hex {
        nonce_store
            .add_nonce(group, commitment_hex)
            .map_err(|e| KeepError::Other(format!("Failed to store nonce: {}", e)))?;
    }
    spinner.finish();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| KeepError::Other(format!("Runtime error: {}", e)))?;

    rt.block_on(async {
        let keys = Keys::generate();
        let client = Client::new(keys.clone());

        client
            .add_relay(relay)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to add relay: {}", e)))?;
        client.connect().await;

        out.info("Connected to relay");
        out.field(
            "Node pubkey",
            &keys.public_key().to_bech32().unwrap_or_default(),
        );

        let content = serde_json::json!({
            "nonces": nonces,
        })
        .to_string();

        let event = EventBuilder::new(Kind::Custom(21106), &content)
            .tag(Tag::custom(TagKind::custom("d"), vec![group.to_string()]))
            .tag(Tag::custom(
                TagKind::custom("participant_index"),
                vec![share_index.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("nonce_start"),
                vec!["0".to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("nonce_count"),
                vec![count.to_string()],
            ))
            .sign_with_keys(&keys)
            .map_err(|e| KeepError::Other(format!("Failed to sign event: {}", e)))?;

        let spinner = out.spinner("Publishing nonce commitments...");
        client
            .send_event(&event)
            .await
            .map_err(|e| KeepError::Other(format!("Failed to publish: {}", e)))?;
        spinner.finish();

        Ok::<_, KeepError>(())
    })?;

    let (available, used) = nonce_store.nonce_stats(group);
    out.newline();
    out.success(&format!("Published {} nonce commitments!", count));
    out.newline();
    out.info(&format!(
        "Nonce status for group: {} available, {} used",
        available, used
    ));
    out.warn("Each nonce can only be used once. Reusing nonces compromises security.");

    Ok(())
}
