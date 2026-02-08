// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::Path;

use nostr_sdk::prelude::*;
use tracing::debug;

use keep_core::error::{CryptoError, FrostError, KeepError, NetworkError, Result, StorageError};

use crate::output::Output;
use crate::signer::{HardwareSigner, NonceStore};

#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_sign_hardware(
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
        hex::decode(message).map_err(|_| KeepError::InvalidInput("Invalid message hex".into()))?;

    if message_bytes.len() != 32 {
        return Err(KeepError::InvalidInput(
            "Message must be 32 bytes (64 hex chars)".into(),
        ));
    }

    let mut message_arr = [0u8; 32];
    message_arr.copy_from_slice(&message_bytes);

    let mut session_id = [0u8; 32];
    ::rand::TryRngCore::try_fill_bytes(&mut ::rand::rngs::OsRng, &mut session_id)
        .map_err(|e| KeepError::CryptoErr(CryptoError::encryption(format!("RNG failed: {e}"))))?;

    out.newline();
    out.header("FROST Hardware Sign via Relay");
    out.field("Device", device);
    out.field("Group", group_npub);
    out.field("Message", message);
    out.field("Relay", relay);
    out.newline();

    let mut nonce_store = NonceStore::open(path)
        .map_err(|e| KeepError::StorageErr(StorageError::database(format!("nonce store: {e}"))))?;
    let (available, used) = nonce_store.nonce_stats(group_npub);
    out.info(&format!("Nonce status: {available} available, {used} used"));

    let spinner = out.spinner("Connecting to hardware...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::NetworkErr(NetworkError::connection(format!("hardware: {e}"))))?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer.ping().map_err(|e| {
        KeepError::NetworkErr(NetworkError::connection(format!("hardware ping: {e}")))
    })?;
    spinner.finish();
    out.field("Hardware version", &version);

    let spinner = out.spinner("Creating commitment (round 1)...");
    let (commitment, our_index) = signer
        .frost_commit(group_npub, &session_id, &message_arr)
        .map_err(|e| KeepError::FrostErr(FrostError::commitment(e.to_string())))?;
    spinner.finish();

    let commitment_hex = hex::encode(&commitment);

    if our_index == 0 || our_index > participants {
        return Err(KeepError::FrostErr(FrostError::invalid_share(format!(
            "hardware returned invalid share index {our_index}, expected 1..={participants}"
        ))));
    }

    if !nonce_store
        .check_and_add_nonce(group_npub, &commitment_hex)
        .map_err(|e| {
            KeepError::StorageErr(StorageError::database(format!("nonce tracking: {e}")))
        })?
    {
        return Err(KeepError::FrostErr(FrostError::session(
            "nonce has already been used - aborting to prevent key compromise",
        )));
    }

    out.field("Share index", &our_index.to_string());
    out.field("Commitment", &commitment_hex);
    out.field("Session ID", &hex::encode(session_id));
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

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
            .map_err(|e| {
                KeepError::CryptoErr(CryptoError::invalid_signature(format!("sign event: {e}")))
            })?;

        let spinner = out.spinner("Publishing sign request (Kind 21104)...");
        client
            .send_event(&request_event)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::publish(e.to_string())))?;
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
            .map_err(|e| {
                KeepError::CryptoErr(CryptoError::invalid_signature(format!(
                    "sign response: {e}"
                )))
            })?;

        let spinner = out.spinner("Publishing our commitment (Kind 21105)...");
        client.send_event(&response_event).await.map_err(|e| {
            KeepError::NetworkErr(NetworkError::publish(format!("commitment: {e}")))
        })?;
        spinner.finish();

        let filter = Filter::new().kind(Kind::Custom(21105)).custom_tag(
            SingleLetterTag::lowercase(Alphabet::E),
            request_event.id.to_hex(),
        );

        out.info("Waiting for peer commitments...");
        out.field("Threshold", &format!("{threshold}-of-{participants}"));
        let mut peer_commitments: HashMap<u16, String> = HashMap::new();
        peer_commitments.insert(our_index, hex::encode(&commitment));

        let timeout = std::time::Duration::from_secs(120);
        let start = std::time::Instant::now();

        while peer_commitments.len() < threshold as usize {
            if start.elapsed() > timeout {
                return Err(KeepError::NetworkErr(NetworkError::timeout(
                    "waiting for peer commitments",
                )));
            }

            let events = client
                .fetch_events(filter.clone(), std::time::Duration::from_secs(5))
                .await
                .map_err(|e| KeepError::NetworkErr(NetworkError::request(e.to_string())))?;

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
                    if let Entry::Vacant(e) = peer_commitments.entry(peer_idx) {
                        e.insert(peer_commitment.to_string());
                        out.success(&format!("Received commitment from participant {peer_idx}"));
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
            .map(|(idx, c)| format!("{idx}:{c}"))
            .collect::<Vec<_>>()
            .join(",");

        let spinner = out.spinner("Generating signature share (round 2)...");
        let (sig_share, _) = signer
            .frost_sign(group_npub, &session_id, &all_commitments_hex)
            .map_err(|e| KeepError::FrostErr(FrostError::session(format!("sign failed: {e}"))))?;
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
            .map_err(|e| KeepError::CryptoErr(CryptoError::invalid_signature(e.to_string())))?;

        let spinner = out.spinner("Publishing signature share...");
        client
            .send_event(&sig_event)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::publish(e.to_string())))?;
        spinner.finish();

        out.newline();
        out.success("Signature share published!");
        out.info("Waiting for coordinator to aggregate final signature...");

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out))]
pub fn cmd_frost_network_nonce_precommit(
    out: &Output,
    path: &Path,
    group: &str,
    relay: &str,
    device: &str,
    count: u32,
) -> Result<()> {
    debug!(group, relay, device, count, "nonce precommit");

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
        .map_err(|e| KeepError::StorageErr(StorageError::database(format!("nonce store: {e}"))))?;

    let (available, used) = nonce_store.nonce_stats(group);
    if available > 0 {
        out.info(&format!(
            "Existing nonces: {available} available, {used} used"
        ));
    }

    let spinner = out.spinner("Connecting to hardware...");
    let mut signer = HardwareSigner::new(device)
        .map_err(|e| KeepError::NetworkErr(NetworkError::connection(format!("hardware: {e}"))))?;
    spinner.finish();

    let spinner = out.spinner("Verifying connection...");
    let version = signer.ping().map_err(|e| {
        KeepError::NetworkErr(NetworkError::connection(format!("hardware ping: {e}")))
    })?;
    spinner.finish();
    out.field("Hardware version", &version);

    let (_pubkey_hex, share_index) = signer
        .get_share_pubkey(group)
        .map_err(|e| KeepError::FrostErr(FrostError::invalid_share(format!("get pubkey: {e}"))))?;
    out.field("Share index", &share_index.to_string());
    out.newline();

    let spinner = out.spinner(&format!("Generating {count} nonce commitments..."));
    let mut nonces = Vec::new();
    let mut commitments_hex = Vec::new();
    for i in 0..count {
        let mut dummy_session = [0u8; 32];
        let mut dummy_message = [0u8; 32];
        ::rand::TryRngCore::try_fill_bytes(&mut ::rand::rngs::OsRng, &mut dummy_session).map_err(
            |e| KeepError::CryptoErr(CryptoError::encryption(format!("RNG failed: {e}"))),
        )?;
        ::rand::TryRngCore::try_fill_bytes(&mut ::rand::rngs::OsRng, &mut dummy_message).map_err(
            |e| KeepError::CryptoErr(CryptoError::encryption(format!("RNG failed: {e}"))),
        )?;
        let (commitment, _) = signer
            .frost_commit(group, &dummy_session, &dummy_message)
            .map_err(|e| KeepError::FrostErr(FrostError::commitment(format!("nonce {i}: {e}"))))?;
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
        nonce_store.add_nonce(group, commitment_hex).map_err(|e| {
            KeepError::StorageErr(StorageError::database(format!("store nonce: {e}")))
        })?;
    }
    spinner.finish();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

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
            .map_err(|e| KeepError::CryptoErr(CryptoError::invalid_signature(e.to_string())))?;

        let spinner = out.spinner("Publishing nonce commitments...");
        client
            .send_event(&event)
            .await
            .map_err(|e| KeepError::NetworkErr(NetworkError::publish(e.to_string())))?;
        spinner.finish();

        Ok::<_, KeepError>(())
    })?;

    let (available, used) = nonce_store.nonce_stats(group);
    out.newline();
    out.success(&format!("Published {count} nonce commitments!"));
    out.newline();
    out.info(&format!(
        "Nonce status for group: {available} available, {used} used"
    ));
    out.warn("Each nonce can only be used once. Reusing nonces compromises security.");

    Ok(())
}
