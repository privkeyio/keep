// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::sync::{Arc, Mutex};

use nostr_sdk::prelude::*;
use secrecy::ExposeSecret;
use tracing::debug;
use zeroize::Zeroize;

use keep_core::error::{FrostError, KeepError, NetworkError, Result};
use keep_core::wallet::{WalletDescriptor, INITIAL_DESCRIPTOR_VERSION};
use keep_core::Keep;

use crate::output::Output;
use crate::signer::HardwareSigner;

use super::get_password;

mod attestation;
mod dkg;
mod hardware;

pub use attestation::cmd_frost_network_attestation_provision;
pub use dkg::{cmd_frost_network_dkg, cmd_frost_network_group_create};
pub use hardware::{cmd_frost_network_nonce_precommit, cmd_frost_network_sign_hardware};

/// Fixed OPRF unlock input (the design's fixed label). Both provisioning and
/// every boot-time unlock derive the LUKS key from this same input, so they
/// agree by construction.
const OPRF_UNLOCK_INPUT: &[u8] = b"keep-node-vault-v1";

/// Build a `KeepDescriptorLookup` from an `Arc<Mutex<Keep>>`. Logs a warning
/// and returns no match when the vault is locked or the mutex is poisoned.
fn descriptor_lookup_for(
    keep: Arc<Mutex<Keep>>,
) -> keep_frost_net::KeepDescriptorLookup<
    impl Fn() -> Option<Vec<WalletDescriptor>> + Send + Sync + 'static,
> {
    keep_frost_net::KeepDescriptorLookup::new(move || {
        let guard = keep.lock().ok()?;
        guard.list_all_wallet_descriptor_versions().ok()
    })
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_serve(
    out: &Output,
    path: &Path,
    group_npub: &str,
    relay: &str,
    share_index: Option<u16>,
    auto_contribute_descriptor: bool,
    refuse_raw_sign: bool,
    attestation_config: Option<&Path>,
    insecure_no_attestation: bool,
    oprf_share_file: Option<&Path>,
    oprf_dealer: Option<u16>,
    tpm_tcti: Option<&str>,
) -> Result<()> {
    debug!(group = group_npub, relay, share = ?share_index, refuse_raw_sign, "starting FROST network node");

    // Resolve the attestation policy up front (fail-closed) so a missing or
    // invalid one fails before we prompt for the password or touch the vault.
    let tpm_policy =
        attestation::resolve_serve_policy(out, attestation_config, insecure_no_attestation)?;

    // Producer side: when this node attests via a TPM, attach a quote to every
    // announce so peers can verify it (and a holder can pin it via
    // `attestation-provision`). Built before unlocking so it fails fast.
    let attestor = attestation::optional_announce_attestor(out, tpm_tcti)?;

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
    out.field("Threshold", &format!("{threshold}-of-{total_shares}"));
    out.field("Relay", relay);
    out.newline();

    // Load this holder's OPRF key share if the file is present, so the node can
    // answer evaluation requests. An absent file means the node serves without a
    // share (e.g. awaiting its first enrollment); the share is sealed into this
    // same path on enrollment and takes effect on the next start.
    let oprf_share: Option<keep_core::oprf::threshold::KeyShare> = match oprf_share_file {
        Some(p) => match std::fs::read(p) {
            Ok(raw) => {
                let bytes = zeroize::Zeroizing::new(raw);
                let share = keep_core::oprf::threshold::deserialize_key_share(&bytes)
                    .map_err(|e| KeepError::Frost(format!("invalid OPRF key share: {e}")))?;
                Some(share)
            }
            // Absent file: serve without a share (e.g. awaiting first enrollment).
            // Any other failure (permissions, I/O) on a configured path is fatal,
            // not silently ignored.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(KeepError::Runtime(format!("read OPRF share file: {e}"))),
        },
        None => None,
    };
    // Where an enrolled share is sealed, owned so the event loop can move it.
    let oprf_seal_path = oprf_share_file.map(|p| p.to_path_buf());

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    let keep = std::sync::Arc::new(std::sync::Mutex::new(keep));

    let unlock_result = rt.block_on(async move {
        out.info("Starting FROST coordination node...");

        let node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        let mut node =
            node.with_descriptor_lookup(Arc::new(descriptor_lookup_for(keep.clone())));
        if let Some(policy) = tpm_policy {
            let pinned = policy.pinned_aks.len();
            node.set_tpm_attestation_policy(policy);
            out.field(
                "Attestation",
                &format!("TPM policy enforced ({pinned} peer(s) pinned)"),
            );
        } else {
            out.field("Attestation", "DISABLED (--insecure-no-attestation)");
        }
        if refuse_raw_sign {
            node.set_hooks(Arc::new(keep_frost_net::RefuseRawSignatureHooks));
            out.field(
                "Sign policy",
                "refuse raw (`message_type=raw` rejected, see #524)",
            );
        }
        // OPRF holder runtime: install the loaded share so this node answers
        // evaluation requests, and pin the dealer that may enroll it.
        if let Some(share) = oprf_share {
            node = node.with_oprf_key_share(share);
            out.field("OPRF holder", "share loaded (answering evaluations)");
        } else if oprf_share_file.is_some() {
            out.field("OPRF holder", "no share yet (awaiting enrollment)");
        }
        if let Some(dealer) = oprf_dealer {
            node.set_expected_oprf_dealer(dealer);
            out.field("OPRF dealer", &format!("pinned to share {dealer}"));
        }
        attestation::set_optional_announce_attestor(out, &mut node, attestor);
        let node = std::sync::Arc::new(node);

        let pk = node.pubkey();
        let npub = pk.to_bech32().unwrap_or_else(|_| format!("{pk}"));
        out.field("Node pubkey", &npub);
        out.newline();
        out.info("Listening for FROST messages... (Ctrl+C to stop)");

        let mut event_rx = node.subscribe();
        let event_node = node.clone();
        let event_keep = keep.clone();
        let event_seal_path = oprf_seal_path;
        let event_task = tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(keep_frost_net::KfpNodeEvent::PsbtSignatureNeeded {
                        session_id,
                        tier_index,
                        ..
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        tracing::warn!(
                            session,
                            tier_index,
                            "PSBT signature requested but `frost network serve` does not yet implement signer contribution; the initiator will time out."
                        );
                    }
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
                    Ok(keep_frost_net::KfpNodeEvent::SigningFailed { session_id, error, .. }) => {
                        let session = hex::encode(&session_id[..8]);
                        tracing::error!(session, error, "signing failed");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::DescriptorContributionNeeded {
                        session_id,
                        network,
                        initiator_pubkey,
                        ..
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        if !auto_contribute_descriptor {
                            tracing::warn!(
                                session,
                                "descriptor contribution requested but --auto-contribute-descriptor not set, ignoring"
                            );
                            continue;
                        }
                        tracing::info!(session, "descriptor contribution requested, auto-contributing");
                        let contribute_node = event_node.clone();
                        let net = network.clone();
                        tokio::spawn(async move {
                            let session = hex::encode(&session_id[..8]);
                            let derived = tokio::task::spawn_blocking({
                                let node = contribute_node.clone();
                                move || node.derive_account_xpub(&net)
                            })
                            .await;
                            let xpub_result = match derived {
                                Ok(inner) => inner,
                                Err(e) => Err(keep_frost_net::FrostNetError::Crypto(e.to_string())),
                            };
                            match xpub_result {
                                Ok((xpub, fingerprint)) => {
                                    if let Err(e) = contribute_node
                                        .contribute_descriptor(
                                            session_id,
                                            &initiator_pubkey,
                                            &xpub,
                                            &fingerprint,
                                        )
                                        .await
                                    {
                                        tracing::error!(session, error = %e, "failed to contribute descriptor");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(session, error = %e, "failed to derive xpub for contribution");
                                }
                            }
                        });
                    }
                    Ok(keep_frost_net::KfpNodeEvent::DescriptorComplete {
                        session_id,
                        external_descriptor,
                        internal_descriptor,
                        network,
                        policy_hash,
                        version,
                        policy,
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        let desc_short = match external_descriptor.get(..40) {
                            Some(prefix) => format!("{prefix}..."),
                            None => external_descriptor.clone(),
                        };
                        tracing::info!(session, descriptor = desc_short, "descriptor complete");

                        let keep = event_keep.clone();
                        tokio::task::spawn_blocking(move || {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let policy_value = match serde_json::to_value(&policy) {
                                Ok(v) => Some(v),
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        session = %hex::encode(&session_id[..8]),
                                        group = %hex::encode(group_pubkey),
                                        "failed to serialize WalletPolicy to JSON (recovery-tier verification will be unavailable for this descriptor)",
                                    );
                                    None
                                }
                            };
                            // The predecessor lookup and the subsequent store
                            // are not held under a single critical section
                            // beyond `keep.lock()`; a second migrate event
                            // could in principle race here. In the CLI this
                            // is acceptable because event handling for a
                            // single node is serialized through this task
                            // and only one migration can be in flight per
                            // group at the protocol layer.
                            let guard = keep.lock().expect("keep mutex poisoned");
                            // Single load reused for both the predecessor-hash
                            // computation below and the supersession WARN.
                            let prior = guard.get_wallet_descriptor(&group_pubkey);
                            let previous_descriptor_hash = if version > INITIAL_DESCRIPTOR_VERSION {
                                match &prior {
                                    Ok(Some(prev)) => {
                                        if prev.version != version - 1 {
                                            tracing::error!(
                                                version,
                                                predecessor_version = prev.version,
                                                "refusing to persist migrated descriptor: predecessor version is not the immediate predecessor"
                                            );
                                            return;
                                        }
                                        Some(prev.canonical_hash())
                                    }
                                    Ok(None) => {
                                        tracing::error!(
                                            version,
                                            "refusing to persist migrated descriptor: no predecessor descriptor found"
                                        );
                                        return;
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            error = %e,
                                            version,
                                            "refusing to persist migrated descriptor: failed to load predecessor"
                                        );
                                        return;
                                    }
                                }
                            } else {
                                None
                            };
                            let descriptor = WalletDescriptor {
                                group_pubkey,
                                external_descriptor,
                                internal_descriptor,
                                network,
                                created_at: now,
                                device_registrations: Vec::new(),
                                policy_hash,
                                version,
                                previous_descriptor_hash,
                                policy: policy_value,
                            };
                            // #426 (b): when a finalized descriptor lands on a
                            // group that already has one, log a single WARN
                            // naming the from/to versions and hashes so the
                            // operator can see the supersession in the journal.
                            // Responders trust the proposer's authority (the
                            // message is authenticated under the group) so we
                            // don't block; the gate lives on the proposer side.
                            if let Ok(Some(prior)) = &prior {
                                let new_hash = descriptor.canonical_hash();
                                let prior_hash = prior.canonical_hash();
                                if prior_hash != new_hash {
                                    tracing::warn!(
                                        group = %hex::encode(group_pubkey),
                                        from_version = prior.version,
                                        from_hash = %hex::encode(prior_hash),
                                        to_version = descriptor.version,
                                        to_hash = %hex::encode(new_hash),
                                        "replacing finalized wallet descriptor for group (see #426)"
                                    );
                                }
                            }
                            match guard.store_wallet_descriptor(&descriptor) {
                                Ok(()) => {
                                    tracing::info!("wallet descriptor stored");
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "failed to store wallet descriptor");
                                }
                            }
                        });
                    }
                    Ok(keep_frost_net::KfpNodeEvent::DescriptorNacked {
                        session_id,
                        share_index,
                        reason,
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        tracing::error!(session, share_index, reason, "descriptor nacked by peer");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::DescriptorFailed {
                        session_id,
                        error,
                    }) => {
                        let session = hex::encode(&session_id[..8]);
                        tracing::error!(session, error, "descriptor session failed");
                    }
                    Ok(keep_frost_net::KfpNodeEvent::OprfShareReceived {
                        dealer_index,
                        share,
                        seal_ack,
                        ..
                    }) => {
                        // Durable custody: seal the enrolled share to disk, then
                        // ack only on a confirmed write so the dealer is never told
                        // enrollment completed with nothing sealed.
                        let sealed = match &event_seal_path {
                            Some(path) => {
                                // The seal write fsyncs the file and its parent dir;
                                // keep those blocking syscalls off the executor.
                                let bytes =
                                    zeroize::Zeroizing::new(share.as_slice().to_vec());
                                let owned_path = path.clone();
                                let write = tokio::task::spawn_blocking(move || {
                                    write_secret_file(&owned_path, bytes.as_slice())
                                })
                                .await;
                                match write {
                                    Ok(Ok(())) => {
                                        tracing::info!(
                                            dealer_index,
                                            path = %path.display(),
                                            "sealed enrolled OPRF share; restart serve with --oprf-share-file to answer evaluations"
                                        );
                                        true
                                    }
                                    Ok(Err(e)) => {
                                        tracing::error!(error = %e, "failed to seal enrolled OPRF share");
                                        false
                                    }
                                    Err(e) => {
                                        tracing::error!(error = %e, "seal write task failed");
                                        false
                                    }
                                }
                            }
                            None => {
                                tracing::error!(
                                    "received an OPRF enrollment but --oprf-share-file is not set; cannot seal"
                                );
                                false
                            }
                        };
                        match seal_ack.lock() {
                            Ok(mut g) => {
                                if let Some(tx) = g.take() {
                                    let _ = tx.send(sealed);
                                }
                            }
                            Err(_) => {
                                tracing::error!(
                                    "seal_ack mutex poisoned; cannot ack OPRF enrollment, dealer will time out"
                                );
                            }
                        }
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
    });

    // The sealed file bytes are wiped via `Zeroizing`, and the node-resident copy is
    // wiped by `KfpNode`'s `Drop`. `KeyShare` is `Copy` + `Zeroize` but not
    // `ZeroizeOnDrop`, so this wipes our remaining local copy by hand.
    if let Some(mut share) = oprf_share {
        share.zeroize();
    }
    unlock_result?;

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

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

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

        let _run_guard = NodeRunGuard::aborting(tokio::spawn({
            let node = node.clone();
            async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            }
        }));

        // Peers announce every 20s. A bare 3s sleep was missing most announces.
        // Poll for up to 25s, exit early as soon as we see anyone.
        const PEER_DISCOVERY_WINDOW: std::time::Duration = std::time::Duration::from_secs(25);
        const PEER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
        let deadline = tokio::time::Instant::now() + PEER_DISCOVERY_WINDOW;
        while tokio::time::Instant::now() < deadline {
            if node.online_peers() > 0 {
                break;
            }
            tokio::time::sleep(PEER_POLL_INTERVAL).await;
        }
        spinner.finish();

        let status = node.peer_status();

        if status.is_empty() {
            out.info("No peers discovered yet (waited up to 25s; announce interval is 20s).");
            out.info("Run 'keep frost network serve' on other devices first.");
        } else {
            out.table_header(&[("SHARE", 8), ("STATUS", 10), ("NAME", 20)]);

            for (share_index, peer_status, name, _pubkey) in status {
                use keep_frost_net::PeerStatus;
                let status_str = match peer_status {
                    PeerStatus::Online => "Online",
                    PeerStatus::Offline => "Offline",
                    PeerStatus::Unknown => "Unknown",
                };
                out.table_row(&[
                    (&share_index.to_string(), 8, false),
                    (status_str, 10, false),
                    (&name.unwrap_or_else(|| "-".to_string()), 20, false),
                ]);
            }
        }

        out.newline();
        out.info(&format!("{} peer(s) online", node.online_peers()));

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

#[tracing::instrument(skip(out, warden_url, message), fields(path = %path.display()))]
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
                let mut signer = HardwareSigner::new(device).map_err(|e| {
                    KeepError::NetworkErr(NetworkError::connection(format!("hardware: {e}")))
                })?;
                let info = signer.get_share_info(group_npub).map_err(|e| {
                    KeepError::FrostErr(FrostError::session(format!(
                        "failed to get share info: {e}"
                    )))
                })?;
                (
                    threshold.unwrap_or(info.threshold),
                    participants.unwrap_or(info.participants),
                )
            }
        };
        if threshold < 2 || threshold > participants {
            return Err(KeepError::FrostErr(FrostError::invalid_config(format!(
                "must be 2 <= threshold ({threshold}) <= participants ({participants})"
            ))));
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
            .map_err(|e| KeepError::Runtime(format!("tokio: {}", e)))?;
        rt.block_on(super::frost::check_warden_policy(
            out, url, group_npub, message,
        ))?;
    }

    #[cfg(not(feature = "warden"))]
    if warden_url.is_some() {
        return Err(KeepError::NotImplemented(
            "Warden support not compiled. Rebuild with --features warden".into(),
        ));
    }

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

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    let signature = rt.block_on(frost_network_sign_round(
        out,
        share,
        relay,
        message.as_bytes().to_vec(),
        "raw",
    ))?;

    out.newline();
    out.success("Signature complete!");
    out.field("Signature", &hex::encode(signature));
    Ok(())
}

/// Construct the unsigned Nostr event whose canonical event id the FROST
/// group will sign. Authored by the group x-only pubkey so the resulting
/// signed event verifies under standard BIP-340 against the group key.
fn build_unsigned_frost_event(
    group_pubkey_bytes: &[u8; 32],
    kind: u16,
    content: &str,
    created_at: Timestamp,
) -> Result<(PublicKey, UnsignedEvent, EventId)> {
    let group_pubkey = PublicKey::from_slice(group_pubkey_bytes).map_err(|e| {
        KeepError::InvalidInput(format!("group pubkey is not a valid x-only pubkey: {e}"))
    })?;
    let mut unsigned = UnsignedEvent::new(
        group_pubkey,
        created_at,
        Kind::Custom(kind),
        Vec::<Tag>::new(),
        content.to_string(),
    );
    unsigned.ensure_id();
    let event_id = unsigned
        .id
        .ok_or_else(|| KeepError::Runtime("failed to compute event ID".into()))?;
    Ok((group_pubkey, unsigned, event_id))
}

/// Shared signing round used by `cmd_frost_network_sign` and
/// `cmd_frost_network_sign_event`: brings up a `KfpNode`, waits for peers,
/// requests an aggregated signature, and returns the 64-byte schnorr sig.
async fn frost_network_sign_round(
    out: &Output,
    share: keep_core::frost::SharePackage,
    relay: &str,
    message_bytes: Vec<u8>,
    message_type: &str,
) -> Result<[u8; 64]> {
    let mut node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
        .await
        .map_err(|e| KeepError::Frost(e.to_string()))?;

    out.info("Starting FROST coordination node...");
    let pk = node.pubkey();
    out.field(
        "Node pubkey",
        &pk.to_bech32().unwrap_or_else(|_| format!("{pk}")),
    );
    out.newline();

    // Take the cooperative shutdown sender before sharing the node behind an
    // Arc; the guard uses it to ask run() to break at its next loop iteration.
    let shutdown_tx = node.take_shutdown_handle();
    let node = std::sync::Arc::new(node);
    let node_clone = node.clone();
    // RAII guard so the background run() task is wound down on every exit path
    // (Ok return, the `?` from `request_signature`, or a panic), not silently
    // detached until the surrounding tokio runtime tears down. See #525.
    let _run_guard = NodeRunGuard {
        handle: tokio::spawn(async move {
            let _ = node_clone.run().await;
        }),
        shutdown: shutdown_tx,
    };

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
        .request_signature(message_bytes, message_type)
        .await
        .map_err(|e| KeepError::Frost(e.to_string()))?;
    spinner.finish();
    Ok(signature)
}

/// Winds down the background `KfpNode::run()` task on drop so a signing
/// helper's every exit path (Ok return, `?` error, panic) stops the relay
/// loop instead of leaving a detached task for the surrounding tokio runtime
/// to cancel much later (#525). Signals the node's cooperative shutdown
/// channel so an in-flight `handle_event` finishes and the loop breaks at its
/// next iteration, dropping the task's `Arc<KfpNode>` and its relay
/// subscriptions. If no shutdown channel was captured, falls back to aborting
/// the task so it can never leak.
struct NodeRunGuard {
    handle: tokio::task::JoinHandle<()>,
    shutdown: Option<tokio::sync::mpsc::Sender<()>>,
}

impl NodeRunGuard {
    /// Aborts `handle` on drop with no cooperative channel. For short-lived
    /// probes (peer discovery, health check) that just need the `run()` task
    /// torn down on every exit path, including early `?` returns and panics.
    fn aborting(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle,
            shutdown: None,
        }
    }
}

impl Drop for NodeRunGuard {
    fn drop(&mut self) {
        match self.shutdown.take() {
            Some(tx) => {
                let _ = tx.try_send(());
            }
            None => self.handle.abort(),
        }
    }
}

#[tracing::instrument(skip(out, content), fields(path = %path.display()))]
#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_sign_event(
    out: &Output,
    path: &Path,
    group_npub: &str,
    kind: u16,
    content: &str,
    relay: &str,
    share_index: Option<u16>,
    hardware: Option<&str>,
) -> Result<()> {
    if hardware.is_some() {
        // Hardware co-signers only publish their signature share and wait for
        // a coordinator to aggregate; the final 64-byte schnorr signature is
        // never observed locally, so we cannot construct the signed event on
        // this side. Tracked separately so the software flow can ship now.
        return Err(KeepError::NotImplemented(
            "hardware FROST network sign-event requires aggregate-receive plumbing on the hardware path; \
             run the same group with a software participant who can aggregate, or see follow-up issue."
                .into(),
        ));
    }

    debug!(group_npub, kind, relay, "frost network sign-event");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey_bytes = keep_core::keys::npub_to_bytes(group_npub)?;
    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey_bytes, idx)?,
        None => keep.frost_get_share(&group_pubkey_bytes)?,
    };

    // Build the unsigned event with the FROST group pubkey as the author so
    // the computed event id is what the aggregate signature will commit to.
    let (group_pubkey, unsigned, event_id) =
        build_unsigned_frost_event(&group_pubkey_bytes, kind, content, Timestamp::now())?;

    out.newline();
    out.header("FROST Network Sign Event");
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
    out.field("Kind", &kind.to_string());
    out.field("Event ID", &event_id.to_hex());
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;
    let sig_bytes = rt.block_on(frost_network_sign_round(
        out,
        share,
        relay,
        event_id.as_bytes().to_vec(),
        keep_frost_net::MSG_TYPE_NOSTR_EVENT,
    ))?;

    let sig = nostr_sdk::secp256k1::schnorr::Signature::from_slice(&sig_bytes).map_err(|e| {
        KeepError::Runtime(format!(
            "aggregate signature was not a valid schnorr signature: {e}"
        ))
    })?;
    let signed = Event::new(
        event_id,
        group_pubkey,
        unsigned.created_at,
        unsigned.kind,
        unsigned.tags,
        unsigned.content,
        sig,
    );
    // Verify the assembled event against the group x-only key before emitting:
    // if the aggregate signature or the group npub's parity diverges from the
    // signing key, fail loudly here instead of publishing an event that no
    // relay or client can verify.
    signed.verify().map_err(|e| {
        KeepError::Runtime(format!(
            "assembled event failed signature verification: {e}"
        ))
    })?;
    let json = serde_json::to_string(&signed)
        .map_err(|e| KeepError::Runtime(format!("serialize signed event: {e}")))?;

    out.newline();
    out.success("Signature complete!");
    out.newline();
    println!("{json}");
    Ok(())
}

#[tracing::instrument(skip(out), fields(path = %path.display()))]
pub fn cmd_frost_network_health_check(
    out: &Output,
    path: &Path,
    group: &str,
    relay: &str,
    share_index: Option<u16>,
    timeout: u64,
) -> Result<()> {
    const MAX_HEALTH_CHECK_TIMEOUT_SECS: u64 = 3600;
    if timeout == 0 || timeout > MAX_HEALTH_CHECK_TIMEOUT_SECS {
        return Err(KeepError::InvalidInput(format!(
            "timeout must be between 1 and {MAX_HEALTH_CHECK_TIMEOUT_SECS} seconds"
        )));
    }
    debug!(group, relay, share = ?share_index, timeout, "health check");

    let mut keep = Keep::open(path)?;
    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group)?;

    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };

    out.newline();
    out.header("Key Health Check");
    out.field("Group", group);
    out.field("Relay", relay);
    out.field("Timeout", &format!("{timeout}s"));
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    rt.block_on(async {
        let node = std::sync::Arc::new(
            keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
                .await
                .map_err(|e| KeepError::Frost(e.to_string()))?,
        );

        node.announce()
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;

        let _run_guard = NodeRunGuard::aborting(tokio::spawn({
            let node = node.clone();
            async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "FROST node error");
                }
            }
        }));

        let spinner = out.spinner("Discovering peers...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        spinner.finish();

        let online = node.online_peers();
        out.info(&format!("{online} peer(s) discovered"));

        if online == 0 {
            out.newline();
            out.warn("No peers discovered. Run 'keep frost network serve' on other devices first.");
            return Ok::<_, KeepError>(());
        }

        let spinner = out.spinner(&format!("Pinging peers (timeout: {timeout}s)..."));
        let result = node
            .health_check(std::time::Duration::from_secs(timeout))
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        spinner.finish();

        out.newline();
        out.header("Results");

        if !result.responsive.is_empty() {
            let shares: Vec<String> = result.responsive.iter().map(|s| s.to_string()).collect();
            out.field("Responsive", &shares.join(", "));
        }
        if !result.unresponsive.is_empty() {
            let shares: Vec<String> = result.unresponsive.iter().map(|s| s.to_string()).collect();
            out.field("Unresponsive", &shares.join(", "));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (&idx, responsive) in result
            .responsive
            .iter()
            .map(|i| (i, true))
            .chain(result.unresponsive.iter().map(|i| (i, false)))
        {
            let existing = keep.get_health_status(&group_pubkey, idx)?;
            let created_at = existing.and_then(|s| s.created_at).unwrap_or(now);
            let status = keep_core::wallet::KeyHealthStatus {
                group_pubkey,
                share_index: idx,
                last_check_timestamp: now,
                responsive,
                created_at: Some(created_at),
            };
            keep.store_health_status(&status)?;
        }

        out.newline();
        out.success(&format!(
            "{} responsive, {} unresponsive",
            result.responsive.len(),
            result.unresponsive.len()
        ));

        let all_statuses = keep.list_health_statuses()?;
        let group_statuses: Vec<_> = all_statuses
            .iter()
            .filter(|s| s.group_pubkey == group_pubkey)
            .collect();
        if !group_statuses.is_empty() {
            out.newline();
            out.header("Health History");
            for s in &group_statuses {
                let age = now.saturating_sub(s.last_check_timestamp);
                let status_str = if s.responsive {
                    "responsive"
                } else {
                    "unresponsive"
                };
                let staleness = if s.is_critical(now) {
                    " [CRITICAL]"
                } else if s.is_stale(now) {
                    " [STALE]"
                } else {
                    ""
                };
                let age_display = format_duration_ago(age);
                out.field(
                    &format!("Share {}", s.share_index),
                    &format!("{status_str} ({age_display}){staleness}"),
                );
            }
        }

        Ok::<_, KeepError>(())
    })?;

    Ok(())
}

/// FROST-index routing for OPRF share distribution: every holder index in
/// `1..=total` except this box's own index. The serialized OPRF share for
/// holder `j` lives at `shares[j - 1]` (positional, vsss identifier `j`).
fn remote_share_indices(box_id: u16, total: u16) -> Vec<u16> {
    (1..=total).filter(|&j| j != box_id).collect()
}

/// Write secret `bytes` to `path` atomically with mode 0600; the caller owns zeroizing `bytes`.
/// The bytes go to a fresh sibling temp file opened with `create_new` (O_CREAT|O_EXCL, which refuses
/// to follow or clobber a symlink and forces the 0600 mode on a guaranteed-new file), are fsync'd,
/// then `rename`d into place, after which the parent directory is fsync'd so the new name is durable
/// across a crash. This avoids both the `mode()`-only-applies-on-create gap and symlink/TOCTOU on
/// the destination that plain open-truncate has. The containing directory MUST be root-owned for
/// full protection. Used for the LUKS key and the box's own OPRF share.
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    // Clear any stale temp from a crashed run; create_new below still fails closed if an attacker
    // races to recreate it, so this never writes through someone else's file.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // 0600 at creation is the Unix appliance's protection; the mode bit is Unix-only, so gate it
    // (create_new still gives O_EXCL everywhere). This feature targets the NixOS boot gate.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| KeepError::Runtime(format!("create {}: {e}", tmp.display())))?;
    f.write_all(bytes)
        .map_err(|e| KeepError::Runtime(format!("write {}: {e}", tmp.display())))?;
    f.sync_all()
        .map_err(|e| KeepError::Runtime(format!("sync {}: {e}", tmp.display())))?;
    drop(f);
    std::fs::rename(&tmp, path)
        .map_err(|e| KeepError::Runtime(format!("rename to {}: {e}", path.display())))?;
    // fsync the containing directory so the new directory entry is durable across a crash; a
    // rename only persists once the parent directory's metadata is synced.
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| KeepError::Runtime(format!("sync dir {}: {e}", parent.display())))?;
    Ok(())
}

/// Reconstruct a LUKS key from a threshold-OPRF quorum and write the 32 raw key
/// bytes to STDOUT (and nothing else), so a boot gate can pipe it to
/// `cryptsetup open --key-file -`. All human/progress output goes to STDERR via
/// `Output` (which is backed by `Term::stderr()`); the key is never logged.
#[tracing::instrument(skip(out), fields(path = %path.display()))]
#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_oprf_unlock(
    out: &Output,
    path: &Path,
    group_npub: &str,
    relay: &str,
    share_index: Option<u16>,
    volume_id: &str,
    epoch: u32,
    share_file: &Path,
    tpm_tcti: Option<&str>,
) -> Result<()> {
    debug!(
        group = group_npub,
        relay,
        share = ?share_index,
        volume_id,
        epoch,
        "frost network oprf-unlock"
    );

    let mut keep = Keep::open(path)?;

    // Build the announce attestor BEFORE unlocking, so a config mistake (a build
    // without `tpm-attestation`, or an unparseable/unreachable TPM) fails fast
    // without prompting for the password or materializing the OPRF secret.
    let attestor = attestation::optional_announce_attestor(out, tpm_tcti)?;

    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };

    // Build the async runtime BEFORE materializing the OPRF key share, so a runtime-construction
    // failure cannot leave the live secret scalar (Copy + Zeroize, not ZeroizeOnDrop) resident on
    // an early `?` return.
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    // Read this box's OPRF key share credential (64 raw bytes; the TPM-unsealed
    // secret at boot). Held in a Zeroizing buffer so the raw bytes are wiped on
    // drop; deserialize it, then explicitly wipe and drop the buffer.
    let mut share_bytes = zeroize::Zeroizing::new(
        std::fs::read(share_file)
            .map_err(|e| KeepError::Runtime(format!("read OPRF share file: {e}")))?,
    );
    let mut oprf_share = keep_core::oprf::threshold::deserialize_key_share(&share_bytes)
        .map_err(|e| KeepError::Frost(format!("invalid OPRF key share: {e}")))?;
    share_bytes.zeroize();
    drop(share_bytes);

    out.newline();
    out.header("OPRF Unlock");
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
    out.field("Volume", volume_id);
    out.field("Epoch", &epoch.to_string());
    out.newline();

    let result = rt.block_on(async move {
        let mut node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        // Install the OPRF key share BEFORE running so this box can answer its
        // own quorum's evaluate requests.
        node.set_oprf_key_share(oprf_share);

        // If a TPM is configured, attach the fresh measured-boot quote source to
        // every announce so holders can verify this box before answering evals.
        attestation::set_optional_announce_attestor(out, &mut node, attestor);

        out.info("Starting FROST coordination node...");
        let shutdown_tx = node.take_shutdown_handle();
        let node = std::sync::Arc::new(node);
        let node_clone = node.clone();
        let _run_guard = NodeRunGuard {
            handle: tokio::spawn(async move {
                let _ = node_clone.run().await;
            }),
            shutdown: shutdown_tx,
        };

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
        out.info("Waiting for peers to discover us...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        node.request_oprf_unlock(OPRF_UNLOCK_INPUT, volume_id, epoch)
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))
    });
    // `KeyShare` is `Copy` + `Zeroize` but NOT `ZeroizeOnDrop`: the copy moved
    // into the async block is gone with the node, but our local copy must be
    // wiped by hand on both the Ok and Err paths.
    oprf_share.zeroize();
    let key = result?;

    // The reconstructed 32-byte LUKS key is the ONLY thing written to STDOUT.
    // It is never logged.
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&key[..])
        .map_err(|e| KeepError::Runtime(format!("write key to stdout: {e}")))?;
    stdout
        .flush()
        .map_err(|e| KeepError::Runtime(format!("flush stdout: {e}")))?;

    out.success("Unlock key written to stdout.");
    Ok(())
}

/// One-time setup: this box is the trusted dealer. Generate the OPRF key, split
/// it `threshold`-of-`total`, distribute the remote holders' shares over the
/// network (NIP-44 encrypted), and write the matching LUKS key and this box's
/// own OPRF share to 0600 files. Secrets only ever reach the 0600 files or
/// `distribute_oprf_shares`; they are never logged.
#[tracing::instrument(skip(out), fields(path = %path.display()))]
#[allow(clippy::too_many_arguments)]
pub fn cmd_frost_network_oprf_provision(
    out: &Output,
    path: &Path,
    group_npub: &str,
    relay: &str,
    share_index: Option<u16>,
    volume_id: &str,
    epoch: u32,
    threshold: u16,
    total: u16,
    key_out: &Path,
    share_out: &Path,
    tpm_tcti: Option<&str>,
) -> Result<()> {
    debug!(
        group = group_npub,
        relay,
        share = ?share_index,
        volume_id,
        epoch,
        threshold,
        total,
        "frost network oprf-provision"
    );

    let mut keep = Keep::open(path)?;

    // Build the announce attestor BEFORE unlocking, so a config mistake (a build
    // without `tpm-attestation`, or an unparseable/unreachable TPM) fails fast.
    // The dealer MUST attest: holders gate enrollment on a Verified dealer, so a
    // box that does not attach a quote here cannot distribute any share.
    let attestor = attestation::optional_announce_attestor(out, tpm_tcti)?;

    let password = get_password("Enter password")?;

    let spinner = out.spinner("Unlocking vault...");
    keep.unlock(password.expose_secret())?;
    spinner.finish();

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let share = match share_index {
        Some(idx) => keep.frost_get_share_by_index(&group_pubkey, idx)?,
        None => keep.frost_get_share(&group_pubkey)?,
    };
    let box_id = share.metadata.identifier;
    let box_name = share.metadata.name.clone();

    // The OPRF holder set IS the FROST group: remote shares are routed to the group's holder
    // indices, and `oprf-unlock` derives its quorum size from `share.metadata.threshold`. A
    // `--threshold`/`--total` that diverges from the group metadata would distribute shares to
    // non-existent holders or format the volume against a key no future unlock can reproduce, so
    // refuse the mismatch before generating any key material.
    if total != share.metadata.total_shares || threshold != share.metadata.threshold {
        return Err(KeepError::InvalidInput(format!(
            "OPRF {threshold}-of-{total} must match the FROST group {}-of-{}",
            share.metadata.threshold, share.metadata.total_shares
        )));
    }

    out.newline();
    out.header("OPRF Provision");
    out.field("Group", group_npub);
    out.field("Box share", &format!("{box_id} ({box_name})"));
    out.field("Threshold", &format!("{threshold}-of-{total}"));
    out.field("Relay", relay);
    out.field("Volume", volume_id);
    out.field("Epoch", &epoch.to_string());
    out.newline();

    // Build the async runtime BEFORE generating the OPRF key, so a runtime-construction failure
    // cannot leave the live shares (Copy + Zeroize, not ZeroizeOnDrop) resident on an early `?`
    // return before the zeroize loop below.
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    // Generate the OPRF key, split it t-of-n, and derive the matching LUKS key.
    // `shares` is positional: shares[k] has vsss identifier k+1, i.e. shares[i-1]
    // belongs to FROST participant i. These are live key material.
    let (k_luks, mut shares) = keep_core::oprf::unlock::provision(
        OPRF_UNLOCK_INPUT,
        volume_id,
        epoch,
        threshold as usize,
        total as usize,
    )
    .map_err(|e| KeepError::Frost(format!("OPRF provision failed: {e}")))?;

    if box_id == 0 || box_id as usize > shares.len() {
        for s in shares.iter_mut() {
            s.zeroize();
        }
        return Err(KeepError::InvalidInput(format!(
            "box share index {box_id} is outside 1..={total}"
        )));
    }

    // Serialize the REMOTE holders' shares (every index except this box's) into
    // distribution targets; each serialized buffer is Zeroizing.
    let remote = remote_share_indices(box_id, total);
    let mut targets: Vec<(u16, zeroize::Zeroizing<Vec<u8>>)> = Vec::with_capacity(remote.len());
    for &j in &remote {
        let ser = keep_core::oprf::threshold::serialize_key_share(&shares[j as usize - 1]);
        targets.push((j, zeroize::Zeroizing::new(ser.to_vec())));
    }

    let dist = rt.block_on(async move {
        let mut node = keep_frost_net::KfpNode::new(share, vec![relay.to_string()])
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))?;
        attestation::set_optional_announce_attestor(out, &mut node, attestor);

        out.info("Starting FROST coordination node...");
        let shutdown_tx = node.take_shutdown_handle();
        let node = std::sync::Arc::new(node);
        let node_clone = node.clone();
        let _run_guard = NodeRunGuard {
            handle: tokio::spawn(async move {
                let _ = node_clone.run().await;
            }),
            shutdown: shutdown_tx,
        };

        out.info("Discovering peers (holders must be online to receive)...");
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
        out.info("Waiting for peers to discover us...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        out.info("Distributing OPRF shares to remote holders...");
        node.distribute_oprf_shares(targets, threshold, total)
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))
    });

    // Write the LUKS key and the box's own share only if distribution succeeded;
    // a failed distribution means the quorum can never be reached, so the volume
    // must not be formatted against this key. Always zeroize the share vector.
    let write_result = match dist {
        Ok(()) => {
            // Write the box's own OPRF share first and the LUKS key last: the key file is the
            // "provisioning succeeded" marker a boot gate formats the volume against, so it must
            // only appear once the share needed to service future unlocks is durable. If either
            // write fails, remove whatever was already written so a partial run never leaves an
            // orphaned secret on disk.
            let own = keep_core::oprf::threshold::serialize_key_share(&shares[box_id as usize - 1]);
            write_secret_file(share_out, &own[..])
                .and_then(|()| write_secret_file(key_out, &k_luks[..]))
                .inspect_err(|_| {
                    let _ = std::fs::remove_file(key_out);
                    let _ = std::fs::remove_file(share_out);
                })
        }
        Err(e) => Err(e),
    };
    for s in shares.iter_mut() {
        s.zeroize();
    }
    write_result?;

    out.newline();
    out.success(&format!(
        "Provisioned: distributed {} remote OPRF share(s); wrote LUKS key and own share (mode 0600).",
        remote.len()
    ));
    Ok(())
}

fn format_duration_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_share_indices_excludes_box_and_covers_rest() {
        // Box 2 of a 3-holder set must route to holders 1 and 3 only; the OPRF
        // share for holder j lives at shares[j-1], so a wrong index map would
        // hand a holder the wrong share and break every future quorum.
        assert_eq!(remote_share_indices(2, 3), vec![1, 3]);
        assert_eq!(remote_share_indices(1, 3), vec![2, 3]);
        assert_eq!(remote_share_indices(3, 3), vec![1, 2]);
        // Single-holder edge case: nothing to distribute.
        assert_eq!(remote_share_indices(1, 1), Vec::<u16>::new());
    }

    #[test]
    fn build_unsigned_frost_event_matches_canonical_nostr_id() {
        // The aggregate signature commits to the canonical Nostr event id.
        // If our derivation drifts from nostr_sdk's serialization, the
        // produced "signed event" verifies against a hash nobody can
        // recompute. Pin it against a fixed input and verify the id matches
        // an independently constructed UnsignedEvent.
        let group_pubkey_bytes = [0x42u8; 32];
        let kind = 1u16;
        let content = "hello FROST";
        let created_at = Timestamp::from_secs(1_700_000_000);

        let (pubkey, _unsigned, event_id) =
            build_unsigned_frost_event(&group_pubkey_bytes, kind, content, created_at).unwrap();

        let mut expected = UnsignedEvent::new(
            pubkey,
            created_at,
            Kind::Custom(kind),
            Vec::<Tag>::new(),
            content.to_string(),
        );
        expected.ensure_id();
        assert_eq!(Some(event_id), expected.id);
    }

    #[test]
    fn assembled_signed_event_verifies_under_group_key() {
        // Exercise the part that can actually break: assembling the final
        // Event from (event_id, group_pubkey, fields..., sig) and emitting it.
        // Sign the canonical event id with a known key exactly as the FROST
        // aggregate would, then assert the assembled event verifies under the
        // group x-only key. Catches field-order/parity mistakes the id-only
        // test cannot.
        use nostr_sdk::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _parity) = keypair.x_only_public_key();
        let group_pubkey_bytes = xonly.serialize();

        let kind = 1u16;
        let content = "hello FROST";
        let created_at = Timestamp::from_secs(1_700_000_000);

        let (group_pubkey, unsigned, event_id) =
            build_unsigned_frost_event(&group_pubkey_bytes, kind, content, created_at).unwrap();

        let msg = Message::from_digest(*event_id.as_bytes());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        let signed = Event::new(
            event_id,
            group_pubkey,
            unsigned.created_at,
            unsigned.kind,
            unsigned.tags,
            unsigned.content,
            sig,
        );

        signed
            .verify()
            .expect("assembled event must verify under the group key");
    }

    /// Dropping `NodeRunGuard` signals the node's cooperative shutdown channel
    /// so a signing helper that returns early via `?` lets the background
    /// `run()` loop break on its own instead of leaking a detached task until
    /// the surrounding tokio runtime tears down (#525).
    #[tokio::test]
    async fn node_run_guard_signals_graceful_shutdown() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

        // Stand in for `KfpNode::run()`'s select! loop: runs until it observes
        // the cooperative shutdown signal, then returns on its own.
        let run_loop = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.recv() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {}
                }
            }
        });

        let guard = NodeRunGuard {
            handle: tokio::spawn(async {}),
            shutdown: Some(tx),
        };
        assert!(
            !run_loop.is_finished(),
            "run loop must still be running before guard drop"
        );

        // Dropping the guard sends `()` on the shutdown channel; the loop
        // breaks and the task completes deterministically (no abort).
        drop(guard);
        run_loop
            .await
            .expect("run loop should complete after graceful shutdown signal");
    }

    /// With no shutdown channel captured, the guard must abort its task on drop
    /// so it can never leak.
    #[tokio::test]
    async fn node_run_guard_aborts_when_no_shutdown_channel() {
        let handle = tokio::spawn(std::future::pending::<()>());
        let abort_handle = handle.abort_handle();

        let guard = NodeRunGuard {
            handle,
            shutdown: None,
        };
        assert!(
            !abort_handle.is_finished(),
            "task must still be running before guard drop"
        );
        drop(guard);

        // The guard aborted the task; spin until the runtime observes the
        // cancellation (terminates as soon as the abort is processed).
        while !abort_handle.is_finished() {
            tokio::task::yield_now().await;
        }
    }
}
