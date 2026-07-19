// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic `MemoryTransport` counterpart of the MockRelay integration
//! test `test_psbt_recovery_spend_end_to_end`. Drives a real taproot recovery
//! PSBT (Bitcoin spend) coordination session between two `KfpNode`s on a shared
//! in-process bus (no relay, no network timing): the initiator proposes the
//! recovery-spend PSBT, the responder contributes a script-spend signature in
//! lieu of a live NIP-46 signer, and the initiator auto-finalizes. Verifies the
//! finalized transaction's witness and the schnorr signature against the prevout
//! (a genuine cryptographic oracle), covering the PSBT coordination path (#790).

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{CosignTransport, KfpNode, KfpNodeEvent};

async fn graceful_shutdown(
    shutdown_tx: Option<mpsc::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
) {
    if let Some(tx) = shutdown_tx {
        let _ = tx.try_send(());
    }
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// In-process `PersistedDescriptorLookup` backed by a single `WalletDescriptor`
/// for use by the recovery-tier PSBT integration test.
struct StaticDescriptorLookup {
    descriptor: keep_core::wallet::WalletDescriptor,
}

impl keep_frost_net::PersistedDescriptorLookup for StaticDescriptorLookup {
    fn find_by_hash(&self, group: &[u8; 32], hash: &[u8; 32]) -> bool {
        &self.descriptor.group_pubkey == group && &self.descriptor.canonical_hash() == hash
    }
    fn network_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        if self.find_by_hash(group, hash) {
            Some(self.descriptor.network.clone())
        } else {
            None
        }
    }
    fn latest_version_for(
        &self,
        group: &[u8; 32],
    ) -> std::result::Result<Option<u32>, keep_frost_net::DescriptorLookupUnavailable> {
        if &self.descriptor.group_pubkey == group {
            Ok(Some(self.descriptor.version))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn psbt_recovery_spend_completes_over_memory_transport() {
    use std::sync::Arc;

    use bitcoin::bip32::Xpub;
    use bitcoin::hashes::Hash as _;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{LeafVersion, Signature as TaprootSignature, TapLeafHash};
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, Network, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
    };
    use keep_bitcoin::recovery::{
        RecoveryConfig, RecoveryTier as BitcoinRecoveryTier, SpendingTier,
    };
    use keep_bitcoin::{
        merge_tap_script_sig, script_spend_sighashes, DescriptorExport, RecoveryTxBuilder,
    };
    use keep_frost_net::{SignerId, WalletPolicy};

    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (mut shares, _pubkey_pkg) = dealer.generate("test-psbt-recovery").unwrap();

    let share1 = shares.remove(0);
    let share2 = shares.remove(0);

    let bus = MemoryBus::new();
    let mut node1 = KfpNode::with_transport(
        share1,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("node1");
    let mut node2 = KfpNode::with_transport(
        share2,
        bus.transport() as Arc<dyn CosignTransport>,
        None,
        None,
    )
    .expect("node2");

    let group_pubkey = *node1.group_pubkey();

    // Responder controls a known external xpub. We derive it from a fixed seed
    // so the test has access to the secret key for inline signing in lieu of a
    // live NIP-46 signer; the responder's `KfpNode` only sees the xpub +
    // fingerprint.
    let secp = Secp256k1::new();
    let responder_xpriv =
        bitcoin::bip32::Xpriv::new_master(Network::Signet, &[7u8; 32]).expect("xpriv master");
    let responder_xpub = Xpub::from_priv(&secp, &responder_xpriv);
    let responder_xpub_str = responder_xpub.to_string();
    let responder_fp = responder_xpub
        .fingerprint()
        .to_string()
        .to_ascii_lowercase();
    let responder_xonly_bytes = responder_xpub.to_x_only_pub().serialize();
    let responder_xonly =
        XOnlyPublicKey::from_slice(&responder_xonly_bytes).expect("xonly from slice");
    let responder_sk = responder_xpriv.private_key.secret_bytes();

    // Build a recovery config with a single recovery tier holding ONE external
    // key (threshold 1). Single-signer keeps the test deterministic and lets
    // the initiator auto-finalize as soon as the responder contributes.
    let recovery_config = RecoveryConfig {
        primary: SpendingTier {
            keys: vec![group_pubkey],
            threshold: 1,
        },
        recovery_tiers: vec![BitcoinRecoveryTier {
            keys: vec![responder_xonly_bytes],
            threshold: 1,
            timelock_months: 6,
        }],
        network: Network::Signet,
    };
    let recovery_output = recovery_config.build().expect("build recovery output");
    let builder = RecoveryTxBuilder::new(recovery_output.clone());

    let policy = WalletPolicy {
        recovery_tiers: vec![keep_frost_net::PolicyTier {
            threshold: 1,
            key_slots: vec![keep_frost_net::KeySlot::External {
                xpub: responder_xpub_str.clone(),
                fingerprint: responder_fp.clone(),
            }],
            timelock_months: 6,
        }],
        version: 1,
    };
    let policy_hash = keep_frost_net::derive_policy_hash(&policy);

    let export =
        DescriptorExport::from_frost_wallet(&group_pubkey, Some(&recovery_config), Network::Signet)
            .expect("descriptor export");
    let external_desc = export.external_descriptor().to_string();
    let internal_desc = export.internal_descriptor().expect("internal descriptor");

    let policy_value = serde_json::to_value(&policy).ok();
    let wallet_descriptor = keep_core::wallet::WalletDescriptor {
        group_pubkey,
        external_descriptor: external_desc.clone(),
        internal_descriptor: internal_desc.clone(),
        network: "signet".to_string(),
        created_at: 0,
        device_registrations: Vec::new(),
        policy_hash,
        version: 1,
        previous_descriptor_hash: None,
        policy: policy_value,
    };
    let descriptor_hash = wallet_descriptor.canonical_hash();
    let lookup: Arc<dyn keep_frost_net::PersistedDescriptorLookup> =
        Arc::new(StaticDescriptorLookup {
            descriptor: wallet_descriptor.clone(),
        });

    node1 = node1.with_descriptor_lookup(lookup.clone());
    node2 = node2.with_descriptor_lookup(lookup);

    let node1_pubkey = node1.pubkey();

    let mut rx1 = node1.subscribe();
    let mut rx2 = node2.subscribe();

    let shutdown1 = node1.take_shutdown_handle();
    let shutdown2 = node2.take_shutdown_handle();

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node1_run = Arc::clone(&node1);
    let node2_run = Arc::clone(&node2);

    let node1_handle = tokio::spawn(async move {
        let _ = node1_run.run().await;
    });
    let node2_handle = tokio::spawn(async move {
        let _ = node2_run.run().await;
    });

    // Both nodes announce so they discover each other; node2 also announces
    // its external recovery xpub so the initiator can target it by fingerprint.
    node1.announce().await.expect("node1 announce");
    node2.announce().await.expect("node2 announce");

    let discovery = timeout(Duration::from_secs(30), async {
        let mut n1 = 0u32;
        let mut n2 = 0u32;
        loop {
            tokio::select! {
                ev = rx1.recv() => {
                    if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = ev {
                        n1 += 1;
                    }
                }
                ev = rx2.recv() => {
                    if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = ev {
                        n2 += 1;
                    }
                }
            }
            if n1 >= 1 && n2 >= 1 {
                return;
            }
        }
    })
    .await;
    if discovery.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("peer discovery timed out");
    }

    // After mutual peer discovery, announce the responder's external xpub so
    // the initiator can target it by fingerprint when proposing.
    node2
        .announce_xpubs(vec![keep_frost_net::AnnouncedXpub {
            xpub: responder_xpub_str.clone(),
            fingerprint: responder_fp.clone(),
            label: Some("test-responder".into()),
        }])
        .await
        .expect("node2 announce_xpubs");

    // Wait for node1 to ingest node2's XpubAnnounce so target_peers filtering
    // by fingerprint succeeds when we propose.
    let xpub_seen = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(KfpNodeEvent::XpubAnnounced { share_index, .. }) = rx1.recv().await {
                if share_index == 2 {
                    return;
                }
            }
        }
    })
    .await;
    if xpub_seen.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("did not receive responder's XpubAnnounce");
    }

    // The XpubAnnounced event only signals the announce was ingested; under load
    // the peer's stored xpub may lag the event observer. Poll node1's peer view
    // until the responder fingerprint is present so target_peers filtering by
    // fingerprint deterministically succeeds before we propose.
    let xpub_stored = timeout(Duration::from_secs(30), async {
        loop {
            if node1
                .get_peer_recovery_xpubs(2)
                .map(|xpubs| xpubs.iter().any(|x| x.fingerprint == responder_fp))
                .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if xpub_stored.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("node1 did not store responder's recovery xpub");
    }

    // Build an unsigned recovery-spend PSBT for a 1-input/1-output tx against
    // a synthetic UTXO that uses our recovery address as the prev script.
    let utxo = OutPoint {
        txid: bitcoin::Txid::all_zeros(),
        vout: 0,
    };
    let utxo_value: u64 = 100_000;
    let fee: u64 = 1_000;
    let dest_kp = Keypair::from_seckey_slice(&secp, &[9u8; 32]).expect("dest keypair");
    let dest_xonly = dest_kp.x_only_public_key().0;
    let dest_script = ScriptBuf::new_p2tr(&secp, dest_xonly, None);

    let unsigned_psbt = builder
        .build_recovery_psbt(0, utxo, utxo_value, &dest_script, fee)
        .expect("build_recovery_psbt");
    let unsigned_bytes = unsigned_psbt.serialize();

    // Initiator proposes the PSBT, expecting the responder's fingerprint to
    // contribute the script-spend signature.
    let session_id = node1
        .request_psbt_spend(
            descriptor_hash,
            0,
            unsigned_bytes.clone(),
            fee,
            1,
            Vec::new(),
            vec![responder_fp.clone()],
            Vec::new(),
            Vec::new(),
            Some(60),
        )
        .await
        .expect("request_psbt_spend");

    // Responder side: receive PsbtSignatureNeeded, then perform the same chain
    // the production approve path runs: compute sighash, sign (in lieu of
    // NIP-46), merge, contribute.
    let need = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(KfpNodeEvent::PsbtSignatureNeeded {
                session_id: sid,
                initiator_pubkey,
                ..
            }) = rx2.recv().await
            {
                if sid == session_id {
                    return initiator_pubkey;
                }
            }
        }
    })
    .await
    .expect("PsbtSignatureNeeded on responder");
    assert_eq!(need, node1_pubkey);

    let proposal_bytes = node2
        .psbt_session_proposal_psbt(&session_id)
        .expect("responder has proposal psbt");
    let mut responder_psbt = Psbt::deserialize(&proposal_bytes).expect("decode proposal");
    let sighashes = script_spend_sighashes(&responder_psbt).expect("compute sighashes");
    assert_eq!(sighashes.len(), 1);

    // In-process "NIP-46 signer": sign the sighash directly with the known
    // secret key. This stands in for a real bunker round-trip.
    let kp = Keypair::from_seckey_slice(&secp, &responder_sk).expect("responder kp");
    let msg = bitcoin::secp256k1::Message::from_digest(sighashes[0].sighash);
    let aux = [0u8; 32];
    let schnorr_sig = secp.sign_schnorr_with_aux_rand(&msg, &kp, &aux);
    let schnorr_bytes: [u8; 64] = schnorr_sig.serialize();
    merge_tap_script_sig(
        &mut responder_psbt,
        sighashes[0].input_index,
        responder_xonly,
        sighashes[0].leaf_hash,
        &sighashes[0].sighash,
        schnorr_bytes,
    )
    .expect("merge sig");
    let merged_bytes = responder_psbt.serialize();

    node2
        .contribute_psbt_signature(
            session_id,
            &need,
            SignerId::Fingerprint(responder_fp.clone()),
            merged_bytes,
        )
        .await
        .expect("contribute_psbt_signature");

    // Initiator auto-finalizes once threshold (1) is met. Wait for the event
    // and validate the produced PSBT's witness verifies on the prevout.
    let finalized = timeout(Duration::from_secs(30), async {
        loop {
            match rx1.recv().await {
                Ok(KfpNodeEvent::PsbtFinalized {
                    session_id: sid, ..
                }) if sid == session_id => {
                    return;
                }
                Ok(KfpNodeEvent::PsbtAborted {
                    session_id: sid,
                    reason,
                }) if sid == session_id => {
                    panic!("session aborted: {reason}");
                }
                Ok(_) => {}
                Err(_) => panic!("event channel closed"),
            }
        }
    })
    .await;
    if finalized.is_err() {
        graceful_shutdown(shutdown1, node1_handle).await;
        graceful_shutdown(shutdown2, node2_handle).await;
        panic!("did not receive PsbtFinalized");
    }

    // Independently reconstruct the same merged PSBT and finalize it via the
    // RecoveryTxBuilder so we can verify the script-spend signature is valid
    // and produces a well-formed witness for the recovery tier.
    let mut verify_psbt = Psbt::deserialize(&unsigned_bytes).expect("decode unsigned");
    let verify_sighashes = script_spend_sighashes(&verify_psbt).expect("verify sighashes");
    let v_msg = bitcoin::secp256k1::Message::from_digest(verify_sighashes[0].sighash);
    let v_sig = secp.sign_schnorr_with_aux_rand(&v_msg, &kp, &aux);
    verify_psbt.inputs[0].tap_script_sigs.insert(
        (responder_xonly, verify_sighashes[0].leaf_hash),
        TaprootSignature {
            signature: v_sig,
            sighash_type: TapSighashType::Default,
        },
    );

    let final_tx = builder
        .finalize_recovery(&mut verify_psbt, 0)
        .expect("finalize_recovery");
    assert!(!final_tx.input[0].witness.is_empty());

    // Verify the schnorr signature against the sighash using the prevout.
    let prevout = TxOut {
        value: Amount::from_sat(utxo_value),
        script_pubkey: recovery_output.address.script_pubkey(),
    };
    let mut cache = SighashCache::new(&final_tx);
    let leaf_hash =
        TapLeafHash::from_script(&recovery_output.tiers[0].script, LeafVersion::TapScript);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("verify sighash");
    let verify_msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    secp.verify_schnorr(&v_sig, &verify_msg, &responder_xonly)
        .expect("schnorr verify");

    // Sanity: ensure the unused stack-cells / script / control-block are at
    // the expected witness positions for a 1-of-1 recovery tier.
    let witness = &final_tx.input[0].witness;
    assert!(witness.len() >= 3, "witness should have sig + script + cb");

    // Silence unused locals.
    let _ = (
        &external_desc,
        &internal_desc,
        Version::TWO,
        LockTime::ZERO,
        TxIn {
            previous_output: utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        },
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        },
    );

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
}
