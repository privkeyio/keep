// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Deterministic `MemoryTransport` counterpart of the MockRelay integration
//! test `test_psbt_migration_sweep_end_to_end` in `multinode_test.rs`. Drives a
//! wallet-descriptor migration sweep between two `KfpNode`s on a shared
//! in-process bus (no relay, no network timing):
//!   - `request_descriptor_migration_sweep` (proposer-side build + broadcast)
//!   - `handle_psbt_propose` -> `validate_migration_sweep_destination`
//!     successor-chain check (responder-side)
//!   - `handle_psbt_sign` -> aggregation -> `handle_psbt_finalize`
//!     (responder and proposer finalization)
//!
//! A `Complete` migration session is injected directly into node1's session
//! manager, and a `DualDescriptorLookup` resolves OLD and NEW descriptors on
//! both nodes. This covers the security-critical descriptor-migration-sweep
//! path (fund safety during a descriptor rotation) for #790.

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

struct DualDescriptorLookup {
    old: keep_core::wallet::WalletDescriptor,
    new: keep_core::wallet::WalletDescriptor,
}

impl keep_frost_net::PersistedDescriptorLookup for DualDescriptorLookup {
    fn find_by_hash(&self, group: &[u8; 32], hash: &[u8; 32]) -> bool {
        if &self.old.group_pubkey != group {
            return false;
        }
        hash == &self.old.canonical_hash() || hash == &self.new.canonical_hash()
    }

    fn network_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        if &self.old.group_pubkey != group {
            return None;
        }
        if hash == &self.old.canonical_hash() {
            return Some(self.old.network.clone());
        }
        if hash == &self.new.canonical_hash() {
            return Some(self.new.network.clone());
        }
        None
    }

    fn external_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> Option<String> {
        if &self.old.group_pubkey != group {
            return None;
        }
        if hash == &self.old.canonical_hash() {
            return Some(self.old.external_descriptor.clone());
        }
        if hash == &self.new.canonical_hash() {
            return Some(self.new.external_descriptor.clone());
        }
        None
    }

    fn latest_version_for(
        &self,
        group: &[u8; 32],
    ) -> std::result::Result<Option<u32>, keep_frost_net::DescriptorLookupUnavailable> {
        if &self.old.group_pubkey == group {
            Ok(Some(self.new.version))
        } else {
            Ok(None)
        }
    }

    fn successor_for(&self, group: &[u8; 32], hash: &[u8; 32]) -> keep_frost_net::SuccessorLookup {
        if &self.old.group_pubkey != group {
            return keep_frost_net::SuccessorLookup::Unavailable;
        }
        let old_hash = self.old.canonical_hash();
        let new_hash = self.new.canonical_hash();
        if hash == &old_hash {
            keep_frost_net::SuccessorLookup::Found {
                external_descriptor: self.new.external_descriptor.clone(),
                network: self.new.network.clone(),
            }
        } else if hash == &new_hash {
            keep_frost_net::SuccessorLookup::Tip
        } else {
            keep_frost_net::SuccessorLookup::Unavailable
        }
    }
}

#[tokio::test]
async fn descriptor_migration_sweep_completes_over_memory_transport() {
    use std::sync::Arc;

    use bitcoin::bip32::Xpub;
    use bitcoin::hashes::Hash as _;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use bitcoin::{Amount, Network, OutPoint, TxOut, XOnlyPublicKey};
    use keep_bitcoin::recovery::{
        RecoveryConfig, RecoveryTier as BitcoinRecoveryTier, SpendingTier,
    };
    use keep_bitcoin::{
        merge_tap_script_sig, script_spend_sighashes, DescriptorExport, RecoveryTxBuilder,
        SweepUtxo,
    };
    use keep_frost_net::{DescriptorSession, FinalizedDescriptor, SignerId, WalletPolicy};

    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (mut shares, _pkg) = dealer.generate("test-psbt-sweep").unwrap();
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

    // Responder external key — known secret enables inline sighash signing
    // in lieu of a NIP-46 round-trip (same pattern as the recovery-spend test).
    let secp = Secp256k1::new();
    let responder_xpriv =
        bitcoin::bip32::Xpriv::new_master(Network::Signet, &[7u8; 32]).expect("xpriv");
    let responder_xpub = Xpub::from_priv(&secp, &responder_xpriv);
    let responder_xpub_str = responder_xpub.to_string();
    let responder_fp = responder_xpub
        .fingerprint()
        .to_string()
        .to_ascii_lowercase();
    let responder_xonly_bytes = responder_xpub.to_x_only_pub().serialize();
    let responder_xonly = XOnlyPublicKey::from_slice(&responder_xonly_bytes).expect("xonly");
    let responder_sk = responder_xpriv.private_key.secret_bytes();

    // OLD and NEW share the same recovery shape (one external key, 1-of-1
    // tier, 6-month timelock). The migration is "cosmetic" but exercises the
    // full sweep coordination — the production threat model the test verifies
    // is the proposer-side build + responder-side validation, not a
    // semantically interesting policy change.
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

    // OLD descriptor: version 1, no previous.
    let old_descriptor = keep_core::wallet::WalletDescriptor {
        group_pubkey,
        external_descriptor: external_desc.clone(),
        internal_descriptor: internal_desc.clone(),
        network: "signet".to_string(),
        created_at: 0,
        device_registrations: Vec::new(),
        policy_hash,
        version: 1,
        previous_descriptor_hash: None,
        policy: policy_value.clone(),
    };
    let old_descriptor_hash = old_descriptor.canonical_hash();

    // NEW descriptor: version 2, previous_descriptor_hash = OLD's hash. Same
    // external/internal strings work here (the sweep cares about the version
    // chain, not the descriptor content).
    let new_descriptor = keep_core::wallet::WalletDescriptor {
        group_pubkey,
        external_descriptor: external_desc.clone(),
        internal_descriptor: internal_desc.clone(),
        network: "signet".to_string(),
        created_at: 0,
        device_registrations: Vec::new(),
        policy_hash,
        version: 2,
        previous_descriptor_hash: Some(old_descriptor_hash),
        policy: policy_value,
    };

    let lookup: Arc<dyn keep_frost_net::PersistedDescriptorLookup> =
        Arc::new(DualDescriptorLookup {
            old: old_descriptor,
            new: new_descriptor.clone(),
        });
    node1 = node1.with_descriptor_lookup(lookup.clone());
    node2 = node2.with_descriptor_lookup(lookup);

    // Inject a Complete migration session for the NEW descriptor on node1.
    // request_descriptor_migration_sweep reads the session for the finalized
    // descriptor's external/internal/policy_hash/network and version.
    let migration_session_id = [0xAA; 32];
    {
        let finalized = FinalizedDescriptor {
            external: external_desc.clone(),
            internal: internal_desc.clone(),
            policy_hash,
        };
        let mut policy_v2 = policy.clone();
        policy_v2.version = 2;
        let session = DescriptorSession::test_completed(
            migration_session_id,
            group_pubkey,
            policy_v2,
            "signet".to_string(),
            finalized,
        );
        node1.test_inject_descriptor_session(session);
    }

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

    node2
        .announce_xpubs(vec![keep_frost_net::AnnouncedXpub {
            xpub: responder_xpub_str.clone(),
            fingerprint: responder_fp.clone(),
            label: Some("test-sweep-responder".into()),
        }])
        .await
        .expect("node2 announce_xpubs");

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

    // Sweep two synthetic UTXOs under the OLD recovery output.
    let utxos = vec![
        SweepUtxo {
            outpoint: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
            },
            value_sats: 75_000,
        },
        SweepUtxo {
            outpoint: OutPoint {
                txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                    [0x11; 32],
                )),
                vout: 1,
            },
            value_sats: 30_000,
        },
    ];
    let total_in: u64 = utxos.iter().map(|u| u.value_sats).sum();
    let fee_sats: u64 = 1_500;

    let session_id = node1
        .request_descriptor_migration_sweep(
            migration_session_id,
            old_descriptor_hash,
            &recovery_output,
            0,
            utxos.clone(),
            fee_sats,
            1,
            Vec::new(),
            vec![responder_fp.clone()],
            Some(60),
        )
        .await
        .expect("request_descriptor_migration_sweep");

    // Responder side: receive PsbtSignatureNeeded, sign the sighashes, contribute.
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
    assert_eq!(sighashes.len(), utxos.len(), "one sighash per swept input");

    let responder_kp = Keypair::from_seckey_slice(&secp, &responder_sk).expect("responder keypair");
    let aux = [0u8; 32];

    for sh in &sighashes {
        let msg = bitcoin::secp256k1::Message::from_digest(sh.sighash);
        let schnorr_sig = secp.sign_schnorr_with_aux_rand(&msg, &responder_kp, &aux);
        let schnorr_bytes: [u8; 64] = schnorr_sig.serialize();
        merge_tap_script_sig(
            &mut responder_psbt,
            sh.input_index,
            responder_xonly,
            sh.leaf_hash,
            &sh.sighash,
            schnorr_bytes,
        )
        .expect("merge sig");
    }
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

    let finalized = timeout(Duration::from_secs(30), async {
        loop {
            match rx1.recv().await {
                Ok(KfpNodeEvent::PsbtFinalized {
                    session_id: sid, ..
                }) if sid == session_id => return,
                Ok(KfpNodeEvent::PsbtAborted {
                    session_id: sid,
                    reason,
                }) if sid == session_id => panic!("sweep aborted: {reason}"),
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

    // Independently rebuild the same proposal PSBT and verify each input's
    // schnorr signature against the swept recovery prevouts. Asserts the
    // proposer-side build wired the right tap_scripts + control_block for
    // every input (sighash recomputation must match what the responder
    // signed) and that the destination addresses the NEW descriptor.
    let new_dest_script =
        keep_bitcoin::descriptor_address(&new_descriptor.external_descriptor, Network::Signet)
            .expect("derive new dest")
            .script_pubkey();
    let verify_psbt = builder
        .build_sweep_psbt(0, &utxos, &new_dest_script, fee_sats)
        .expect("build_sweep_psbt");

    let verify_sighashes = script_spend_sighashes(&verify_psbt).expect("verify sighashes");
    assert_eq!(verify_sighashes.len(), utxos.len(), "one sighash per input");

    let prevouts: Vec<TxOut> = utxos
        .iter()
        .map(|u| TxOut {
            value: Amount::from_sat(u.value_sats),
            script_pubkey: recovery_output.address.script_pubkey(),
        })
        .collect();
    let mut cache = SighashCache::new(&verify_psbt.unsigned_tx);
    let leaf_hash =
        TapLeafHash::from_script(&recovery_output.tiers[0].script, LeafVersion::TapScript);
    for (idx, sh) in verify_sighashes.iter().enumerate() {
        // Sighash recomputed from the rebuilt PSBT must match what the
        // responder signed: same value if and only if the proposer used the
        // same inputs + destination + recovery output.
        let recomputed = cache
            .taproot_script_spend_signature_hash(
                idx,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .expect("recompute sighash");
        assert_eq!(
            recomputed.to_byte_array(),
            sh.sighash,
            "input {idx}: recomputed sighash must match the proposer's"
        );

        // Cross-check the responder's real proposal sighash (derived from the
        // protocol's proposal PSBT) against the locally rebuilt one.
        assert_eq!(
            sighashes[idx].input_index, sh.input_index,
            "input {idx}: proposal/rebuild input index must align"
        );
        assert_eq!(
            sighashes[idx].sighash, sh.sighash,
            "input {idx}: responder's real proposal sighash must match the rebuilt one"
        );

        // Verify the responder's actual contributed signature, not a re-signed
        // copy. Pulls the schnorr sig the responder merged into the proposal
        // PSBT before contributing; re-signing here would tautologically pass
        // regardless of whether the PSBT coordination produced a valid sig.
        let v_msg = bitcoin::secp256k1::Message::from_digest(sh.sighash);
        let contributed_sig = responder_psbt.inputs[sh.input_index]
            .tap_script_sigs
            .get(&(responder_xonly, sh.leaf_hash))
            .unwrap_or_else(|| {
                panic!(
                    "input {idx}: PSBT is missing the responder's tap_script_sig \
                     for (xonly={responder_xonly:?}, leaf={:?}); \
                     PSBT merging or storage regression",
                    sh.leaf_hash
                )
            });
        secp.verify_schnorr(&contributed_sig.signature, &v_msg, &responder_xonly)
            .expect("responder's contributed sweep signature MUST verify under BIP-340");
    }

    // The proposer-side build produced exactly the right output shape: one
    // output paying the NEW descriptor address with the swept-amount minus
    // fee.
    assert_eq!(verify_psbt.unsigned_tx.output.len(), 1);
    assert_eq!(
        verify_psbt.unsigned_tx.output[0].script_pubkey, new_dest_script,
        "sweep MUST pay the NEW descriptor address"
    );
    assert_eq!(
        verify_psbt.unsigned_tx.output[0].value.to_sat(),
        total_in - fee_sats,
        "sweep output value = sum(inputs) - fee"
    );

    graceful_shutdown(shutdown1, node1_handle).await;
    graceful_shutdown(shutdown2, node2_handle).await;
}
