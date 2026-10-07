// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Key-path spends of a FROST group's taproot outputs over the in-process
//! `MemoryTransport`. A taproot output commits to its internal key only through
//! the BIP-341 tweak, so the oracle is the check consensus applies: the aggregate
//! signature must verify under the output key in the spent scriptPubKey. It must
//! not verify under the untweaked internal key, which is what a signer that
//! skipped the tweak would have produced.

use std::sync::Arc;
use std::time::Duration;

use keep_core::frost::bip32_signing::derive_child;
use keep_core::frost::taproot::{verify_key_path_signature, TaprootTweak};
use keep_core::frost::{ThresholdConfig, TrustedDealer};
use keep_frost_net::test_support::{key_spend_payload, MemoryBus};
use keep_frost_net::{CosignTransport, KfpNode, KfpNodeEvent, ServeHooks, TaprootTweakPayload};
use tokio::time::timeout;

struct Group {
    group_pubkey: [u8; 32],
    requester: Arc<KfpNode>,
    nodes: Vec<Arc<KfpNode>>,
}

/// A 2-of-3 group whose two co-signers do (`allow`) or do not opt in to
/// key-path spends; node 3 requests.
async fn group_with(allow: bool) -> Group {
    let dealer = TrustedDealer::new(ThresholdConfig::two_of_three());
    let (shares, _) = dealer.generate("mem-taproot-spend").unwrap();
    let group_pubkey = *shares[0].group_pubkey();
    let bus = MemoryBus::new();
    let mut nodes: Vec<KfpNode> = shares
        .into_iter()
        .map(|share| {
            KfpNode::with_transport(
                share,
                bus.transport() as Arc<dyn CosignTransport>,
                None,
                None,
            )
            .expect("node")
        })
        .collect();
    for node in &nodes[..2] {
        node.set_hooks(Arc::new(ServeHooks {
            refuse_raw_sign: false,
            require_structured_payload: false,
            auto_approve_oprf_eval: false,
            allow_key_path_spend: allow,
        }));
    }
    let mut rx = nodes[2].subscribe();
    for node in &mut nodes {
        std::mem::forget(node.take_shutdown_handle());
    }
    let nodes: Vec<Arc<KfpNode>> = nodes.into_iter().map(Arc::new).collect();
    for node in &nodes {
        let node = Arc::clone(node);
        tokio::spawn(async move {
            let _ = node.run().await;
        });
    }
    timeout(Duration::from_secs(30), async {
        let mut n = 0;
        while n < 2 {
            if let Ok(KfpNodeEvent::PeerDiscovered { .. }) = rx.recv().await {
                n += 1;
            }
        }
    })
    .await
    .expect("the requester must discover both co-signers");
    Group {
        group_pubkey,
        requester: Arc::clone(&nodes[2]),
        nodes,
    }
}

async fn group() -> Group {
    group_with(true).await
}

async fn spend(
    g: &Group,
    spent: &bitcoin::ScriptBuf,
    sighash_type: u8,
    path: &[u32],
    tweak: TaprootTweakPayload,
) -> ([u8; 32], keep_frost_net::Result<[u8; 64]>) {
    let (sighash, payload) = key_spend_payload(spent, sighash_type);
    let result = timeout(
        Duration::from_secs(30),
        g.requester
            .request_key_path_spend(sighash.to_vec(), payload, path.to_vec(), tweak),
    )
    .await
    .expect("the request must finish");
    (sighash, result)
}

#[tokio::test]
async fn a_bip86_output_at_a_path_is_spent_on_the_key_path() {
    let g = group().await;
    let path = [0u32, 3];
    let child = derive_child(&g.group_pubkey, &path).unwrap().child_pubkey;
    let spent = TaprootTweak::default().script_pubkey(&child).unwrap();

    for sighash_type in [0x00, 0x01] {
        let (sighash, sig) = spend(&g, &spent, sighash_type, &path, Default::default()).await;
        let sig = sig.expect("the group signs a spend of its own output");
        verify_key_path_signature(&sig, &sighash, &spent)
            .expect("the signature must verify under the output key it spends");

        use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
        assert!(
            Secp256k1::verification_only()
                .verify_schnorr(
                    &Signature::from_slice(&sig).unwrap(),
                    &Message::from_digest(sighash),
                    &XOnlyPublicKey::from_slice(&child).unwrap(),
                )
                .is_err(),
            "an untweaked signature is what nodes reject"
        );
    }
}

#[tokio::test]
async fn a_recovery_tree_output_is_spent_on_the_key_path() {
    let g = group().await;
    let tweak = TaprootTweakPayload {
        merkle_root: Some([0x5c; 32]),
    };
    let spent = TaprootTweak::from(tweak)
        .script_pubkey(&g.group_pubkey)
        .unwrap();
    let (sighash, sig) = spend(&g, &spent, 0x00, &[], tweak).await;
    let sig = sig.expect("the group signs a key-path spend of its recovery output");
    verify_key_path_signature(&sig, &sighash, &spent).unwrap();
}

/// Co-signers that have not opted in refuse, even for the group's own output.
#[tokio::test]
async fn co_signers_refuse_key_path_spends_unless_they_opt_in() {
    let g = group_with(false).await;
    let path = [0u32, 3];
    let child = derive_child(&g.group_pubkey, &path).unwrap().child_pubkey;
    let spent = TaprootTweak::default().script_pubkey(&child).unwrap();
    let (_, result) = spend(&g, &spent, 0x00, &path, Default::default()).await;
    // A peer's refusal makes the requester fail over rather than stop, so the
    // co-signers' audit logs, not the requester's error, show why.
    result.expect_err("no co-signer approves key-path spends");
    for co_signer in &g.nodes[..2] {
        assert!(
            !co_signer.audit_log().refusals().is_empty(),
            "each co-signer that was asked must record its refusal"
        );
    }
}

/// The requester refuses before asking anyone: an output that is not the
/// group's for the path and tweak, or a sighash type narrower than ALL.
#[tokio::test]
async fn the_requester_refuses_what_its_co_signers_would() {
    let g = group().await;
    let path = [0u32, 3];
    let child = derive_child(&g.group_pubkey, &path).unwrap().child_pubkey;
    let other = derive_child(&g.group_pubkey, &[0, 4]).unwrap().child_pubkey;
    let ours = TaprootTweak::default().script_pubkey(&child).unwrap();

    let cases = [
        (
            TaprootTweak::default().script_pubkey(&other).unwrap(),
            0x00,
            "this group's output",
        ),
        (
            TaprootTweak::new(Some([1; 32]))
                .script_pubkey(&child)
                .unwrap(),
            0x00,
            "this group's output",
        ),
        (ours.clone(), 0x02, "SIGHASH_DEFAULT or SIGHASH_ALL"),
        (ours.clone(), 0x83, "SIGHASH_DEFAULT or SIGHASH_ALL"),
    ];
    for (spent, sighash_type, expected) in cases {
        let (_, result) = spend(&g, &spent, sighash_type, &path, Default::default()).await;
        let e = result.expect_err("must be refused");
        assert!(e.to_string().contains(expected), "{e}");
    }
}
