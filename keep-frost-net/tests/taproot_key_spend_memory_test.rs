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
use keep_frost_net::test_support::MemoryBus;
use keep_frost_net::{CosignTransport, KfpNode, KfpNodeEvent, ServeHooks, TaprootTweakPayload};
use tokio::time::timeout;

struct Group {
    group_pubkey: [u8; 32],
    requester: Arc<KfpNode>,
    nodes: Vec<Arc<KfpNode>>,
}

/// The single output `key_spend_payload` pays, 99 000 sats to an OP_RETURN.
/// A co-signer policy has to allow it by script like any other destination.
fn payload_destination() -> bitcoin::ScriptBuf {
    bitcoin::ScriptBuf::new_op_return([0u8; 4])
}

/// What `key_spend_payload`'s transaction consumes: one 100 000 sat input, of
/// which 99 000 reaches the output and 1 000 is the fee. The cap is on this,
/// not on the 99 000, so a policy that allows the spend has to cover the fee.
const PAYLOAD_CONSUMES: bitcoin::Amount = bitcoin::Amount::from_sat(100_000);

/// The fee that leaves in `key_spend_payload`'s transaction: 100 000 in less
/// the 99 000 the output pays.
const PAYLOAD_FEE: bitcoin::Amount = bitcoin::Amount::from_sat(1_000);

/// A 2-of-3 group whose two co-signers run `policy` on key-path spends; node 3
/// requests.
async fn group_with(policy: keep_frost_net::KeySpendPolicy) -> Group {
    // Ten spends' worth, though the tests using this reach the window once
    // between them: they all go through `spend`, which is one transaction.
    group_with_window(policy, PAYLOAD_CONSUMES * 10).await
}

/// As [`group_with`], with the rolling window's total chosen by the caller.
async fn group_with_window(
    policy: keep_frost_net::KeySpendPolicy,
    window_total: bitcoin::Amount,
) -> Group {
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
            key_path_spend: policy.clone(),
            spend_window: keep_frost_net::KeySpendWindow::daily(window_total.to_sat()),
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
    group_with(keep_frost_net::KeySpendPolicy::new(
        vec![payload_destination()],
        PAYLOAD_CONSUMES,
        PAYLOAD_FEE,
    ))
    .await
}

async fn spend(
    g: &Group,
    spent: &bitcoin::ScriptBuf,
    sighash_type: u8,
    path: &[u32],
    tweak: TaprootTweakPayload,
) -> ([u8; 32], keep_frost_net::Result<[u8; 64]>) {
    // Always funding output 0, so every call through this helper is the SAME
    // transaction and the rolling window charges them once between them. A test
    // about the window wants [`spend_of`] with distinct vouts instead.
    spend_of(g, spent, sighash_type, path, tweak, 0).await
}

/// As [`spend`], spending output `vout` of the funding transaction, so a caller
/// can make each request a distinct transaction rather than the same one.
async fn spend_of(
    g: &Group,
    spent: &bitcoin::ScriptBuf,
    sighash_type: u8,
    path: &[u32],
    tweak: TaprootTweakPayload,
    vout: u32,
) -> ([u8; 32], keep_frost_net::Result<[u8; 64]>) {
    let (sighash, payload) =
        keep_frost_net::test_support::key_spend_payload_of(spent, sighash_type, vout);
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

/// Co-signers running the default policy refuse, even for the group's own
/// output.
#[tokio::test]
async fn co_signers_refuse_key_path_spends_unless_they_opt_in() {
    let g = group_with(keep_frost_net::KeySpendPolicy::default()).await;
    let path = [0u32, 3];
    let child = derive_child(&g.group_pubkey, &path).unwrap().child_pubkey;
    let spent = TaprootTweak::default().script_pubkey(&child).unwrap();
    let (_, result) = spend(&g, &spent, 0x00, &path, Default::default()).await;
    // A peer's refusal makes the requester fail over rather than stop; the
    // last refusal is carried into the error, and each co-signer records it.
    let e = result.expect_err("no co-signer approves key-path spends");
    assert!(
        e.to_string().contains("does not approve key-path spends"),
        "{e}"
    );
    for co_signer in &g.nodes[..2] {
        assert!(
            !co_signer.audit_log().refusals().is_empty(),
            "each co-signer that was asked must record its refusal"
        );
    }
}

/// The destination and the cap are enforced where it counts, by the co-signers
/// on the real request path, not only in the policy's own unit tests. Both
/// cases spend the group's own output at a path the node accepts, so the only
/// thing refusing is the policy.
#[tokio::test]
async fn co_signers_enforce_the_destination_and_the_cap_on_a_key_path_spend() {
    let path = [0u32, 3];
    let elsewhere = bitcoin::ScriptBuf::new_op_return([9u8; 4]);
    let cases = [
        (
            keep_frost_net::KeySpendPolicy::new(vec![elsewhere], PAYLOAD_CONSUMES, PAYLOAD_FEE),
            "a destination the policy does not list",
        ),
        (
            keep_frost_net::KeySpendPolicy::new(
                vec![payload_destination()],
                PAYLOAD_CONSUMES - bitcoin::Amount::from_sat(1),
                PAYLOAD_FEE,
            ),
            "a spend consuming one sat over the cap",
        ),
        (
            keep_frost_net::KeySpendPolicy::new(
                vec![payload_destination()],
                PAYLOAD_CONSUMES,
                PAYLOAD_FEE - bitcoin::Amount::from_sat(1),
            ),
            "a spend leaving one sat more in fees than the fee cap",
        ),
    ];
    for (policy, case) in cases {
        let g = group_with(policy).await;
        let child = derive_child(&g.group_pubkey, &path).unwrap().child_pubkey;
        let spent = TaprootTweak::default().script_pubkey(&child).unwrap();
        let (_, result) = spend(&g, &spent, 0x00, &path, Default::default()).await;
        let e = result.expect_err(case);
        assert!(
            e.to_string().contains("does not approve key-path spends"),
            "{case}: {e}"
        );
        for co_signer in &g.nodes[..2] {
            assert!(
                !co_signer.audit_log().refusals().is_empty(),
                "{case}: each co-signer that was asked must record its refusal"
            );
        }
    }
}

/// The rolling window bounds the spends the per-spend policy approves, on the
/// real request path, and shows the shape of that bound: it is per co-signer,
/// not per group.
///
/// Each of these spends passes every per-spend bound, and the window of each
/// co-signer has room for exactly one. The first two still succeed, because a
/// refusal makes the requester fail over to the other co-signer, whose window is
/// its own. The third is refused by both. So two co-signers with a window of N
/// admit 2N before anything stops, which is what the window is worth and is why
/// it is a bound on this node's participation rather than on the group's funds.
#[tokio::test]
async fn the_window_bounds_each_co_signer_and_a_requester_can_use_both() {
    let g = group_with_window(
        keep_frost_net::KeySpendPolicy::new(
            vec![payload_destination()],
            PAYLOAD_CONSUMES,
            PAYLOAD_FEE,
        ),
        // Room for exactly one of these spends.
        PAYLOAD_CONSUMES,
    )
    .await;
    let path = [0u32, 3];
    let child = derive_child(&g.group_pubkey, &path).unwrap().child_pubkey;
    let spent = TaprootTweak::default().script_pubkey(&child).unwrap();

    // A different funding output each time, so each request is a distinct
    // transaction with its own txid. The sighash type alone would not do it: it
    // changes the digest but not the transaction, and the window charges per
    // transaction, so two payloads differing only in it are one spend.
    let (sighash, sig) = spend_of(&g, &spent, 0x00, &path, Default::default(), 0).await;
    let sig = sig.expect("the first spend is within the window");
    verify_key_path_signature(&sig, &sighash, &spent).expect("the signature must verify");

    // The second fills the other co-signer's window by failing over to it: the
    // first has no room left and refuses, which is what sends the requester on.
    let (sighash, sig) = spend_of(&g, &spent, 0x00, &path, Default::default(), 1).await;
    let sig = sig.expect("the second spend fails over to the co-signer with room");
    verify_key_path_signature(&sig, &sighash, &spent).expect("the signature must verify");

    // Now both windows are full and there is nowhere left to fail over to.
    let (_, third) = spend_of(&g, &spent, 0x00, &path, Default::default(), 2).await;
    let e = third.expect_err("with every window full the spend must be refused");
    assert!(
        e.to_string().contains("does not approve key-path spends"),
        "{e}"
    );
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
