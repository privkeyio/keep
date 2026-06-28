// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Loading the TPM attestation policy a FROST node uses to verify a peer's
//! measured-boot state before answering its OPRF evaluation requests.
//!
//! The policy is provisioned out of band (trust-on-first-use) and pinned in a
//! TOML file: a shared PCR selection and reference digest set, plus one AK pin
//! per peer. See `keep frost network serve --attestation-config`.
//!
//! ```toml
//! # Marshalled TPML_PCR_SELECTION the peer quote must match (hex).
//! selection = "00000001000b03951800"
//! # Reference PCR digests in selection order (hex, 32 bytes each).
//! reference_pcrs = ["0000…", "0000…", "0000…", "0000…", "cf2b…", "0000…"]
//!
//! [[peer]]
//! index = 2
//! ak = "04f533…b327…"   # 65-byte uncompressed SEC1 point
//! ```

use std::collections::HashMap;
use std::path::Path;

use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use keep_core::error::{KeepError, Result};
use keep_frost_net::TpmAttestationPolicy;

use crate::output::Output;

#[derive(Deserialize, Serialize)]
struct AttestationConfig {
    selection: String,
    reference_pcrs: Vec<String>,
    #[serde(default)]
    peer: Vec<PeerPin>,
}

#[derive(Deserialize, Serialize)]
struct PeerPin {
    index: u16,
    ak: String,
}

fn err(msg: impl Into<String>) -> KeepError {
    KeepError::Frost(msg.into())
}

/// Count the PCRs selected by a marshalled `TPML_PCR_SELECTION`:
/// `count: u32`, then `count` * `{ hash: u16, sizeofSelect: u8, select[sizeofSelect] }`,
/// summing the set bits across every selection bitmap. Mirrors the parse in
/// `keep_frost_net::tpm_quote`, so the reference count can be reconciled at load.
fn count_selected_pcrs(selection: &[u8]) -> Result<usize> {
    let bad = || err("attestation `selection` is not a valid TPML_PCR_SELECTION");
    let mut pos = 0usize;
    let take = |pos: &mut usize, n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or_else(bad)?;
        let slice = selection.get(*pos..end).ok_or_else(bad)?;
        *pos = end;
        Ok(slice)
    };
    let count = u32::from_be_bytes(take(&mut pos, 4)?.try_into().map_err(|_| bad())?);
    let mut selected = 0usize;
    for _ in 0..count {
        take(&mut pos, 2)?; // hash alg
        let size = take(&mut pos, 1)?[0] as usize;
        for &b in take(&mut pos, size)? {
            selected += b.count_ones() as usize;
        }
    }
    if pos != selection.len() {
        return Err(bad());
    }
    Ok(selected)
}

/// Read and parse a TOML attestation policy file.
pub fn load_tpm_policy(path: &Path) -> Result<TpmAttestationPolicy> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| err(format!("read attestation config {}: {e}", path.display())))?;
    parse_tpm_policy(&text)
}

fn parse_tpm_policy(text: &str) -> Result<TpmAttestationPolicy> {
    let cfg: AttestationConfig =
        toml::from_str(text).map_err(|e| err(format!("invalid attestation config: {e}")))?;

    let selection = hex::decode(cfg.selection.trim())
        .map_err(|_| err("attestation `selection` is not valid hex"))?;
    if selection.is_empty() {
        return Err(err("attestation `selection` must not be empty"));
    }
    let selected = count_selected_pcrs(&selection)?;

    if cfg.reference_pcrs.is_empty() {
        return Err(err(
            "attestation `reference_pcrs` must list at least one PCR",
        ));
    }
    let mut reference_pcrs = Vec::with_capacity(cfg.reference_pcrs.len());
    for (i, p) in cfg.reference_pcrs.iter().enumerate() {
        let bytes = hex::decode(p.trim())
            .map_err(|_| err(format!("`reference_pcrs[{i}]` is not valid hex")))?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| err(format!("`reference_pcrs[{i}]` must be 32 bytes")))?;
        reference_pcrs.push(digest);
    }
    // The reference count must equal the PCRs the selection actually picks, or
    // the policy would look "enforced" yet reject every peer on the count check
    // in `verify_quote`.
    if reference_pcrs.len() != selected {
        return Err(err(format!(
            "attestation `selection` picks {selected} PCR(s) but `reference_pcrs` lists {}",
            reference_pcrs.len()
        )));
    }

    if cfg.peer.is_empty() {
        return Err(err(
            "attestation config pins no peers (add a `[[peer]]` entry)",
        ));
    }
    let mut pinned_aks = HashMap::new();
    for p in &cfg.peer {
        let ak = hex::decode(p.ak.trim())
            .map_err(|_| err(format!("peer {} `ak` is not valid hex", p.index)))?;
        if ak.len() != 65 || ak[0] != 0x04 {
            return Err(err(format!(
                "peer {} `ak` must be a 65-byte uncompressed SEC1 point (starts with 0x04)",
                p.index
            )));
        }
        // Reject a pin that is not a valid P-256 point at load time, so a typo'd
        // AK is a clear config error here rather than every peer silently failing
        // attestation later (`appraise_tpm_quote` parses the pin the same way).
        VerifyingKey::from_sec1_bytes(&ak)
            .map_err(|_| err(format!("peer {} `ak` is not a valid P-256 point", p.index)))?;
        if pinned_aks.insert(p.index, ak).is_some() {
            return Err(err(format!(
                "peer index {} is pinned more than once",
                p.index
            )));
        }
    }

    Ok(TpmAttestationPolicy::new(
        selection,
        reference_pcrs,
        pinned_aks,
    ))
}

/// Resolve the serve-time attestation policy from the CLI flags, fail-closed: a
/// node must either pin a policy or explicitly opt out of attestation, and it
/// cannot do both.
pub fn resolve_serve_policy(
    out: &Output,
    attestation_config: Option<&Path>,
    insecure_no_attestation: bool,
) -> Result<Option<TpmAttestationPolicy>> {
    match (attestation_config, insecure_no_attestation) {
        (Some(_), true) => Err(err(
            "--attestation-config conflicts with --insecure-no-attestation",
        )),
        (Some(path), false) => Ok(Some(load_tpm_policy(path)?)),
        (None, true) => {
            out.warn(
                "INSECURE: --insecure-no-attestation set; this node configures no peer-attestation \
                 policy. The OPRF oracle still requires a Verified peer, so without a policy it \
                 serves NO OPRF evaluations; the node participates only in FROST coordination.",
            );
            Ok(None)
        }
        (None, false) => Err(err(
            "attestation required: pass --attestation-config <FILE>, or \
             --insecure-no-attestation for test/dev only",
        )),
    }
}

/// Build the TPM-backed announce attestor for this box from a `--tpm-tcti`
/// string, so its announces carry a fresh measured-boot quote peers can verify.
/// Only available when built with the `tpm-attestation` feature.
#[cfg(feature = "tpm-attestation")]
pub fn build_announce_attestor(
    out: &Output,
    tcti: &str,
) -> Result<std::sync::Arc<dyn keep_frost_net::AnnounceAttestor>> {
    use keep_frost_net::AnnounceAttestor;
    let service = keep_frost_net::TpmQuoteService::spawn_from_tcti(tcti)
        .map_err(|e| err(format!("start TPM quote service: {e}")))?;
    out.field("Attestation key", &hex::encode(service.ak_sec1()));
    Ok(std::sync::Arc::new(service))
}

/// Without the `tpm-attestation` feature there is no TPM producer; `--tpm-tcti`
/// is rejected so the build limitation is explicit rather than silently ignored.
#[cfg(not(feature = "tpm-attestation"))]
pub fn build_announce_attestor(
    _out: &Output,
    _tcti: &str,
) -> Result<std::sync::Arc<dyn keep_frost_net::AnnounceAttestor>> {
    Err(err(
        "this build has no TPM support; rebuild with `--features tpm-attestation` to use --tpm-tcti",
    ))
}

/// Build an attestation policy from observed group announces (trust-on-first-use):
/// pin each attested peer's AK, and take the shared PCR selection + reference
/// values from the first attested announce. A peer that disagrees on the selection
/// or reference PCRs cannot be expressed by this single-reference policy (it would
/// be rejected at serve time), so it is skipped with a warning rather than written
/// into a policy guaranteed to lock it out.
///
/// Capture matches the runtime `handle_announce` admission bar: announces for a
/// different group, or whose proof-of-share does not verify, are ignored, so this
/// step never trusts the relay more than a running node does. The AK pins remain
/// trust-on-first-use: the operator establishes trust by running this in a trusted
/// moment while the genuine holders are online.
fn capture_policy_from_announces(
    out: &Output,
    group_pubkey: &[u8; 32],
    events: &[nostr_sdk::Event],
) -> Result<AttestationConfig> {
    use std::collections::btree_map::Entry;
    use std::collections::BTreeMap;

    let mut selection: Option<String> = None;
    let mut reference_pcrs: Option<Vec<String>> = None;
    let mut peers: BTreeMap<u16, String> = BTreeMap::new();

    for event in events {
        let payload = match keep_frost_net::KfpMessage::from_json(&event.content) {
            Ok(keep_frost_net::KfpMessage::Announce(p)) => p,
            _ => continue,
        };
        // The relay's `g` filter is advisory; the signed payload is authoritative.
        if payload.group_pubkey != *group_pubkey {
            continue;
        }
        // Reject announces whose proof-of-share does not verify, matching the
        // runtime `handle_announce` path so a forged or self-inconsistent announce
        // on the relay is not pinned.
        if keep_frost_net::proof::verify_proof(
            &payload.verifying_share,
            &payload.proof_signature,
            &payload.group_pubkey,
            payload.share_index,
            payload.timestamp,
        )
        .is_err()
        {
            out.warn(&format!(
                "peer {} proof-of-share did not verify; ignoring its announce",
                payload.share_index
            ));
            continue;
        }
        let Some(tpm) = payload.tpm_attestation else {
            continue;
        };
        // The selection a verifier pins lives only inside the signed quote.
        let sel = match keep_frost_net::tpm_quote::pcr_selection_from_attest(&tpm.attest) {
            Ok(s) => hex::encode(s),
            Err(_) => continue, // malformed quote; ignore this announce
        };

        // The first attested peer fixes the shared selection + reference PCRs; a
        // later peer that disagrees is skipped (it cannot be admitted under a
        // single-reference policy), so the pinned count reflects reality.
        match &selection {
            None => selection = Some(sel.clone()),
            Some(s) if *s != sel => {
                out.warn(&format!(
                    "peer {} announced a different PCR selection; not pinning it",
                    payload.share_index
                ));
                continue;
            }
            _ => {}
        }
        match &reference_pcrs {
            None => reference_pcrs = Some(tpm.pcr_values.clone()),
            Some(r) if *r != tpm.pcr_values => {
                out.warn(&format!(
                    "peer {} announced different reference PCRs; not pinning it",
                    payload.share_index
                ));
                continue;
            }
            _ => {}
        }
        // First-wins on the AK pin, consistent with the selection/reference above:
        // a later announce for an already-pinned index never silently replaces it.
        match peers.entry(payload.share_index) {
            Entry::Vacant(e) => {
                e.insert(hex::encode(&tpm.ak_sec1));
            }
            Entry::Occupied(_) => out.warn(&format!(
                "peer {} announced more than once; keeping the first AK pin",
                payload.share_index
            )),
        }
    }

    let selection =
        selection.ok_or_else(|| err("no attested announce observed; are the holders online?"))?;
    let reference_pcrs = reference_pcrs
        .ok_or_else(|| err("no attested announce observed; are the holders online?"))?;
    Ok(AttestationConfig {
        selection,
        reference_pcrs,
        peer: peers
            .into_iter()
            .map(|(index, ak)| PeerPin { index, ak })
            .collect(),
    })
}

/// Serialize a captured policy to TOML and write it, after re-parsing it through
/// the loader so a written file is guaranteed to load back into a valid policy.
fn write_policy_toml(path: &Path, config: &AttestationConfig) -> Result<()> {
    use std::io::Write;
    let text = toml::to_string_pretty(config).map_err(|e| err(format!("serialize policy: {e}")))?;
    parse_tpm_policy(&text)?; // never write a file the loader would reject
                              // `create_new` fails closed if the path exists, so a re-run never
                              // clobbers a hand-edited attestation policy.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => err(format!(
                "refusing to overwrite existing policy {}; remove it or choose another --out",
                path.display()
            )),
            _ => err(format!("write {}: {e}", path.display())),
        })?;
    f.write_all(text.as_bytes())
        .map_err(|e| err(format!("write {}: {e}", path.display())))
}

/// `keep frost network attestation-provision`: observe the group's announces over
/// the relay for `wait_secs`, capture each attested peer's AK + reference PCRs
/// (trust-on-first-use), and write an `--attestation-config` TOML file.
pub fn cmd_frost_network_attestation_provision(
    out: &Output,
    group_npub: &str,
    relay: &str,
    out_path: &Path,
    wait_secs: u64,
) -> Result<()> {
    use nostr_sdk::prelude::*;

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let wait = wait_secs.max(1);

    out.newline();
    out.header("Attestation Policy Provisioning");
    out.field("Group", group_npub);
    out.field("Relay", relay);
    out.field("Output", &out_path.display().to_string());
    out.warn(
        "TRUST-ON-FIRST-USE: AK pins and reference PCRs are captured from observed announces \
         WITHOUT verifying them. Run this only on a trusted network while your holders are online.",
    );
    out.newline();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| KeepError::Runtime(format!("tokio: {e}")))?;

    let config = rt.block_on(async {
        let client = Client::new(Keys::generate());
        client
            .add_relay(relay)
            .await
            .map_err(|e| err(format!("add relay {relay}: {e}")))?;
        client.connect().await;

        let filter = Filter::new()
            .kind(Kind::Custom(keep_frost_net::KFP_EVENT_KIND))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::G),
                hex::encode(group_pubkey),
            )
            .since(Timestamp::now() - std::time::Duration::from_secs(wait));

        let spinner = out.spinner(&format!("Listening {wait}s for attested announces..."));
        let events = client
            .fetch_events(filter, std::time::Duration::from_secs(wait))
            .await
            .map_err(|e| err(format!("fetch announces: {e}")))?;
        spinner.finish();

        capture_policy_from_announces(out, &group_pubkey, &events.into_iter().collect::<Vec<_>>())
    })?;

    let pinned = config.peer.len();
    write_policy_toml(out_path, &config)?;
    out.success(&format!(
        "Wrote attestation policy pinning {pinned} peer(s) to {}",
        out_path.display()
    ));
    out.info("Review it, then pass it to `keep frost network serve --attestation-config <FILE>`.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A default build (no `tpm-attestation`) must reject `--tpm-tcti` with a
    // message pointing at the feature flag, not silently ignore it.
    #[cfg(not(feature = "tpm-attestation"))]
    #[test]
    fn rejects_tpm_tcti_without_feature() {
        let out = Output::new();
        let rejected = build_announce_attestor(&out, "device:/dev/tpmrm0")
            .is_err_and(|e| e.to_string().contains("tpm-attestation"));
        assert!(
            rejected,
            "default build must reject --tpm-tcti via the feature flag"
        );
    }

    // A valid config over the default selection {0,2,4,7,11,12} with one peer.
    const VALID: &str = r#"
        selection = "00000001000b03951800"
        reference_pcrs = [
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "cf2b0db7514f320c315130275a960f6e6ed80744c754c687069d7a9f55d704f0",
          "0000000000000000000000000000000000000000000000000000000000000000",
        ]
        [[peer]]
        index = 2
        ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
    "#;

    #[test]
    fn parses_valid_config() {
        let pol = parse_tpm_policy(VALID).expect("valid config");
        assert_eq!(pol.pinned_aks.len(), 1);
        assert_eq!(pol.reference_pcrs.len(), 6);
        assert_eq!(pol.pinned_aks.get(&2).unwrap().len(), 65);
    }

    // A 1-PCR selection (picks PCR 0 only) so single-`reference_pcrs` fixtures
    // pass the count cross-check and exercise their intended validation.
    const ONE_PCR_SELECTION: &str = "00000001000b03010000";

    #[test]
    fn rejects_no_peers() {
        let cfg = r#"
            selection = "00000001000b03010000"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    #[test]
    fn rejects_bad_ak() {
        let cfg = r#"
            selection = "00000001000b03010000"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
            [[peer]]
            index = 2
            ak = "0400"
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    #[test]
    fn rejects_off_curve_ak() {
        // 65 bytes, 0x04 prefix, but not a valid P-256 point.
        let cfg = format!(
            r#"
            selection = "{ONE_PCR_SELECTION}"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
            [[peer]]
            index = 2
            ak = "04{}"
        "#,
            "ff".repeat(64)
        );
        assert!(parse_tpm_policy(&cfg).is_err());
    }

    #[test]
    fn rejects_reference_count_mismatch() {
        // selection picks 6 PCRs but only one reference value is listed.
        let cfg = r#"
            selection = "00000001000b03951800"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
            [[peer]]
            index = 2
            ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    #[test]
    fn rejects_short_reference_pcr() {
        let cfg = r#"
            selection = "00000001000b03951800"
            reference_pcrs = ["00ff"]
            [[peer]]
            index = 2
            ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    #[test]
    fn resolve_requires_a_choice() {
        let out = Output::new();
        // Neither flag: fail closed.
        assert!(resolve_serve_policy(&out, None, false).is_err());
    }

    #[test]
    fn resolve_rejects_both() {
        let out = Output::new();
        let path = Path::new("/nonexistent.toml");
        assert!(resolve_serve_policy(&out, Some(path), true).is_err());
    }

    #[test]
    fn resolve_insecure_opts_out() {
        let out = Output::new();
        assert!(matches!(resolve_serve_policy(&out, None, true), Ok(None)));
    }

    #[test]
    fn rejects_duplicate_peer() {
        let cfg = r#"
            selection = "00000001000b03010000"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
            [[peer]]
            index = 2
            ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
            [[peer]]
            index = 2
            ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    // The real swtpm quote vector: selection {0,2,4,7,11,12}, a valid AK.
    const ATTEST: &str = "ff54434780180022000bb9df3193fe4f66ac5a3ee8f8552e454d20bbae633354bcff12b65d581f9d38c7001000112233445566778899aabbccddeeff000000000000041f000000010000000001202401250012000000000001000b03951800002094d0f020a3c4d09b8b88e69e7a093a38ec0ff9715cfdc70285d99d236c52990a";
    const AK: &str = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb";

    // The 6 reference PCRs the canned ATTEST selection {0,2,4,7,11,12} picks.
    fn default_pcrs() -> Vec<String> {
        let zero = "00".repeat(32);
        let pcr11 = "cf2b0db7514f320c315130275a960f6e6ed80744c754c687069d7a9f55d704f0".to_string();
        vec![
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            pcr11,
            zero,
        ]
    }

    // A valid proof-of-share for the announce fields, so capture's verify_proof
    // gate (matching the runtime admission path) accepts the announce.
    fn signed_share(group: &[u8; 32], index: u16, timestamp: u64) -> ([u8; 33], [u8; 64]) {
        use k256::schnorr::SigningKey;
        let signing_share = [7u8; 32]; // any valid nonzero scalar
        let sk = SigningKey::from_bytes(&signing_share).expect("valid scalar");
        let mut verifying_share = [0u8; 33];
        verifying_share[0] = 0x02;
        verifying_share[1..].copy_from_slice(&sk.verifying_key().to_bytes());
        let sig = keep_frost_net::proof::sign_proof(
            &signing_share,
            group,
            index,
            &verifying_share,
            timestamp,
        )
        .expect("sign proof");
        (verifying_share, sig)
    }

    // Build an attested announce event with a valid proof-of-share, given the
    // captured-into-policy fields that the tests vary. Uses the canned ATTEST
    // selection {0,2,4,7,11,12} unless `attest` overrides it.
    fn attested_event(
        group: &[u8; 32],
        index: u16,
        timestamp: u64,
        pcr_values: Vec<String>,
        proof: ([u8; 33], [u8; 64]),
    ) -> nostr_sdk::Event {
        attested_event_with_attest(group, index, timestamp, ATTEST, pcr_values, proof)
    }

    fn attested_event_with_attest(
        group: &[u8; 32],
        index: u16,
        timestamp: u64,
        attest: &str,
        pcr_values: Vec<String>,
        proof: ([u8; 33], [u8; 64]),
    ) -> nostr_sdk::Event {
        use keep_frost_net::{AnnouncePayload, KfpMessage, TpmQuoteEvidence, KFP_EVENT_KIND};
        use nostr_sdk::{EventBuilder, Keys, Kind};

        let evidence = TpmQuoteEvidence {
            attest: hex::decode(attest).unwrap(),
            signature: vec![0u8; 64],
            ak_sec1: hex::decode(AK).unwrap(),
            pcr_values,
        };
        let payload = AnnouncePayload::new(*group, index, proof.0, proof.1, timestamp)
            .with_tpm_attestation(evidence);
        let content = KfpMessage::Announce(payload).to_json().unwrap();
        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), content)
            .sign_with_keys(&Keys::generate())
            .unwrap()
    }

    #[test]
    fn capture_policy_from_announce_round_trips_through_loader() {
        let group = [7u8; 32];
        let event = attested_event(
            &group,
            2,
            1_700_000_000,
            default_pcrs(),
            signed_share(&group, 2, 1_700_000_000),
        );

        let out = Output::new();
        let config = capture_policy_from_announces(&out, &group, &[event]).expect("capture");
        assert_eq!(config.selection, "00000001000b03951800");
        assert_eq!(config.peer.len(), 1);
        assert_eq!(config.peer[0].index, 2);
        assert_eq!(config.reference_pcrs.len(), 6);

        // The written file must load back into a valid policy.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        write_policy_toml(&path, &config).expect("write");
        let pol = load_tpm_policy(&path).expect("written policy must load");
        assert_eq!(pol.pinned_aks.len(), 1);
    }

    #[test]
    fn capture_errors_without_an_attested_announce() {
        let out = Output::new();
        assert!(capture_policy_from_announces(&out, &[7u8; 32], &[]).is_err());
    }

    #[test]
    fn capture_ignores_announce_with_bad_proof() {
        // A real announce body but a zero (invalid) proof-of-share: rejected like
        // the runtime path, leaving nothing to capture.
        let group = [7u8; 32];
        let event = attested_event(
            &group,
            2,
            1_700_000_000,
            default_pcrs(),
            ([2u8; 33], [0u8; 64]),
        );
        let out = Output::new();
        assert!(capture_policy_from_announces(&out, &group, &[event]).is_err());
    }

    #[test]
    fn capture_ignores_announce_for_other_group() {
        let group = [7u8; 32];
        let other = [9u8; 32];
        let event = attested_event(
            &other,
            2,
            1_700_000_000,
            default_pcrs(),
            signed_share(&other, 2, 1_700_000_000),
        );
        let out = Output::new();
        assert!(capture_policy_from_announces(&out, &group, &[event]).is_err());
    }

    #[test]
    fn capture_skips_peer_with_divergent_reference_pcrs() {
        // Peer 2 fixes the reference; peer 3 announces different PCR values the
        // single-reference policy cannot express, so only peer 2 is pinned.
        let group = [7u8; 32];
        let mut divergent = default_pcrs();
        divergent[0] = "11".repeat(32);
        let events = vec![
            attested_event(
                &group,
                2,
                1_700_000_000,
                default_pcrs(),
                signed_share(&group, 2, 1_700_000_000),
            ),
            attested_event(
                &group,
                3,
                1_700_000_000,
                divergent,
                signed_share(&group, 3, 1_700_000_000),
            ),
        ];
        let out = Output::new();
        let config = capture_policy_from_announces(&out, &group, &events).expect("capture");
        assert_eq!(config.peer.len(), 1);
        assert_eq!(config.peer[0].index, 2);
    }

    #[test]
    fn capture_skips_peer_with_divergent_selection() {
        // Same canned quote but the PCR selection bitmap changed to {0} only, so
        // peer 3's selection differs from peer 2's and it is skipped.
        let attest_alt = ATTEST.replace("000b03951800", "000b03010000");
        assert_ne!(attest_alt, ATTEST);
        let group = [7u8; 32];
        let events = vec![
            attested_event(
                &group,
                2,
                1_700_000_000,
                default_pcrs(),
                signed_share(&group, 2, 1_700_000_000),
            ),
            attested_event_with_attest(
                &group,
                3,
                1_700_000_000,
                &attest_alt,
                vec!["00".repeat(32)],
                signed_share(&group, 3, 1_700_000_000),
            ),
        ];
        let out = Output::new();
        let config = capture_policy_from_announces(&out, &group, &events).expect("capture");
        assert_eq!(config.peer.len(), 1);
        assert_eq!(config.peer[0].index, 2);
    }

    #[test]
    fn capture_keeps_first_ak_on_repeat_announce() {
        // The same index announcing twice keeps the first pin (first-wins),
        // consistent with the selection/reference handling.
        let group = [7u8; 32];
        let events = vec![
            attested_event(
                &group,
                2,
                1_700_000_000,
                default_pcrs(),
                signed_share(&group, 2, 1_700_000_000),
            ),
            attested_event(
                &group,
                2,
                1_700_000_001,
                default_pcrs(),
                signed_share(&group, 2, 1_700_000_001),
            ),
        ];
        let out = Output::new();
        let config = capture_policy_from_announces(&out, &group, &events).expect("capture");
        assert_eq!(config.peer.len(), 1);
    }
}
