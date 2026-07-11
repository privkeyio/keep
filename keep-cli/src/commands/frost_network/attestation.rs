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

/// The PCR indices a `TPML_PCR_SELECTION` selects, in the same order the reference
/// digests are listed (ascending PCR within each bank). Mirrors `count_selected_pcrs`
/// but collects the indices. keep pins a single (SHA-256) bank, so an index appears
/// once and maps 1:1 to its reference-digest position.
fn selected_pcr_indices(selection: &[u8]) -> Result<Vec<u32>> {
    let bad = || err("attestation `selection` is not a valid TPML_PCR_SELECTION");
    let mut pos = 0usize;
    let take = |pos: &mut usize, n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or_else(bad)?;
        let slice = selection.get(*pos..end).ok_or_else(bad)?;
        *pos = end;
        Ok(slice)
    };
    let count = u32::from_be_bytes(take(&mut pos, 4)?.try_into().map_err(|_| bad())?);
    let mut indices = Vec::new();
    for _ in 0..count {
        take(&mut pos, 2)?; // hash alg
        let size = take(&mut pos, 1)?[0] as usize;
        for (byte, &b) in take(&mut pos, size)?.iter().enumerate() {
            for bit in 0..8u32 {
                if b & (1 << bit) != 0 {
                    indices.push((byte as u32) * 8 + bit);
                }
            }
        }
    }
    if pos != selection.len() {
        return Err(bad());
    }
    Ok(indices)
}

/// Parse repeatable `--expected-pcr INDEX=HEX` values (e.g. `11=<64 hex>`) into a
/// map of PCR index to its known-good 32-byte SHA-256 reference. A malformed entry,
/// non-32-byte digest, or duplicate index is a hard error , a bad reference must
/// fail loudly, not silently weaken the pin.
fn parse_expected_pcrs(args: &[String]) -> Result<std::collections::BTreeMap<u32, [u8; 32]>> {
    let mut map = std::collections::BTreeMap::new();
    for arg in args {
        let (idx, hex_val) = arg.split_once('=').ok_or_else(|| {
            err(format!(
                "--expected-pcr must be INDEX=HEX (e.g. 11=<64 hex>), got: {arg}"
            ))
        })?;
        let idx: u32 = idx
            .trim()
            .parse()
            .map_err(|_| err(format!("--expected-pcr index is not a number: {idx}")))?;
        let bytes = hex::decode(hex_val.trim())
            .map_err(|_| err(format!("--expected-pcr {idx} value is not hex")))?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| {
            err(format!(
                "--expected-pcr {idx} must be a 32-byte (64 hex) SHA-256 digest"
            ))
        })?;
        if map.insert(idx, digest).is_some() {
            return Err(err(format!("--expected-pcr {idx} given more than once")));
        }
    }
    Ok(map)
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
    // A fully zeroed reference set is theater: every PCR unextended means no
    // measured boot happened, so the policy would "verify" a completely
    // unmeasured TPM. Mirror the Nitro all-zero PCR0 rejection. A mix of zero
    // and non-zero slots is legitimate (unused PCRs read zero), so reject only
    // when EVERY reference PCR is zero.
    if reference_pcrs.iter().all(|d| d.iter().all(|&b| b == 0)) {
        return Err(err(
            "attestation `reference_pcrs` are all zeros (an unmeasured TPM); refusing to pin a policy that verifies nothing",
        ));
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

/// Build the announce attestor only when `--tpm-tcti` is set, returning `Ok(None)`
/// otherwise. Built before unlocking so a config mistake fails fast.
pub fn optional_announce_attestor(
    out: &Output,
    tpm_tcti: Option<&str>,
) -> Result<Option<std::sync::Arc<dyn keep_frost_net::AnnounceAttestor>>> {
    match tpm_tcti {
        Some(tcti) => Ok(Some(build_announce_attestor(out, tcti)?)),
        None => Ok(None),
    }
}

/// Install an announce attestor on `node` and report it, so every node that
/// attaches a TPM quote to its announces surfaces the same status field.
pub fn set_optional_announce_attestor(
    out: &Output,
    node: &mut keep_frost_net::KfpNode,
    attestor: Option<std::sync::Arc<dyn keep_frost_net::AnnounceAttestor>>,
) {
    if let Some(attestor) = attestor {
        node.set_announce_attestor(attestor);
        out.field("Self-attestation", "attaching a TPM quote to announces");
    }
}

/// Parse an announced AK exactly as the policy loader will (`parse_tpm_policy`):
/// a 65-byte uncompressed SEC1 point on P-256. Returns `None` for anything the
/// loader would later reject, so a bad AK is dropped at capture instead of
/// poisoning the batch.
fn validated_ak(ak_sec1: &[u8]) -> Option<VerifyingKey> {
    if ak_sec1.len() != 65 || ak_sec1[0] != 0x04 {
        return None;
    }
    VerifyingKey::from_sec1_bytes(ak_sec1).ok()
}

/// Decode announced PCR values into 32-byte digests, rejecting any entry that is
/// not exactly 32 bytes of hex (the same shape `parse_tpm_policy` requires).
fn decode_pcr_digests(values: &[String]) -> Option<Vec<[u8; 32]>> {
    values
        .iter()
        .map(|v| hex::decode(v.trim()).ok()?.try_into().ok())
        .collect()
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
    expected: &std::collections::BTreeMap<u32, [u8; 32]>,
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
        let sel_bytes = match keep_frost_net::tpm_quote::pcr_selection_from_attest(&tpm.attest) {
            Ok(s) => s,
            Err(_) => continue, // malformed quote; ignore this announce
        };
        // Authenticate the TPM evidence against THIS signed announce before any of
        // it is trusted: run the same AK/PCR-shape checks the policy loader enforces,
        // then verify the quote the way the runtime appraisal does (`verify_quote`):
        // the nonce binds the quote to this announce, the AK signs the attest, and
        // the PCR values recompute to the attested digest. A peer failing any check
        // is skipped, so malformed or forged evidence can neither seed the capture
        // baseline (selection/reference) nor be pinned.
        let Some(ak) = validated_ak(&tpm.ak_sec1) else {
            out.warn(&format!(
                "peer {} announced an invalid attestation key; ignoring its announce",
                payload.share_index
            ));
            continue;
        };
        let pcr_digests = match decode_pcr_digests(&tpm.pcr_values) {
            Some(d) if d.len() == count_selected_pcrs(&sel_bytes).unwrap_or(0) => d,
            _ => {
                out.warn(&format!(
                    "peer {} announced PCR values inconsistent with its selection; ignoring it",
                    payload.share_index
                ));
                continue;
            }
        };
        let nonce = keep_frost_net::derive_announce_attestation_nonce(
            &payload.group_pubkey,
            payload.share_index,
            payload.timestamp,
        );
        if keep_frost_net::tpm_quote::verify_quote(
            &tpm.attest,
            &tpm.signature,
            &ak,
            &nonce,
            &sel_bytes,
            &pcr_digests,
            &pcr_digests,
        )
        .is_err()
        {
            out.warn(&format!(
                "peer {} TPM quote did not authenticate against its announce; ignoring it",
                payload.share_index
            ));
            continue;
        }

        // Known-good reference check (closes the TOFU gap for measured-boot PCRs): when the operator
        // supplied `--expected-pcr`, the peer's authenticated quote must report EXACTLY the reference
        // value at each of those PCR indices, or it is refused , not pinned. This turns "trust whatever
        // the first box reports" into "trust only a box whose kernel/initrd (PCR 11) match the shipped
        // UKI." The AK stays TOFU (it is genuinely per-TPM), but the boot-state PCRs are pinned to a
        // build-derived reference, so a box compromised at first attest cannot seed the policy.
        if !expected.is_empty() {
            let indices = selected_pcr_indices(&sel_bytes)?;
            let mut refused = false;
            for (&want_idx, want_val) in expected {
                match indices.iter().position(|&i| i == want_idx) {
                    Some(pos) if pcr_digests[pos] == *want_val => {}
                    Some(_) => {
                        out.warn(&format!(
                            "peer {} PCR {want_idx} does not match the expected reference; refusing it",
                            payload.share_index
                        ));
                        refused = true;
                        break;
                    }
                    None => {
                        out.warn(&format!(
                            "peer {} does not attest PCR {want_idx} (not in its selection); refusing it",
                            payload.share_index
                        ));
                        refused = true;
                        break;
                    }
                }
            }
            if refused {
                continue;
            }
        }

        let sel = hex::encode(&sel_bytes);

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
    expected_pcr: &[String],
) -> Result<()> {
    use nostr_sdk::prelude::*;

    let group_pubkey = keep_core::keys::npub_to_bytes(group_npub)?;
    let wait = wait_secs.max(1);
    let expected = parse_expected_pcrs(expected_pcr)?;

    out.newline();
    out.header("Attestation Policy Provisioning");
    out.field("Group", group_npub);
    out.field("Relay", relay);
    out.field("Output", &out_path.display().to_string());
    if expected.is_empty() {
        out.warn(
            "TRUST-ON-FIRST-USE: AK pins and reference PCRs are captured from observed announces \
             WITHOUT verifying them. Run this only on a trusted network while your holders are \
             online. Pass --expected-pcr to pin a known-good reference (e.g. the measured-boot \
             PCR 11) instead.",
        );
    } else {
        let pins: Vec<String> = expected.keys().map(|i| i.to_string()).collect();
        out.field("Expected PCRs (verified, not TOFU)", &pins.join(", "));
        out.warn(
            "AK pins are trust-on-first-use (genuinely per-TPM), but a peer whose attested PCRs at \
             the --expected-pcr indices differ from the reference is REFUSED, not pinned.",
        );
    }
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

        // Announces are ephemeral (KFP_EVENT_KIND is in the NIP-16 ephemeral range), so relays
        // do not store them: a point-in-time fetch (which returns on EOSE) only catches one if a
        // peer happens to broadcast in the brief window before EOSE, making capture a race.
        // Peers re-announce on a fixed interval, so hold a live subscription open for the full
        // `wait` and collect every announce that arrives instead, guaranteeing we observe at
        // least one periodic re-announce from each online peer (pick `wait` >= that interval).
        let mut notifications = client.notifications();
        let filter = Filter::new()
            .kind(Kind::Custom(keep_frost_net::KFP_EVENT_KIND))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::G),
                hex::encode(group_pubkey),
            )
            .since(Timestamp::now() - std::time::Duration::from_secs(wait));
        client
            .subscribe(filter, None)
            .await
            .map_err(|e| err(format!("subscribe announces: {e}")))?;

        let spinner = out.spinner(&format!("Listening {wait}s for attested announces..."));
        let mut events: Vec<Event> = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(wait);
        loop {
            match tokio::time::timeout_at(deadline, notifications.recv()).await {
                Err(_) => break, // the full wait window elapsed: the normal success path
                Ok(Ok(RelayPoolNotification::Event { event, .. })) => events.push(*event),
                Ok(Ok(_)) => {} // non-event notifications: ignore
                // Fell behind the broadcast buffer: some notifications were dropped, but peers
                // re-announce on their interval, so keep listening rather than aborting.
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                // The stream closed before the window elapsed (relay pool shut down): surface a
                // clear failure instead of silently capturing a partial/empty set.
                Ok(Err(e)) => return Err(err(format!("announce subscription ended early: {e}"))),
            }
        }
        spinner.finish();

        capture_policy_from_announces(out, &group_pubkey, &events, &expected)
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
            reference_pcrs = ["cf2b0db7514f320c315130275a960f6e6ed80744c754c687069d7a9f55d704f0"]
        "#;
        assert!(parse_tpm_policy(cfg).is_err());
    }

    #[test]
    fn rejects_bad_ak() {
        let cfg = r#"
            selection = "00000001000b03010000"
            reference_pcrs = ["cf2b0db7514f320c315130275a960f6e6ed80744c754c687069d7a9f55d704f0"]
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
            reference_pcrs = ["cf2b0db7514f320c315130275a960f6e6ed80744c754c687069d7a9f55d704f0"]
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
    fn rejects_all_zero_reference_set() {
        // A fully zeroed reference set (an unmeasured TPM) is refused even when
        // count and peer are otherwise valid. A mix with a non-zero slot (the
        // VALID fixture) is accepted, so this pins the all-zero-only case.
        let cfg = r#"
            selection = "00000001000b03010000"
            reference_pcrs = ["0000000000000000000000000000000000000000000000000000000000000000"]
            [[peer]]
            index = 2
            ak = "04f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb3271b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb"
        "#;
        let e = parse_tpm_policy(cfg).unwrap_err().to_string();
        assert!(
            e.contains("all zeros"),
            "expected all-zeros rejection, got: {e}"
        );
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

    // Marshalled TPML_PCR_SELECTION for {0,2,4,7,11,12} (6 PCRs).
    const SELECTION: &str = "00000001000b03951800";

    // The 6 reference PCRs the SELECTION picks.
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

    // The test AK: a fixed P-256 key the synthetic quotes are signed under.
    fn ak_signing_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).expect("valid AK scalar")
    }

    fn ak_sec1() -> Vec<u8> {
        ak_signing_key()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    // Build a marshalled TPMS_ATTEST quote over the given nonce, selection, and
    // PCR values (digest = SHA-256 of the concatenated values), matching what
    // `verify_quote` parses and checks.
    fn build_attest(nonce: &[u8], selection: &[u8], pcr_values: &[String]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for v in pcr_values {
            h.update(hex::decode(v.trim()).unwrap());
        }
        let pcr_digest = h.finalize();
        let mut a = Vec::new();
        a.extend_from_slice(&0xFF54_4347u32.to_be_bytes()); // TPM_GENERATED
        a.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
        a.extend_from_slice(&0u16.to_be_bytes()); // TPM2B_NAME (empty)
        a.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        a.extend_from_slice(nonce); // extraData
        a.extend_from_slice(&[0u8; 17]); // TPMS_CLOCK_INFO
        a.extend_from_slice(&[0u8; 8]); // firmware version
        a.extend_from_slice(selection); // TPML_PCR_SELECTION
        a.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        a.extend_from_slice(&pcr_digest);
        a
    }

    // A TPM evidence blob whose quote is signed under the test AK over `nonce`.
    fn evidence(
        nonce: &[u8],
        selection: &[u8],
        pcr_values: Vec<String>,
    ) -> keep_frost_net::TpmQuoteEvidence {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature};
        use sha2::{Digest, Sha256};

        let attest = build_attest(nonce, selection, &pcr_values);
        let sig: Signature = ak_signing_key()
            .sign_prehash(&Sha256::digest(&attest))
            .expect("sign attest");
        keep_frost_net::TpmQuoteEvidence {
            attest,
            signature: sig.to_bytes().to_vec(),
            ak_sec1: ak_sec1(),
            pcr_values,
        }
    }

    fn announce_event(
        group: &[u8; 32],
        index: u16,
        timestamp: u64,
        evidence: keep_frost_net::TpmQuoteEvidence,
        proof: ([u8; 33], [u8; 64]),
    ) -> nostr_sdk::Event {
        use keep_frost_net::{AnnouncePayload, KfpMessage, KFP_EVENT_KIND};
        use nostr_sdk::{EventBuilder, Keys, Kind};

        let payload = AnnouncePayload::new(*group, index, proof.0, proof.1, timestamp)
            .with_tpm_attestation(evidence);
        let content = KfpMessage::Announce(payload).to_json().unwrap();
        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), content)
            .sign_with_keys(&Keys::generate())
            .unwrap()
    }

    // An announce carrying a valid, announce-bound quote and proof-of-share.
    fn attested_event(
        group: &[u8; 32],
        index: u16,
        timestamp: u64,
        pcr_values: Vec<String>,
        proof: ([u8; 33], [u8; 64]),
    ) -> nostr_sdk::Event {
        attested_event_sel(group, index, timestamp, SELECTION, pcr_values, proof)
    }

    fn attested_event_sel(
        group: &[u8; 32],
        index: u16,
        timestamp: u64,
        selection_hex: &str,
        pcr_values: Vec<String>,
        proof: ([u8; 33], [u8; 64]),
    ) -> nostr_sdk::Event {
        let nonce = keep_frost_net::derive_announce_attestation_nonce(group, index, timestamp);
        let selection = hex::decode(selection_hex).unwrap();
        let ev = evidence(&nonce, &selection, pcr_values);
        announce_event(group, index, timestamp, ev, proof)
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
        let config = capture_policy_from_announces(&out, &group, &[event], &Default::default())
            .expect("capture");
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
        assert!(capture_policy_from_announces(&out, &[7u8; 32], &[], &Default::default()).is_err());
    }

    #[test]
    fn selected_pcr_indices_maps_the_default_selection() {
        // SELECTION picks {0,2,4,7,11,12}; PCR 11 sits at reference/selection index 4,
        // which is the position the --expected-pcr 11 gate compares against.
        let sel = hex::decode(SELECTION).unwrap();
        assert_eq!(
            selected_pcr_indices(&sel).unwrap(),
            vec![0, 2, 4, 7, 11, 12]
        );
    }

    #[test]
    fn parse_expected_pcrs_accepts_valid_and_rejects_bad() {
        let good = "11=".to_string() + &"ab".repeat(32);
        let m = parse_expected_pcrs(&[good]).unwrap();
        assert_eq!(m[&11], [0xabu8; 32]);
        assert!(parse_expected_pcrs(&["11".to_string()]).is_err()); // no '='
        assert!(parse_expected_pcrs(&["x=".to_string() + &"ab".repeat(32)]).is_err()); // bad index
        assert!(parse_expected_pcrs(&["11=zz".to_string()]).is_err()); // bad hex
        assert!(parse_expected_pcrs(&["11=abab".to_string()]).is_err()); // not 32 bytes
        assert!(parse_expected_pcrs(&[
            "11=".to_string() + &"ab".repeat(32),
            "11=".to_string() + &"cd".repeat(32),
        ])
        .is_err()); // duplicate index
    }

    #[test]
    fn capture_pins_peer_whose_expected_pcr_matches() {
        let group = [7u8; 32];
        let pcrs = default_pcrs();
        // PCR 11 is at selection index 4 in {0,2,4,7,11,12}.
        let mut expected = std::collections::BTreeMap::new();
        expected.insert(11u32, hex_to_32(&pcrs[4]));
        let event = attested_event(
            &group,
            2,
            1_700_000_000,
            pcrs,
            signed_share(&group, 2, 1_700_000_000),
        );
        let out = Output::new();
        let config = capture_policy_from_announces(&out, &group, &[event], &expected)
            .expect("a peer matching the expected PCR 11 must be pinned");
        assert_eq!(config.peer.len(), 1);
        assert_eq!(config.reference_pcrs[4], pcrs_pcr11_hex());
    }

    #[test]
    fn capture_refuses_peer_whose_expected_pcr_differs() {
        let group = [7u8; 32];
        let mut expected = std::collections::BTreeMap::new();
        expected.insert(11u32, [0xABu8; 32]); // NOT the announced PCR 11
        let event = attested_event(
            &group,
            2,
            1_700_000_000,
            default_pcrs(),
            signed_share(&group, 2, 1_700_000_000),
        );
        let out = Output::new();
        // The only peer is refused on the reference mismatch, so there is nothing to pin.
        assert!(capture_policy_from_announces(&out, &group, &[event], &expected).is_err());
    }

    #[test]
    fn capture_refuses_peer_not_attesting_the_expected_pcr() {
        let group = [7u8; 32];
        let mut expected = std::collections::BTreeMap::new();
        expected.insert(99u32, [0xABu8; 32]); // PCR 99 is not in the peer's selection
        let event = attested_event(
            &group,
            2,
            1_700_000_000,
            default_pcrs(),
            signed_share(&group, 2, 1_700_000_000),
        );
        let out = Output::new();
        assert!(capture_policy_from_announces(&out, &group, &[event], &expected).is_err());
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn pcrs_pcr11_hex() -> String {
        default_pcrs()[4].clone()
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
        assert!(
            capture_policy_from_announces(&out, &group, &[event], &Default::default()).is_err()
        );
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
        assert!(
            capture_policy_from_announces(&out, &group, &[event], &Default::default()).is_err()
        );
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
        let config = capture_policy_from_announces(&out, &group, &events, &Default::default())
            .expect("capture");
        assert_eq!(config.peer.len(), 1);
        assert_eq!(config.peer[0].index, 2);
    }

    #[test]
    fn capture_skips_peer_with_divergent_selection() {
        // Peer 3 quotes a different selection ({0} only) the single-reference
        // policy cannot express, so only peer 2 is pinned.
        let group = [7u8; 32];
        let events = vec![
            attested_event(
                &group,
                2,
                1_700_000_000,
                default_pcrs(),
                signed_share(&group, 2, 1_700_000_000),
            ),
            attested_event_sel(
                &group,
                3,
                1_700_000_000,
                "00000001000b03010000",
                vec!["00".repeat(32)],
                signed_share(&group, 3, 1_700_000_000),
            ),
        ];
        let out = Output::new();
        let config = capture_policy_from_announces(&out, &group, &events, &Default::default())
            .expect("capture");
        assert_eq!(config.peer.len(), 1);
        assert_eq!(config.peer[0].index, 2);
    }

    #[test]
    fn capture_ignores_announce_with_unauthenticated_quote() {
        // Valid proof-of-share, but the quote's nonce is bound to a different
        // timestamp than the announce carries, so verify_quote rejects it and
        // nothing is captured.
        let group = [7u8; 32];
        let selection = hex::decode(SELECTION).unwrap();
        let wrong_nonce =
            keep_frost_net::derive_announce_attestation_nonce(&group, 2, 1_700_000_999);
        let ev = evidence(&wrong_nonce, &selection, default_pcrs());
        let event = announce_event(
            &group,
            2,
            1_700_000_000,
            ev,
            signed_share(&group, 2, 1_700_000_000),
        );
        let out = Output::new();
        assert!(
            capture_policy_from_announces(&out, &group, &[event], &Default::default()).is_err()
        );
    }

    #[test]
    fn capture_bad_first_announce_does_not_poison_capture() {
        // A malformed first announce (invalid AK) must be skipped before it can
        // seed the baseline; a later valid peer is still captured.
        let group = [7u8; 32];
        let selection = hex::decode(SELECTION).unwrap();
        let nonce2 = keep_frost_net::derive_announce_attestation_nonce(&group, 2, 1_700_000_000);
        let mut bad = evidence(&nonce2, &selection, default_pcrs());
        bad.ak_sec1 = vec![0u8; 10]; // not a 65-byte SEC1 point
        let nonce3 = keep_frost_net::derive_announce_attestation_nonce(&group, 3, 1_700_000_000);
        let good = evidence(&nonce3, &selection, default_pcrs());
        let events = vec![
            announce_event(
                &group,
                2,
                1_700_000_000,
                bad,
                signed_share(&group, 2, 1_700_000_000),
            ),
            announce_event(
                &group,
                3,
                1_700_000_000,
                good,
                signed_share(&group, 3, 1_700_000_000),
            ),
        ];
        let out = Output::new();
        let config = capture_policy_from_announces(&out, &group, &events, &Default::default())
            .expect("capture");
        assert_eq!(config.peer.len(), 1);
        assert_eq!(config.peer[0].index, 3);
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
        let config = capture_policy_from_announces(&out, &group, &events, &Default::default())
            .expect("capture");
        assert_eq!(config.peer.len(), 1);
    }
}
