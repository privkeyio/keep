// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! TPM-quote attestation policy and appraisal, the parallel to the Nitro
//! [`crate::attestation`] path. A node pins, out of band (TOFU at provisioning),
//! each peer's AK public key, the PCR selection it must quote, and the reference
//! PCR values it must report. [`appraise_tpm_quote`] checks a presented
//! [`TpmQuoteEvidence`] against that policy and the announce-bound nonce, yielding
//! the normalized [`AttestationStatus`] the OPRF oracle gates on.

use std::collections::HashMap;

use p256::ecdsa::VerifyingKey;
use subtle::ConstantTimeEq;

use crate::peer::AttestationStatus;
use crate::protocol::TpmQuoteEvidence;

/// Verifier-side pinned policy for appraising peer TPM quotes.
#[derive(Clone, Debug)]
pub struct TpmAttestationPolicy {
    /// Pinned `TPML_PCR_SELECTION` bytes the quote must match exactly.
    pub pcr_selection: Vec<u8>,
    /// Pinned reference PCR values, in selection order.
    pub reference_pcrs: Vec<[u8; 32]>,
    /// `share_index -> pinned AK SEC1` (65-byte uncompressed point), TOFU.
    pub pinned_aks: HashMap<u16, Vec<u8>>,
}

impl TpmAttestationPolicy {
    pub fn new(
        pcr_selection: Vec<u8>,
        reference_pcrs: Vec<[u8; 32]>,
        pinned_aks: HashMap<u16, Vec<u8>>,
    ) -> Self {
        Self {
            pcr_selection,
            reference_pcrs,
            pinned_aks,
        }
    }
}

/// Appraise a TPM quote evidence against a pinned policy and an expected nonce.
/// Fail-closed: any pin miss, parse failure, or verification error yields
/// [`AttestationStatus::Failed`]. The nonce is a parameter so the caller can supply
/// the announce-bound value derived from the announce that carries the quote.
pub(crate) fn appraise_tpm_quote(
    share_index: u16,
    ev: &TpmQuoteEvidence,
    pol: &TpmAttestationPolicy,
    nonce: &[u8],
) -> AttestationStatus {
    // TOFU: the AK must be pinned for this share and match exactly (constant-time).
    let pinned_ok = pol
        .pinned_aks
        .get(&share_index)
        .is_some_and(|ak| ak.as_slice().ct_eq(ev.ak_sec1.as_slice()).unwrap_u8() == 1);
    if !pinned_ok {
        return AttestationStatus::Failed(format!(
            "AK not pinned or changed for share {share_index}"
        ));
    }

    let ak = match VerifyingKey::from_sec1_bytes(&ev.ak_sec1) {
        Ok(k) => k,
        Err(e) => return AttestationStatus::Failed(format!("TPM AK parse failed: {e}")),
    };

    let pcr_values = match crate::tpm_quote::decode_pcr_values(&ev.pcr_values) {
        Ok(v) => v,
        Err(e) => return AttestationStatus::Failed(e.to_string()),
    };

    match crate::tpm_quote::verify_quote(
        &ev.attest,
        &ev.signature,
        &ak,
        nonce,
        &pol.pcr_selection,
        &pcr_values,
        &pol.reference_pcrs,
    ) {
        Ok(()) => AttestationStatus::Verified,
        Err(e) => AttestationStatus::Failed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The real swtpm quote vector (ATTEST/SIG_*/AK_*/NONCE/PCR_SELECT/PCR11 and
    // h/h32) is the single source of truth in `tpm_quote::test_vector`.
    use crate::tpm_quote::test_vector::*;

    const ZERO_PCR: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const SHARE_INDEX: u16 = 2;

    fn ak_sec1() -> Vec<u8> {
        let mut v = vec![0x04u8];
        v.extend_from_slice(&h(AK_X));
        v.extend_from_slice(&h(AK_Y));
        v
    }

    fn pcr_value_strings() -> Vec<String> {
        // selection order: PCR 0, 2, 4, 7, 11, 12
        vec![
            ZERO_PCR.into(),
            ZERO_PCR.into(),
            ZERO_PCR.into(),
            ZERO_PCR.into(),
            PCR11.into(),
            ZERO_PCR.into(),
        ]
    }

    fn reference_pcrs() -> Vec<[u8; 32]> {
        let z = [0u8; 32];
        vec![z, z, z, z, h32(PCR11), z]
    }

    fn evidence() -> TpmQuoteEvidence {
        TpmQuoteEvidence {
            attest: h(ATTEST),
            signature: [h(SIG_R), h(SIG_S)].concat(),
            ak_sec1: ak_sec1(),
            pcr_values: pcr_value_strings(),
        }
    }

    fn policy() -> TpmAttestationPolicy {
        let mut pinned = HashMap::new();
        pinned.insert(SHARE_INDEX, ak_sec1());
        TpmAttestationPolicy::new(h(PCR_SELECT), reference_pcrs(), pinned)
    }

    #[test]
    fn tpm_appraise_verifies_real_quote() {
        let status = appraise_tpm_quote(SHARE_INDEX, &evidence(), &policy(), &h(NONCE));
        assert_eq!(status, AttestationStatus::Verified);
    }

    #[test]
    fn tpm_appraise_rejects_unpinned_ak() {
        let mut pol = policy();
        // A different pinned AK for this share (TOFU mismatch / key rotation).
        let mut other = ak_sec1();
        other[1] ^= 0x01;
        pol.pinned_aks.insert(SHARE_INDEX, other);
        let status = appraise_tpm_quote(SHARE_INDEX, &evidence(), &pol, &h(NONCE));
        assert!(matches!(status, AttestationStatus::Failed(_)));
    }

    #[test]
    fn tpm_appraise_rejects_missing_pin() {
        let pol = policy();
        // No pin for this share index.
        let status = appraise_tpm_quote(SHARE_INDEX + 1, &evidence(), &pol, &h(NONCE));
        assert!(matches!(status, AttestationStatus::Failed(_)));
    }

    #[test]
    fn tpm_appraise_rejects_wrong_reference_pcr() {
        let mut pol = policy();
        pol.reference_pcrs[4] = [0u8; 32]; // expect a different boot state at PCR 11
        let status = appraise_tpm_quote(SHARE_INDEX, &evidence(), &pol, &h(NONCE));
        assert!(matches!(status, AttestationStatus::Failed(_)));
    }

    #[test]
    fn tpm_appraise_rejects_tampered_attest() {
        let mut ev = evidence();
        let n = ev.attest.len();
        ev.attest[n - 1] ^= 0x01;
        let status = appraise_tpm_quote(SHARE_INDEX, &ev, &policy(), &h(NONCE));
        assert!(matches!(status, AttestationStatus::Failed(_)));
    }

    #[test]
    fn tpm_appraise_rejects_wrong_nonce() {
        let status = appraise_tpm_quote(SHARE_INDEX, &evidence(), &policy(), &[0u8; 16]);
        assert!(matches!(status, AttestationStatus::Failed(_)));
    }

    // The single-PCR `TPMS_ATTEST` builder lives in `crate::test_support` so the
    // verifier's unit tests and the end-to-end attestation tests share one wire
    // format. This case exercises the full nonce-derivation-to-verify wiring with
    // a 32-byte announce-bound nonce, which the fixed test-vector quote (a 16-byte
    // nonce) cannot.
    use crate::test_support::build_signed_quote;

    #[test]
    fn tpm_appraise_verifies_announce_bound_derived_nonce() {
        use crate::attestation::derive_announce_attestation_nonce;

        let group = [7u8; 32];
        let share_index: u16 = 2;
        let timestamp: u64 = 1_700_000_000;
        let nonce = derive_announce_attestation_nonce(&group, share_index, timestamp);

        let sk = p256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let ak_sec1 = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let pcr_select = crate::test_support::one_pcr_selection(); // sha256, one PCR
        let pcr_value = [0x11u8; 32];
        let (attest, signature) = build_signed_quote(&nonce, &pcr_select, &pcr_value, &sk);

        let ev = TpmQuoteEvidence {
            attest,
            signature,
            ak_sec1: ak_sec1.clone(),
            pcr_values: vec![hex::encode(pcr_value)],
        };
        let mut pinned = HashMap::new();
        pinned.insert(share_index, ak_sec1);
        let pol = TpmAttestationPolicy::new(pcr_select, vec![pcr_value], pinned);

        // The 32-byte announce-bound nonce derived from this announce verifies end to end.
        assert_eq!(
            appraise_tpm_quote(share_index, &ev, &pol, &nonce),
            AttestationStatus::Verified
        );

        // The same quote appraised against a DIFFERENT announce (one tick later) fails: the
        // qualifyingData no longer matches the derived nonce, so the quote cannot be replayed
        // across announces.
        let other = derive_announce_attestation_nonce(&group, share_index, timestamp + 1);
        assert!(matches!(
            appraise_tpm_quote(share_index, &ev, &pol, &other),
            AttestationStatus::Failed(_)
        ));
    }
}
