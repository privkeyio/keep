// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! TPM-side quote PRODUCER (feature `tpm-attestation`): the counterpart to the
//! always-built pure-Rust verifier in [`crate::tpm_quote`]. A node with a real
//! TPM 2.0 uses this to produce the [`TpmQuoteEvidence`] it attaches to its
//! announce; peers appraise it with [`crate::tpm_policy::appraise_tpm_quote`].
//!
//! This module links the tpm2-tss C stack (via `tss-esapi`) and so is gated
//! behind the `tpm-attestation` feature. Nodes that only VERIFY peers do not
//! need it, and default builds do not compile it.
//!
//! Trust model: the attestation key (AK) is a restricted ECDSA-P256 signing key
//! created as a primary in the Endorsement hierarchy. Being a primary, it is
//! derived deterministically from the TPM's endorsement seed, so it is stable
//! across reboots without persistent-handle management, and being restricted it
//! can only sign TPM-internal structures (quotes), never attacker-chosen data.
//! Its public key is pinned out of band at provisioning (TOFU); this module does
//! not perform EK credential activation (there is no manufacturer IDevID to
//! anchor for a self-hosted box, per ATTESTATION-DESIGN.md).

use sha2::{Digest, Sha256};
use tss_esapi::abstraction::pcr;
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    AttestInfo, Data, EccScheme, HashScheme, KeyDerivationFunctionScheme, PcrSelectionList,
    PcrSelectionListBuilder, PcrSlot, Public, PublicBuilder, PublicEccParametersBuilder, Signature,
    SignatureScheme,
};
use tss_esapi::traits::Marshall;
use tss_esapi::utils::PublicKey;
use tss_esapi::Context;

use crate::error::{FrostNetError, Result};
use crate::protocol::TpmQuoteEvidence;

/// Measured-boot PCRs quoted by default: firmware/config (0), extended firmware
/// (2), boot loader (4), Secure Boot policy (7), and the systemd-stub/UKI kernel
/// + OS measurements (11, 12). Matches the selection the verifier pins.
pub const DEFAULT_PCR_SLOTS: [PcrSlot; 6] = [
    PcrSlot::Slot0,
    PcrSlot::Slot2,
    PcrSlot::Slot4,
    PcrSlot::Slot7,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
];

fn tpm_err(e: tss_esapi::Error) -> FrostNetError {
    FrostNetError::Attestation(format!("TPM error: {e}"))
}

fn att(msg: impl Into<String>) -> FrostNetError {
    FrostNetError::Attestation(msg.into())
}

/// Left-pad a big-endian ECC parameter to a fixed 32 bytes. The TPM may return r,
/// s, x, or y with leading zero bytes trimmed; P-256 fields are 32 bytes wide.
fn pad32(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.is_empty() || bytes.len() > 32 {
        return Err(att("TPM ECC parameter not in 1..=32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

/// Template for the restricted ECDSA-P256 signing AK.
fn ak_template() -> Result<Public> {
    let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .build()
        .map_err(tpm_err)?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(tpm_err)?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(Default::default())
        .build()
        .map_err(tpm_err)
}

/// The uncompressed SEC1 point `0x04 || x || y` of an ECC public key.
fn ecc_sec1(public: &Public) -> Result<Vec<u8>> {
    let key = PublicKey::try_from(public.clone()).map_err(tpm_err)?;
    let (x, y) = match key {
        PublicKey::Ecc { x, y } => (x, y),
        _ => return Err(att("AK is not an ECC key")),
    };
    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(&pad32(&x)?);
    out.extend_from_slice(&pad32(&y)?);
    Ok(out)
}

/// The 64-byte `r || s` of an ECDSA signature.
fn ecdsa_rs(signature: &Signature) -> Result<Vec<u8>> {
    let ecc = match signature {
        Signature::EcDsa(ecc) => ecc,
        _ => return Err(att("AK quote signature is not ECDSA")),
    };
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&pad32(ecc.signature_r().value())?);
    out.extend_from_slice(&pad32(ecc.signature_s().value())?);
    Ok(out)
}

/// Produces TPM2 quotes over a fixed PCR selection, signed by a restricted AK.
/// Holds the open [`Context`] and the AK handle for the node's lifetime.
pub struct TpmQuoter {
    context: Context,
    ak_handle: KeyHandle,
    ak_sec1: Vec<u8>,
    pcr_selection: PcrSelectionList,
    ordered_slots: Vec<PcrSlot>,
}

impl TpmQuoter {
    /// Create the AK (restricted ECDSA-P256 Endorsement-hierarchy primary) and
    /// fix the PCR selection this quoter will attest over. `slots` are quoted
    /// from the SHA-256 bank in ascending PCR order, which is the order the
    /// verifier recomputes the composite digest in.
    pub fn create(mut context: Context, slots: &[PcrSlot]) -> Result<Self> {
        if slots.is_empty() {
            return Err(att("TPM quoter needs at least one PCR slot"));
        }
        let mut ordered_slots = slots.to_vec();
        ordered_slots.sort_by_key(|s| u32::from(*s));
        ordered_slots.dedup();

        let pcr_selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &ordered_slots)
            .build()
            .map_err(tpm_err)?;

        let template = ak_template()?;
        let primary = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Endorsement, template, None, None, None, None)
            })
            .map_err(tpm_err)?;

        // From here the AK is allocated in the TPM; flush it on any error so a
        // transient handle does not leak. Once the struct is built, Drop owns it.
        let ak_sec1 = match ecc_sec1(&primary.out_public) {
            Ok(sec1) => sec1,
            Err(e) => {
                let _ = context.flush_context(ObjectHandle::from(primary.key_handle));
                return Err(e);
            }
        };

        Ok(Self {
            context,
            ak_handle: primary.key_handle,
            ak_sec1,
            pcr_selection,
            ordered_slots,
        })
    }

    /// Convenience constructor over [`DEFAULT_PCR_SLOTS`].
    pub fn create_default(context: Context) -> Result<Self> {
        Self::create(context, &DEFAULT_PCR_SLOTS)
    }

    /// The pinned AK identity (65-byte uncompressed SEC1 point). The verifier
    /// pins this at provisioning.
    pub fn ak_sec1(&self) -> &[u8] {
        &self.ak_sec1
    }

    /// Produce a fresh quote over the configured PCRs, bound to `nonce` (the
    /// announce-bound value from [`crate::attestation::derive_announce_attestation_nonce`]).
    /// The returned evidence is ready to attach to an announce.
    pub fn quote(&mut self, nonce: &[u8]) -> Result<TpmQuoteEvidence> {
        if nonce.len() != 32 {
            return Err(att("quote nonce must be exactly 32 bytes"));
        }
        let qualifying_data = Data::try_from(nonce.to_vec())
            .map_err(|_| att("quote nonce too long for TPM2B_DATA"))?;

        // The quote attests a PCR composite captured at quote time; the reported
        // PCR values are read separately, right after. If a selected PCR changes
        // in between, the values would no longer reproduce the attested digest and
        // the verifier (which recomputes the composite, check 5) would reject an
        // otherwise-honest quote. Re-quote a bounded number of times until the
        // read reproduces the attested digest, so the evidence is self-consistent.
        const MAX_ATTEMPTS: usize = 3;
        for _ in 0..MAX_ATTEMPTS {
            let selection = self.pcr_selection.clone();
            let ak_handle = self.ak_handle;
            // Restricted key: scheme must be Null so the key's own scheme is used.
            let (attest, signature) = self
                .context
                .execute_with_nullauth_session(|ctx| {
                    ctx.quote(
                        ak_handle,
                        qualifying_data.clone(),
                        SignatureScheme::Null,
                        selection,
                    )
                })
                .map_err(tpm_err)?;

            let attested_digest = match attest.attested() {
                AttestInfo::Quote { info } => info.pcr_digest().value().to_vec(),
                _ => return Err(att("TPM returned a non-quote attestation")),
            };

            // Read the live PCR values in the same ascending order the verifier
            // recomputes the composite digest in, accumulating that composite.
            let pcr_data =
                pcr::read_all(&mut self.context, self.pcr_selection.clone()).map_err(tpm_err)?;
            let bank = pcr_data
                .pcr_bank(HashingAlgorithm::Sha256)
                .ok_or_else(|| att("TPM returned no SHA-256 PCR bank"))?;
            let mut pcr_values = Vec::with_capacity(self.ordered_slots.len());
            let mut composite = Sha256::new();
            for slot in &self.ordered_slots {
                let digest = bank
                    .get_digest(*slot)
                    .ok_or_else(|| att("TPM did not return a value for a selected PCR"))?;
                composite.update(digest.value());
                pcr_values.push(hex::encode(digest.value()));
            }

            // A selected PCR changed between the quote and the read; discard this
            // inconsistent pair and re-quote.
            if composite.finalize().as_slice() != attested_digest.as_slice() {
                continue;
            }

            return Ok(TpmQuoteEvidence {
                attest: attest.marshall().map_err(tpm_err)?,
                signature: ecdsa_rs(&signature)?,
                ak_sec1: self.ak_sec1.clone(),
                pcr_values,
            });
        }

        Err(att(
            "PCR state changed during quoting; no consistent quote after retries",
        ))
    }
}

impl Drop for TpmQuoter {
    /// Flush the transient AK so it does not linger in the TPM's limited object
    /// memory after the quoter is dropped (a direct swtpm/`/dev/tpm0` connection,
    /// unlike a resource manager, does not auto-flush on close).
    fn drop(&mut self) {
        let _ = self
            .context
            .flush_context(ObjectHandle::from(self.ak_handle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::derive_announce_attestation_nonce;
    use crate::peer::AttestationStatus;
    use crate::tpm_policy::{appraise_tpm_quote, TpmAttestationPolicy};
    use std::collections::HashMap;
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::structures::{PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme};
    use tss_esapi::{Context, TctiNameConf};

    #[test]
    fn pad32_rejects_empty() {
        assert!(pad32(&[]).is_err());
    }

    #[test]
    fn pad32_full_width_roundtrips() {
        let input = [7u8; 32];
        assert_eq!(pad32(&input).unwrap(), input);
    }

    #[test]
    fn pad32_left_pads_short_input() {
        let out = pad32(&[0xaa, 0xbb]).unwrap();
        let mut expected = [0u8; 32];
        expected[30] = 0xaa;
        expected[31] = 0xbb;
        assert_eq!(out, expected);
    }

    #[test]
    fn pad32_rejects_oversized_input() {
        assert!(pad32(&[0u8; 33]).is_err());
    }

    #[test]
    fn ecc_sec1_rejects_non_ecc_key() {
        let object_attributes = ObjectAttributesBuilder::new().build().unwrap();
        let rsa_params = PublicRsaParametersBuilder::new()
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .build()
            .unwrap();
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .unwrap();
        match ecc_sec1(&public) {
            Err(FrostNetError::Attestation(m)) => assert_eq!(m, "AK is not an ECC key"),
            other => panic!("expected non-ECC attestation error, got {other:?}"),
        }
    }

    #[test]
    fn ecdsa_rs_rejects_non_ecdsa_signature() {
        match ecdsa_rs(&Signature::Null) {
            Err(FrostNetError::Attestation(m)) => assert_eq!(m, "AK quote signature is not ECDSA"),
            other => panic!("expected non-ECDSA attestation error, got {other:?}"),
        }
    }

    // Marshalled TPML_PCR_SELECTION for the SHA-256 bank over DEFAULT_PCR_SLOTS
    // {0,2,4,7,11,12}: count=1, alg=0x000b, sizeofSelect=3, bitmap 0x95 0x18 0x00.
    // The verifier pins exactly these bytes (check 4).
    const DEFAULT_SELECTION: &str = "00000001000b03951800";

    fn tcti_context() -> Context {
        let tcti = TctiNameConf::from_environment_variable()
            .expect("set TPM2TOOLS_TCTI / TCTI (e.g. swtpm:host=localhost,port=2321)");
        Context::new(tcti).expect("open TPM context")
    }

    // End-to-end against a real (virtual) TPM: produce a quote with the producer,
    // then appraise it with the pure-Rust verifier. Ignored by default because it
    // needs a TPM; run with a swtpm and TPM2TOOLS_TCTI set.
    #[test]
    #[ignore = "requires a TPM; run against swtpm with TPM2TOOLS_TCTI set"]
    fn produce_then_verify_roundtrip() {
        let mut quoter = TpmQuoter::create_default(tcti_context()).expect("create quoter");
        let ak_sec1 = quoter.ak_sec1().to_vec();
        assert_eq!(ak_sec1.len(), 65, "AK SEC1 must be 65 bytes");
        assert_eq!(ak_sec1[0], 0x04, "AK SEC1 must be uncompressed");

        let group = [9u8; 32];
        let share_index: u16 = 2;
        let timestamp: u64 = 1_700_000_000;
        let nonce = derive_announce_attestation_nonce(&group, share_index, timestamp);

        let ev = quoter.quote(&nonce).expect("produce quote");
        assert_eq!(ev.signature.len(), 64, "signature must be r||s");
        assert_eq!(ev.ak_sec1, ak_sec1);
        assert_eq!(ev.pcr_values.len(), DEFAULT_PCR_SLOTS.len());

        // Verifier pins the AK, the agreed selection, and the reported PCRs as
        // the reference (TOFU at provisioning), then appraises the SAME announce.
        let pcr_values = crate::tpm_quote::decode_pcr_values(&ev.pcr_values).unwrap();
        let mut pinned = HashMap::new();
        pinned.insert(share_index, ak_sec1.clone());
        let pol =
            TpmAttestationPolicy::new(hex::decode(DEFAULT_SELECTION).unwrap(), pcr_values, pinned);
        assert_eq!(
            appraise_tpm_quote(share_index, &ev, &pol, &nonce),
            AttestationStatus::Verified,
            "a freshly produced quote must verify against the verifier"
        );

        // A different announce (one tick later) must fail: the qualifyingData no
        // longer matches, so a captured quote cannot be replayed across announces.
        let other = derive_announce_attestation_nonce(&group, share_index, timestamp + 1);
        assert!(
            matches!(
                appraise_tpm_quote(share_index, &ev, &pol, &other),
                AttestationStatus::Failed(_)
            ),
            "the quote must not verify against a different announce"
        );
    }
}
