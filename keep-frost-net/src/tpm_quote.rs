// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Pure-Rust verification of a TPM 2.0 quote (`TPMS_ATTEST` of type
//! `TPM_ST_ATTEST_QUOTE`). NO TPM and NO libtss2 are required on the verifier:
//! every step is byte parsing plus one ECDSA-P256 signature check and SHA-256.
//! Only the quote PRODUCER (a node attesting its own measured-boot state) needs
//! a TPM; every node can VERIFY a peer's quote with this module.
//!
//! The verifier performs the mandatory checks, each tied to a known CVE class
//! (see ATTESTATION-DESIGN.md / RFC 9683 / tpm2_checkquote):
//!   1. magic == `TPM_GENERATED` (0xFF544347)        [GHSA-5495-c38w-gr6f]
//!   2. attest type == `TPM_ST_ATTEST_QUOTE` (0x8018)
//!   3. extraData == the expected nonce              (binds the quote to this announce)
//!   4. quoted pcrSelection == the pinned selection    [GHSA-8rjm-5f5f-h4q6]
//!   5. recomputed PCR composite digest == attested pcrDigest
//!   6. claimed PCR values == pinned reference values
//!   7. ECDSA-P256 signature over SHA-256(attest) verifies with the pinned AK
//!
//! The AK public key is pinned out of band (TOFU at provisioning); this module
//! does not establish AK->device identity (that is the EK/MakeCredential flow).
//!
//! Freshness: the announce nonce is bound to the specific announce that carries the quote. The
//! production caller derives it from the group public key, the announcing share index, and the
//! announce timestamp, and the quote producer MUST quote with that exact value as `qualifyingData`.
//! Check 3 therefore stops a valid quote from being lifted into a different or forged announce
//! (cross-announce replay), and the signed announce timestamp (`ANNOUNCE_MAX_AGE_SECS`) bounds
//! replay of the announce itself. As with all attestation, this proves boot-time state, not
//! runtime (TOCTOU).

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{FrostNetError, Result};

const TPM_GENERATED: u32 = 0xFF54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
const PCR_DIGEST_LEN: usize = 32;

fn att(msg: &str) -> FrostNetError {
    FrostNetError::Attestation(msg.to_string())
}

/// Minimal big-endian, bounds-checked cursor over the marshaled attest bytes.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| att("TPM quote: length overflow"))?;
        let s = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| att("TPM quote: truncated"))?;
        self.offset = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// `TPM2B_*`: a u16 size followed by that many bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// The fields of a parsed quote that the appraisal needs.
struct ParsedQuote<'a> {
    extra_data: &'a [u8],
    pcr_select: &'a [u8],
    pcr_digest: &'a [u8],
}

/// Parse a marshaled `TPMS_ATTEST` of type quote and enforce checks 1-2 (magic,
/// type). The input is the inner `TPMS_ATTEST` (starting at the magic, with no
/// outer `TPM2B_ATTEST` size prefix), which is exactly the byte string the TPM
/// signed.
fn parse_quote(attest: &[u8]) -> Result<ParsedQuote<'_>> {
    let mut c = Cursor::new(attest);
    if c.u32()? != TPM_GENERATED {
        return Err(att("TPM quote: bad magic (not TPM_GENERATED)"));
    }
    if c.u16()? != TPM_ST_ATTEST_QUOTE {
        return Err(att("TPM quote: attestation is not a quote"));
    }
    let _qualified_signer = c.tpm2b()?; // TPM2B_NAME
    let extra_data = c.tpm2b()?; // TPM2B_DATA (the nonce)
    let _clock_info = c.take(17)?; // TPMS_CLOCK_INFO: u64 + u32 + u32 + u8
    let _firmware_version = c.take(8)?; // UINT64
                                        // TPMS_QUOTE_INFO.pcrSelect = TPML_PCR_SELECTION:
                                        //   count: u32, then count * { hash: u16, sizeofSelect: u8, select[sizeofSelect] }
    let sel_start = c.offset;
    let count = c.u32()?;
    for _ in 0..count {
        let _hash = c.u16()?;
        let size = c.u8()? as usize;
        c.take(size)?;
    }
    let pcr_select = &attest[sel_start..c.offset];
    let pcr_digest = c.tpm2b()?; // TPM2B_DIGEST (the attested composite)
    Ok(ParsedQuote {
        extra_data,
        pcr_select,
        pcr_digest,
    })
}

/// Extract the marshaled `TPML_PCR_SELECTION` bytes from a quote's `TPMS_ATTEST`.
/// The selection a verifier must pin lives only inside the signed quote, so
/// trust-on-first-use provisioning reads it from an observed announce. This
/// validates magic and type but performs NO signature or freshness check: the
/// caller is establishing trust, not relying on it.
pub fn pcr_selection_from_attest(attest: &[u8]) -> Result<Vec<u8>> {
    Ok(parse_quote(attest)?.pcr_select.to_vec())
}

/// Verify a TPM2 quote against a pinned AK, expected nonce, pinned PCR selection,
/// and pinned reference PCR values. `pcr_values` are the holder's claimed PCR
/// digests in the SAME order as the selection; `attest` is the marshaled
/// `TPMS_ATTEST` and `signature_rs` its 64-byte ECDSA-P256 `r || s` signature.
///
/// Returns `Ok(())` only if all seven checks pass; any failure is fail-closed.
#[allow(clippy::too_many_arguments)]
pub fn verify_quote(
    attest: &[u8],
    signature_rs: &[u8],
    ak: &VerifyingKey,
    expected_nonce: &[u8],
    pinned_pcr_select: &[u8],
    pcr_values: &[[u8; PCR_DIGEST_LEN]],
    reference_pcrs: &[[u8; PCR_DIGEST_LEN]],
) -> Result<()> {
    let q = parse_quote(attest)?; // checks 1, 2

    // 3: nonce equality (binds the quote to this announce; see module docs on freshness), constant-time.
    if q.extra_data.ct_eq(expected_nonce).unwrap_u8() != 1 {
        return Err(att("TPM quote: nonce mismatch"));
    }
    // 4: the quote's PCR selection must equal the pinned selection, so the
    // attested digest provably binds the claimed VALUES to the expected INDICES.
    if q.pcr_select != pinned_pcr_select {
        return Err(att(
            "TPM quote: PCR selection does not match the pinned selection",
        ));
    }
    // 5: recompute the PCR composite digest from the claimed values, in
    // selection order, and require it to equal the attested pcrDigest.
    let mut h = Sha256::new();
    for v in pcr_values {
        h.update(v);
    }
    let composite = h.finalize();
    if composite.as_slice().ct_eq(q.pcr_digest).unwrap_u8() != 1 {
        return Err(att(
            "TPM quote: recomputed PCR digest does not match the attested digest",
        ));
    }
    // 6: the claimed PCR values must equal the pinned reference values.
    if pcr_values.len() != reference_pcrs.len() {
        return Err(att("TPM quote: PCR count does not match the reference"));
    }
    let mut matched = 1u8;
    for (v, r) in pcr_values.iter().zip(reference_pcrs.iter()) {
        matched &= v.ct_eq(r).unwrap_u8();
    }
    if matched != 1 {
        return Err(att(
            "TPM quote: PCR values do not match the reference (unexpected boot state)",
        ));
    }
    // 7: ECDSA-P256 signature over SHA-256(attest) with the pinned AK.
    let sig =
        Signature::from_slice(signature_rs).map_err(|_| att("TPM quote: malformed signature"))?;
    let prehash = Sha256::digest(attest);
    ak.verify_prehash(&prehash, &sig)
        .map_err(|_| att("TPM quote: signature does not verify against the pinned AK"))?;
    Ok(())
}

/// Decode hex-encoded PCR values (each a 32-byte SHA-256 digest) into fixed arrays.
/// Every entry must be exactly 64 hex characters; the length is checked BEFORE decoding
/// so the decode allocation is never sized by attacker-controlled input. Fail-closed: any
/// malformed entry is an error. The number of values is bounded by the caller.
pub(crate) fn decode_pcr_values(
    values: &[String],
) -> core::result::Result<Vec<[u8; PCR_DIGEST_LEN]>, &'static str> {
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        if v.len() != 64 {
            return Err("TPM PCR value must be 64 hex characters");
        }
        let bytes = hex::decode(v).map_err(|_| "TPM PCR value must be 32 hex-encoded bytes")?;
        let arr = <[u8; PCR_DIGEST_LEN]>::try_from(bytes.as_slice())
            .map_err(|_| "TPM PCR value must be 32 hex-encoded bytes")?;
        out.push(arr);
    }
    Ok(out)
}

/// Canonical real-swtpm quote vector (swtpm 0.10.1 + tpm2-tools 5.7, ECDSA-P256/
/// SHA-256 AK over sha256:0,2,4,7,11,12, verified by tpm2_checkquote). Shared by
/// the verifier tests below and the producer's marshal-contract test, so both
/// sides are pinned to the same wire bytes.
#[cfg(test)]
pub(crate) mod test_vector {
    use super::*;
    use p256::{EncodedPoint, FieldBytes};

    pub(crate) const ATTEST: &str = "ff54434780180022000bb9df3193fe4f66ac5a3ee8f8552e454d20bbae633354bcff12b65d581f9d38c7001000112233445566778899aabbccddeeff000000000000041f000000010000000001202401250012000000000001000b03951800002094d0f020a3c4d09b8b88e69e7a093a38ec0ff9715cfdc70285d99d236c52990a";
    pub(crate) const SIG_R: &str =
        "0408dac9c80e649049e75fc74d6e1634fa4922066ce488b49b5110e7125b172b";
    pub(crate) const SIG_S: &str =
        "124fd1dc171546bde98f4409ad002fa7ccad75a65374ea7ee96381de337b34f0";
    pub(crate) const AK_X: &str =
        "f533789fb86ad512ca3e930df08cd16396d14c30c79c46a88839b574a3dfb327";
    pub(crate) const AK_Y: &str =
        "1b3db55b2abdc884e40898e95dfffd2c7e8554526d4e1f651779bab1f81300cb";
    pub(crate) const NONCE: &str = "00112233445566778899aabbccddeeff";
    pub(crate) const PCR_SELECT: &str = "00000001000b03951800";
    pub(crate) const PCR11: &str =
        "cf2b0db7514f320c315130275a960f6e6ed80744c754c687069d7a9f55d704f0";

    pub(crate) fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }
    pub(crate) fn h32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }
    pub(crate) fn ak() -> VerifyingKey {
        let x = h(AK_X);
        let y = h(AK_Y);
        let point = EncodedPoint::from_affine_coordinates(
            FieldBytes::from_slice(&x),
            FieldBytes::from_slice(&y),
            false,
        );
        VerifyingKey::from_encoded_point(&point).unwrap()
    }
    pub(crate) fn sig_rs() -> Vec<u8> {
        [h(SIG_R), h(SIG_S)].concat()
    }
    pub(crate) fn pcrs() -> [[u8; 32]; 6] {
        let z = [0u8; 32];
        // selection order: PCR 0, 2, 4, 7, 11, 12
        [z, z, z, z, h32(PCR11), z]
    }
}

#[cfg(test)]
mod tests {
    use super::test_vector::*;
    use super::*;

    #[test]
    fn pcr_selection_from_attest_matches_pinned_selection() {
        // The selection extracted from the real quote equals the pinned bytes
        // the verifier checks (`PCR_SELECT`), so TOFU provisioning recovers it.
        let sel = super::pcr_selection_from_attest(&h(ATTEST)).expect("extract selection");
        assert_eq!(sel, h(PCR_SELECT));
    }

    #[test]
    fn pcr_selection_from_attest_rejects_non_quote() {
        assert!(super::pcr_selection_from_attest(&[0u8; 8]).is_err());
    }

    #[test]
    fn verifies_real_swtpm_quote() {
        let pcrs = pcrs();
        verify_quote(
            &h(ATTEST),
            &sig_rs(),
            &ak(),
            &h(NONCE),
            &h(PCR_SELECT),
            &pcrs,
            &pcrs, // pinned reference == the actual measured state (happy path)
        )
        .expect("a valid, fresh quote in the expected boot state must verify");
    }

    #[test]
    fn rejects_wrong_nonce() {
        let pcrs = pcrs();
        let r = verify_quote(
            &h(ATTEST),
            &sig_rs(),
            &ak(),
            &[0u8; 16], // a replayed/stale nonce
            &h(PCR_SELECT),
            &pcrs,
            &pcrs,
        );
        assert!(r.is_err(), "a nonce mismatch must be rejected");
    }

    #[test]
    fn rejects_unexpected_pcr_state() {
        let pcrs = pcrs();
        let mut refs = pcrs;
        refs[4] = [0u8; 32]; // reference expects PCR 11 = 0 (a different OS)
        let r = verify_quote(
            &h(ATTEST),
            &sig_rs(),
            &ak(),
            &h(NONCE),
            &h(PCR_SELECT),
            &pcrs,
            &refs,
        );
        assert!(
            r.is_err(),
            "PCR values not matching the reference must be rejected"
        );
    }

    #[test]
    fn rejects_tampered_attest() {
        let mut attest = h(ATTEST);
        let n = attest.len();
        attest[n - 1] ^= 0x01; // flip a bit of the attested pcrDigest
        let pcrs = pcrs();
        let r = verify_quote(
            &attest,
            &sig_rs(),
            &ak(),
            &h(NONCE),
            &h(PCR_SELECT),
            &pcrs,
            &pcrs,
        );
        assert!(
            r.is_err(),
            "any tampering breaks the signature and/or the digest"
        );
    }

    #[test]
    fn rejects_forged_pcr_selection() {
        // An attacker presents PCR 0,1,2 values as if they were the pinned 0,2,4,7,11,12
        // selection. The selection-equality check (4) must catch it before the digest math.
        let pcrs = pcrs();
        let forged_select = h("00000001000b03070000"); // PCRs 0,1,2
        let r = verify_quote(
            &h(ATTEST),
            &sig_rs(),
            &ak(),
            &h(NONCE),
            &forged_select,
            &pcrs,
            &pcrs,
        );
        assert!(
            r.is_err(),
            "a selection mismatch must be rejected (GHSA-8rjm-5f5f-h4q6)"
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let mut attest = h(ATTEST);
        attest[0] = 0x00; // corrupt TPM_GENERATED
        let pcrs = pcrs();
        let r = verify_quote(
            &attest,
            &sig_rs(),
            &ak(),
            &h(NONCE),
            &h(PCR_SELECT),
            &pcrs,
            &pcrs,
        );
        assert!(
            r.is_err(),
            "missing TPM_GENERATED magic must be rejected (GHSA-5495-c38w-gr6f)"
        );
    }
}
