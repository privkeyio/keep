// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::error::{EnclaveError, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

#[derive(Clone)]
pub struct ExpectedPcrs {
    pub pcr0: [u8; 48],
    pub pcr1: [u8; 48],
    pub pcr2: [u8; 48],
}

impl ExpectedPcrs {
    pub fn new(pcr0: [u8; 48], pcr1: [u8; 48], pcr2: [u8; 48]) -> Self {
        Self { pcr0, pcr1, pcr2 }
    }

    pub fn from_hex(pcr0: &str, pcr1: &str, pcr2: &str) -> Result<Self> {
        let parse = |s: &str| -> Result<[u8; 48]> {
            let bytes = hex::decode(s).map_err(|e| EnclaveError::Attestation(e.to_string()))?;
            bytes
                .try_into()
                .map_err(|_| EnclaveError::Attestation("PCR must be 48 bytes".into()))
        };
        Ok(Self {
            pcr0: parse(pcr0)?,
            pcr1: parse(pcr1)?,
            pcr2: parse(pcr2)?,
        })
    }
}

#[derive(Debug)]
pub struct VerifiedAttestation {
    pub enclave_pubkey: Vec<u8>,
    pub pcrs: std::collections::HashMap<u32, Vec<u8>>,
    pub timestamp: u64,
    pub user_data: Option<Vec<u8>>,
}

pub struct AttestationVerifier {
    expected_pcrs: Option<ExpectedPcrs>,
    root_cert: Certificate,
}

const AWS_NITRO_ROOT_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"#;

fn parse_pem_cert(pem: &str) -> Certificate {
    let lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let b64 = lines.join("");
    use base64::Engine;
    let der = BASE64
        .decode(&b64)
        .expect("Invalid base64 in embedded root cert");
    Certificate::from_der(&der).expect("Invalid DER in embedded root cert")
}

impl AttestationVerifier {
    pub fn new(expected_pcrs: Option<ExpectedPcrs>) -> Self {
        let root_cert = parse_pem_cert(AWS_NITRO_ROOT_CERT_PEM);
        Self {
            expected_pcrs,
            root_cert,
        }
    }

    pub fn verify(&self, attestation_doc: &[u8], nonce: &[u8; 32]) -> Result<VerifiedAttestation> {
        let cose = CoseSign1::from_bytes(attestation_doc)?;
        let payload = cose
            .payload
            .as_ref()
            .ok_or_else(|| EnclaveError::Attestation("Missing COSE payload".into()))?;

        let attestation: AttestationDocument = ciborium::from_reader(payload.as_slice())
            .map_err(|e| EnclaveError::Attestation(format!("Failed to parse attestation: {e}")))?;

        self.verify_certificate_chain(&attestation.certificate, &attestation.cabundle, &cose)?;

        if let Some(doc_nonce) = &attestation.nonce {
            if doc_nonce.as_slice() != nonce {
                return Err(EnclaveError::Attestation("Nonce mismatch".into()));
            }
        } else {
            return Err(EnclaveError::Attestation(
                "Missing nonce in attestation".into(),
            ));
        }

        if let Some(expected) = &self.expected_pcrs {
            self.verify_pcrs(&attestation.pcrs, expected)?;
        }

        let enclave_pubkey = attestation
            .public_key
            .ok_or_else(|| EnclaveError::Attestation("Missing public key".into()))?;

        Ok(VerifiedAttestation {
            enclave_pubkey,
            pcrs: attestation.pcrs,
            timestamp: attestation.timestamp,
            user_data: attestation.user_data,
        })
    }

    fn verify_certificate_chain(
        &self,
        signing_cert_der: &[u8],
        cabundle: &[Vec<u8>],
        cose: &CoseSign1,
    ) -> Result<()> {
        let signing_cert = Certificate::from_der(signing_cert_der)
            .map_err(|e| EnclaveError::Certificate(format!("Failed to parse signing cert: {e}")))?;
        verify_cert_validity(&signing_cert)?;

        let signing_pubkey = extract_p384_pubkey(&signing_cert)?;
        let sig_bytes = cose.signature.as_slice();
        let signature = Signature::from_der(sig_bytes)
            .map_err(|e| EnclaveError::Attestation(format!("Invalid COSE signature: {e}")))?;

        let to_verify = cose.sig_structure()?;
        signing_pubkey
            .verify(&to_verify, &signature)
            .map_err(|_| EnclaveError::Attestation("COSE signature verification failed".into()))?;

        if cabundle.is_empty() {
            return Err(EnclaveError::Attestation("Empty certificate bundle".into()));
        }

        let issuer_cert_der = &cabundle[0];
        let issuer_cert = Certificate::from_der(issuer_cert_der)
            .map_err(|e| EnclaveError::Certificate(format!("Failed to parse issuer cert: {e}")))?;
        verify_cert_validity(&issuer_cert)?;

        let issuer_pubkey = extract_p384_pubkey(&issuer_cert)?;
        let tbs_bytes = signing_cert
            .tbs_certificate
            .to_der()
            .map_err(|e| EnclaveError::Certificate(format!("DER encode failed: {e}")))?;

        let cert_sig_bytes = signing_cert.signature.as_bytes().ok_or_else(|| {
            EnclaveError::Certificate("Missing signature bytes on signing cert".into())
        })?;

        let cert_signature = Signature::from_der(cert_sig_bytes)
            .map_err(|e| EnclaveError::Certificate(format!("Invalid signature: {e}")))?;

        issuer_pubkey
            .verify(&tbs_bytes, &cert_signature)
            .map_err(|_| {
                EnclaveError::Certificate("Signing certificate not issued by CA".into())
            })?;

        let mut certs = Vec::with_capacity(cabundle.len());
        for cert_der in cabundle {
            let cert = Certificate::from_der(cert_der)
                .map_err(|e| EnclaveError::Certificate(format!("Failed to parse cert: {e}")))?;
            verify_cert_validity(&cert)?;
            certs.push(cert);
        }

        for i in 0..certs.len().saturating_sub(1) {
            let subject = &certs[i];
            let issuer = &certs[i + 1];

            let issuer_pubkey = extract_p384_pubkey(issuer)?;
            let tbs_bytes = subject
                .tbs_certificate
                .to_der()
                .map_err(|e| EnclaveError::Certificate(format!("DER encode failed: {e}")))?;

            let sig_bytes = subject
                .signature
                .as_bytes()
                .ok_or_else(|| EnclaveError::Certificate("Missing signature bytes".into()))?;

            let signature = Signature::from_der(sig_bytes)
                .map_err(|e| EnclaveError::Certificate(format!("Invalid signature: {e}")))?;

            issuer_pubkey
                .verify(&tbs_bytes, &signature)
                .map_err(|_| EnclaveError::Certificate("Certificate signature invalid".into()))?;
        }

        let chain_root = certs
            .last()
            .ok_or_else(|| EnclaveError::Certificate("Empty certificate chain".into()))?;

        let chain_root_der = chain_root
            .to_der()
            .map_err(|e| EnclaveError::Certificate(format!("DER encode failed: {e}")))?;
        let expected_root_der = self
            .root_cert
            .to_der()
            .map_err(|e| EnclaveError::Certificate(format!("DER encode failed: {e}")))?;

        if chain_root_der != expected_root_der {
            return Err(EnclaveError::Certificate(
                "Certificate chain does not terminate at AWS Nitro root CA".into(),
            ));
        }

        Ok(())
    }

    fn verify_pcrs(
        &self,
        pcrs: &std::collections::HashMap<u32, Vec<u8>>,
        expected: &ExpectedPcrs,
    ) -> Result<()> {
        let check = |idx: u32, expected: &[u8; 48]| -> Result<()> {
            let actual = pcrs
                .get(&idx)
                .ok_or_else(|| EnclaveError::Attestation(format!("Missing PCR{idx}")))?;
            if actual.as_slice() != expected {
                return Err(EnclaveError::PcrMismatch {
                    pcr: idx,
                    expected: hex::encode(expected),
                    actual: hex::encode(actual),
                });
            }
            Ok(())
        };

        check(0, &expected.pcr0)?;
        check(1, &expected.pcr1)?;
        check(2, &expected.pcr2)?;

        Ok(())
    }
}

fn extract_p384_pubkey(cert: &Certificate) -> Result<VerifyingKey> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| EnclaveError::Certificate("Missing public key bytes".into()))?;

    VerifyingKey::from_sec1_bytes(key_bytes)
        .map_err(|e| EnclaveError::Certificate(format!("Invalid P-384 key: {e}")))
}

fn verify_cert_validity(cert: &Certificate) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EnclaveError::Certificate("System clock error".into()))?
        .as_secs();

    let validity = &cert.tbs_certificate.validity;

    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();

    if now < not_before {
        return Err(EnclaveError::Certificate(
            "Certificate not yet valid".into(),
        ));
    }
    if now > not_after {
        return Err(EnclaveError::Certificate("Certificate has expired".into()));
    }

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct AttestationDocument {
    #[serde(rename = "module_id")]
    _module_id: String,
    timestamp: u64,
    #[serde(rename = "digest")]
    _digest: String,
    pcrs: std::collections::HashMap<u32, Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

struct CoseSign1 {
    _protected: Vec<u8>,
    _unprotected: ciborium::Value,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    fn from_bytes(data: &[u8]) -> Result<Self> {
        let value: ciborium::Value = ciborium::from_reader(data)
            .map_err(|e| EnclaveError::Attestation(format!("Invalid CBOR: {e}")))?;

        let arr = value
            .as_array()
            .ok_or_else(|| EnclaveError::Attestation("COSE_Sign1 must be array".into()))?;

        if arr.len() != 4 {
            return Err(EnclaveError::Attestation(
                "COSE_Sign1 must have 4 elements".into(),
            ));
        }

        let protected = arr[0]
            .as_bytes()
            .ok_or_else(|| EnclaveError::Attestation("Invalid protected header".into()))?
            .clone();

        let unprotected = arr[1].clone();

        let payload = if arr[2].is_null() {
            None
        } else {
            Some(
                arr[2]
                    .as_bytes()
                    .ok_or_else(|| EnclaveError::Attestation("Invalid payload".into()))?
                    .clone(),
            )
        };

        let signature = arr[3]
            .as_bytes()
            .ok_or_else(|| EnclaveError::Attestation("Invalid signature".into()))?
            .clone();

        Ok(Self {
            _protected: protected,
            _unprotected: unprotected,
            payload,
            signature,
        })
    }

    fn sig_structure(&self) -> Result<Vec<u8>> {
        let structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".into()),
            ciborium::Value::Bytes(self._protected.clone()),
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Bytes(self.payload.clone().unwrap_or_default()),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&structure, &mut buf).map_err(|e| {
            EnclaveError::Attestation(format!("Failed to encode sig structure: {e}"))
        })?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_pcrs_from_hex() {
        let pcr0 = "0".repeat(96);
        let pcr1 = "1".repeat(96);
        let pcr2 = "2".repeat(96);

        let pcrs = ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2).unwrap();
        assert_eq!(pcrs.pcr0[0], 0x00);
        assert_eq!(pcrs.pcr1[0], 0x11);
        assert_eq!(pcrs.pcr2[0], 0x22);
    }
}
