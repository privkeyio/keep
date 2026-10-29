// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Android Key Attestation of a phone's approver key, judged when the phone
//! pairs.
//!
//! The phone makes its approver key in the Keystore with the pairing
//! session's challenge, and sends the chain `KeyStore.getCertificateChain`
//! returns, leaf first. The gateway takes the key only if the chain:
//!
//! - ends in one of Google's attestation roots, pinned by the SHA-256 of its
//!   public key, and each certificate is signed by the next and names it as
//!   issuer;
//! - is in date by the rules Google's own verifier keeps: the leaf's dates
//!   are set on the device and not judged, a certificate not yet valid is
//!   refused, and an expired one is refused unless the chain was provisioned
//!   in the factory, whose keys cannot be rotated;
//! - carries the attestation record in the leaf and nowhere else, since only
//!   the first record the secure hardware issued can be trusted;
//! - says the key is the paired approver key, made in a TEE or StrongBox
//!   from this session's challenge, a P-256 signing key that is generated
//!   there, needs a biometric for every use and never works without one;
//! - says the device is locked and boots either its maker's verified OS or
//!   GrapheneOS, whose boot keys are pinned per device;
//! - and names only the Keep app, signed with its release key.
//!
//! Revocation is judged by the pair command, which can reach Google's
//! status list: the gateway has no network. It gets the chain's serial
//! numbers back for that.

use keep_approval::pairing::{APP_PACKAGE, APP_SIGNER};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_cert::der::asn1::ObjectIdentifier as Oid;
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Where Google lists the attestation certificates it has revoked or
/// suspended.
pub const STATUS_URL: &str = "https://android.googleapis.com/attestation/status";

/// The largest status list read, well above the size Google serves.
const MAX_STATUS_BYTES: usize = 8 << 20;

/// Fetch Google's attestation status list, over TLS checked against the
/// bundled web roots only.
pub fn fetch_status() -> Result<Vec<u8>, String> {
    let failed = |e: &dyn std::fmt::Display| format!("fetching {STATUS_URL}: {e}");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| failed(&e))?;
    runtime.block_on(async {
        let tls = crate::inject::worker::client_config(crate::inject::worker::roots());
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| failed(&e))?;
        let mut response = client
            .get(STATUS_URL)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| failed(&e))?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| failed(&e))? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_STATUS_BYTES {
                return Err(failed(&"the list is too large"));
            }
        }
        Ok(body)
    })
}

/// The serial numbers a status list marks revoked or suspended, lowercase
/// hex as [`Attested::serials`] writes them. A suspended certificate is
/// refused too: pairing is a one-time decision. The list writes some
/// serials in decimal, so an all-digit entry counts in both readings.
pub fn unusable_serials(list: &[u8]) -> Result<std::collections::HashSet<String>, String> {
    #[derive(serde::Deserialize)]
    struct List {
        entries: std::collections::HashMap<String, Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        status: String,
    }
    if list.len() > MAX_STATUS_BYTES {
        return Err("the attestation status list is too large".into());
    }
    let list: List = serde_json::from_slice(list)
        .map_err(|e| format!("the attestation status list does not parse: {e}"))?;
    Ok(list
        .entries
        .into_iter()
        .filter(|(_, e)| matches!(e.status.as_str(), "REVOKED" | "SUSPENDED"))
        .flat_map(|(serial, _)| {
            // A certificate serial is at most 20 bytes, 49 decimal digits.
            let decimal = (serial.len() <= 49 && serial.bytes().all(|b| b.is_ascii_digit()))
                .then(|| decimal_to_hex(&serial));
            let serial = serial.to_ascii_lowercase();
            let trimmed = serial.trim_start_matches('0');
            let hex = if trimmed.is_empty() {
                "0".into()
            } else {
                trimmed.to_string()
            };
            std::iter::once(hex).chain(decimal)
        })
        .collect())
}

/// `digits` read as a decimal number, written as unpadded lowercase hex.
fn decimal_to_hex(digits: &str) -> String {
    let mut value = vec![0u8];
    for d in digits.bytes() {
        let mut carry = u32::from(d - b'0');
        for byte in value.iter_mut().rev() {
            let next = u32::from(*byte) * 10 + carry;
            *byte = next as u8;
            carry = next >> 8;
        }
        if carry > 0 {
            value.insert(0, carry as u8);
        }
    }
    let hex = hex::encode(value);
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() { "0" } else { trimmed }.to_string()
}

/// SHA-256 of the public key of each Google attestation root, as
/// <https://android.googleapis.com/attestation/root> lists them: the RSA
/// root (`serialNumber=f92009e853b6b045`, whose earlier self-signed
/// certificates carry the same key) and the `Key Attestation CA1` P-384
/// root that signs from 2026-02-01.
const GOOGLE_ROOTS: [&str; 2] = [
    "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
];

/// GrapheneOS verified boot keys, per device, as GrapheneOS publishes them
/// in its attestation compatibility guide. A device booting GrapheneOS
/// reports its boot state as self-signed, which is accepted only with one of
/// these.
const GRAPHENEOS_BOOT_KEYS: [&str; 21] = [
    "f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8", // Pixel 6
    "439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c", // Pixel 6 Pro
    "08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031", // Pixel 6a
    "3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1", // Pixel 7
    "bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f", // Pixel 7 Pro
    "508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4", // Pixel 7a
    "ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842", // Pixel Fold
    "94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230", // Pixel Tablet
    "cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233", // Pixel 8
    "896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c", // Pixel 8 Pro
    "096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e", // Pixel 8a
    "9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de", // Pixel 9
    "f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86", // Pixel 9 Pro
    "55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023", // Pixel 9 Pro XL
    "af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c", // Pixel 9 Pro Fold
    "0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b", // Pixel 9a
    "3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7", // Pixel 10
    "4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093", // Pixel 10 Pro
    "141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74", // Pixel 10 Pro XL
    "55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3", // Pixel 10 Pro Fold
    "d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80", // Pixel 10a
];

/// The fewest certificates a hardware chain has: leaf, intermediate, root.
const MIN_CHAIN_CERTS: usize = 3;

/// The oldest attestation format judged: Keymaster 4.0.
const MIN_ATTESTATION_VERSION: u64 = 3;

const KEY_DESCRIPTION: Oid = Oid::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
const SERIAL_NUMBER_ATTR: Oid = Oid::new_unwrap("2.5.4.5");
const RSA_KEY: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
const EC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
const P256_CURVE: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
const P384_CURVE: Oid = Oid::new_unwrap("1.3.132.0.34");
const RSA_SHA256: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: Oid = Oid::new_unwrap("1.2.840.113549.1.1.12");
const ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");

// KeyMint values (hardware/interfaces/security/keymint/aidl).
const SECURITY_TEE: u64 = 1;
const SECURITY_STRONGBOX: u64 = 2;
const PURPOSE_SIGN: u64 = 2;
const PURPOSE_VERIFY: u64 = 3;
const ALGORITHM_EC: u64 = 3;
const CURVE_P256: u64 = 1;
const ORIGIN_GENERATED: u64 = 0;
const AUTH_PASSWORD: u64 = 1;
const AUTH_FINGERPRINT: u64 = 2;
const BOOT_VERIFIED: u64 = 0;
const BOOT_SELF_SIGNED: u64 = 1;

// AuthorizationList tags.
const TAG_PURPOSE: u32 = 1;
const TAG_ALGORITHM: u32 = 2;
const TAG_EC_CURVE: u32 = 10;
const TAG_NO_AUTH_REQUIRED: u32 = 503;
const TAG_USER_AUTH_TYPE: u32 = 504;
const TAG_AUTH_TIMEOUT: u32 = 505;
const TAG_ORIGIN: u32 = 702;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_APPLICATION_ID: u32 = 709;

/// What an accepted attestation says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The serial number of every certificate but the root, lowercase hex
    /// without leading zeros, as Google's status list names them.
    pub serials: Vec<String>,
    /// Whether the key lives in StrongBox rather than the TEE.
    pub strongbox: bool,
    /// Whether the device boots GrapheneOS rather than its maker's OS.
    pub grapheneos: bool,
}

/// Judge `chain` (DER, leaf first) as the attestation of `approver` (33
/// bytes, compressed P-256) made with `challenge`, at `now` (Unix seconds).
pub(crate) fn verify(
    chain: &[Vec<u8>],
    challenge: &[u8; 32],
    approver: &[u8; 33],
    now: u64,
) -> Result<Attested, String> {
    verify_with(chain, &trusted_roots(), challenge, approver, now)
}

/// SHA-256 of the public key of the fixed test root that test builds, and
/// end to end builds made with `--cfg keep_e2e_roots`, also trust, so a
/// stand-in phone can pair. A release never does.
#[cfg(any(test, keep_e2e_roots))]
const TEST_ROOT: &str = "154771a464a03f6cdf496bb877d55fb3425faa9986d8bdba1e7402bfcf276094";

fn trusted_roots() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut roots = GOOGLE_ROOTS.to_vec();
    #[cfg(any(test, keep_e2e_roots))]
    roots.push(TEST_ROOT);
    roots
}

fn verify_with(
    chain: &[Vec<u8>],
    roots: &[&str],
    challenge: &[u8; 32],
    approver: &[u8; 33],
    now: u64,
) -> Result<Attested, String> {
    let verified = verify_chain(chain, roots, now)?;
    let record = KeyDescription::parse(&verified.record)?;
    let grapheneos = judge(&record, challenge)?;
    let leaf = uncompressed_p256(&verified.leaf_key)?;
    let paired = p256::PublicKey::from_sec1_bytes(approver)
        .map_err(|_| "the approver key is not a P-256 point".to_string())?;
    if leaf != paired.to_encoded_point(false).as_bytes() {
        return Err("the attested key is not the approver key".into());
    }
    Ok(Attested {
        serials: verified.serials,
        strongbox: record.attestation_level == SECURITY_STRONGBOX,
        grapheneos,
    })
}

/// A chain that ends in a pinned root, with each link checked.
struct Verified {
    serials: Vec<String>,
    /// The leaf's attestation record, DER.
    record: Vec<u8>,
    /// The leaf's SubjectPublicKeyInfo, DER.
    leaf_key: Vec<u8>,
}

fn verify_chain(chain: &[Vec<u8>], roots: &[&str], now: u64) -> Result<Verified, String> {
    if chain.len() < MIN_CHAIN_CERTS || chain.len() > keep_approval::pairing::MAX_CHAIN_CERTS {
        return Err(format!(
            "an attestation chain holds {MIN_CHAIN_CERTS} to {} certificates",
            keep_approval::pairing::MAX_CHAIN_CERTS
        ));
    }
    let certs = chain
        .iter()
        .map(|der| {
            Certificate::from_der(der)
                .map_err(|_| "an attestation certificate does not parse".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let root = certs.last().expect("the chain is not empty");
    let root_key = spki_der(root)?;
    if !roots.contains(&hex::encode(keep_approval::sha256(&root_key)).as_str()) {
        return Err("the attestation chain does not end in a Google attestation root".into());
    }
    let last = certs.len() - 1;
    check_signature(&chain[last], root, root)?;
    for i in 0..last {
        if certs[i].tbs_certificate().issuer() != certs[i + 1].tbs_certificate().subject() {
            return Err("an attestation certificate names another issuer".into());
        }
        check_signature(&chain[i], &certs[i], &certs[i + 1])?;
    }
    for cert in &certs[1..] {
        if has_record(cert) {
            return Err("an attestation record outside the leaf".into());
        }
    }
    // The certificate nearest the root says how the chain was provisioned:
    // a factory chain's carries the device's serial number.
    let factory = certs[last - 1]
        .tbs_certificate()
        .subject()
        .iter()
        .any(|attr| attr.oid == SERIAL_NUMBER_ATTR);
    for cert in &certs[1..last] {
        let validity = cert.tbs_certificate().validity();
        if now < validity.not_before.to_unix_duration().as_secs() {
            return Err("an attestation certificate is not valid yet".into());
        }
        if now > validity.not_after.to_unix_duration().as_secs() && !factory {
            return Err("an attestation certificate has expired".into());
        }
    }
    let record = certs[0]
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .find(|e| e.extn_id == KEY_DESCRIPTION)
        .ok_or("the leaf carries no attestation record")?
        .extn_value
        .as_bytes()
        .to_vec();
    let serials = certs[..last]
        .iter()
        .map(|c| serial_hex(c.tbs_certificate().serial_number().as_bytes()))
        .collect();
    Ok(Verified {
        serials,
        record,
        leaf_key: spki_der(&certs[0])?,
    })
}

fn has_record(cert: &Certificate) -> bool {
    cert.tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .any(|e| e.extn_id == KEY_DESCRIPTION)
}

fn spki_der(cert: &Certificate) -> Result<Vec<u8>, String> {
    use x509_cert::der::Encode;
    cert.tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| "an attestation key does not encode".to_string())
}

/// A serial number as Google's status list writes it.
fn serial_hex(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    }
}

enum KeyType {
    Rsa,
    P256,
    P384,
}

fn key_type(cert: &Certificate) -> Result<KeyType, String> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid == RSA_KEY {
        return Ok(KeyType::Rsa);
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<Oid>().ok());
    match (spki.algorithm.oid == EC_KEY, curve) {
        (true, Some(c)) if c == P256_CURVE => Ok(KeyType::P256),
        (true, Some(c)) if c == P384_CURVE => Ok(KeyType::P384),
        _ => Err("an attestation certificate has a key of an unknown type".into()),
    }
}

/// Check that `issuer`'s key signed `cert`, whose encoding is `der`.
fn check_signature(der: &[u8], cert: &Certificate, issuer: &Certificate) -> Result<(), String> {
    let bad = || "an attestation certificate's signature does not verify".to_string();
    let alg = cert.signature_algorithm();
    if cert.tbs_certificate().signature() != alg {
        return Err(bad());
    }
    let verifier: &dyn VerificationAlgorithm = match (alg.oid, key_type(issuer)?) {
        (o, KeyType::Rsa) if o == RSA_SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        (o, KeyType::Rsa) if o == RSA_SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        (o, KeyType::P256) if o == ECDSA_SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
        (o, KeyType::P256) if o == ECDSA_SHA384 => &signature::ECDSA_P256_SHA384_ASN1,
        (o, KeyType::P384) if o == ECDSA_SHA256 => &signature::ECDSA_P384_SHA256_ASN1,
        (o, KeyType::P384) if o == ECDSA_SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
        _ => return Err("an attestation certificate is signed with an unknown algorithm".into()),
    };
    let key = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or_else(bad)?;
    let sig = cert.signature().as_bytes().ok_or_else(bad)?;
    UnparsedPublicKey::new(verifier, key)
        .verify(signed_part(der)?, sig)
        .map_err(|_| bad())
}

/// The signed part of a certificate, exactly as it was sent.
fn signed_part(der: &[u8]) -> Result<&[u8], String> {
    let mut outer = Der::new(der);
    let cert = outer.expect(UNIVERSAL, true, 16)?;
    outer.finish()?;
    Der::new(cert).read().map(|t| t.whole)
}

/// The uncompressed point of a P-256 SubjectPublicKeyInfo.
fn uncompressed_p256(spki: &[u8]) -> Result<Vec<u8>, String> {
    use p256::pkcs8::DecodePublicKey;
    let key = p256::PublicKey::from_public_key_der(spki)
        .map_err(|_| "the attested key is not a P-256 key".to_string())?;
    Ok(key.to_encoded_point(false).as_bytes().to_vec())
}

/// The attestation record's fields the gateway reads.
#[derive(Debug, Default)]
struct KeyDescription {
    attestation_version: u64,
    attestation_level: u64,
    keymint_level: u64,
    challenge: Vec<u8>,
    software: AuthList,
    hardware: AuthList,
}

#[derive(Debug, Default)]
struct AuthList {
    purpose: Option<Vec<u64>>,
    algorithm: Option<u64>,
    ec_curve: Option<u64>,
    no_auth_required: bool,
    user_auth_type: Option<u64>,
    auth_timeout: Option<u64>,
    origin: Option<u64>,
    root_of_trust: Option<RootOfTrust>,
    application_id: Option<Vec<u8>>,
}

#[derive(Debug)]
struct RootOfTrust {
    boot_key: Vec<u8>,
    locked: bool,
    state: u64,
}

impl KeyDescription {
    fn parse(der: &[u8]) -> Result<Self, String> {
        let mut outer = Der::new(der);
        let mut d = Der::new(outer.expect(UNIVERSAL, true, 16)?);
        outer.finish()?;
        let record = KeyDescription {
            attestation_version: d.integer()?,
            attestation_level: d.enumerated()?,
            keymint_level: {
                d.integer()?;
                d.enumerated()?
            },
            challenge: d.octets()?.to_vec(),
            software: {
                d.octets()?;
                AuthList::parse(d.expect(UNIVERSAL, true, 16)?)?
            },
            hardware: AuthList::parse(d.expect(UNIVERSAL, true, 16)?)?,
        };
        // Later versions may add fields after these; the record is signed
        // by the secure hardware, so they are left unread.
        Ok(record)
    }
}

impl AuthList {
    fn parse(der: &[u8]) -> Result<Self, String> {
        let mut list = AuthList::default();
        let mut d = Der::new(der);
        let mut last = None;
        while !d.is_empty() {
            let field = d.read()?;
            if field.class != CONTEXT || !field.constructed {
                return Err("an authorization list holds an untagged field".into());
            }
            if last.is_some_and(|l| field.number <= l) {
                return Err("an authorization list is out of order".into());
            }
            last = Some(field.number);
            let mut v = Der::new(field.value);
            match field.number {
                TAG_PURPOSE => {
                    let mut set = Der::new(v.expect(UNIVERSAL, true, 17)?);
                    let mut purposes = Vec::new();
                    while !set.is_empty() {
                        purposes.push(set.integer()?);
                    }
                    list.purpose = Some(purposes);
                }
                TAG_ALGORITHM => list.algorithm = Some(v.integer()?),
                TAG_EC_CURVE => list.ec_curve = Some(v.integer()?),
                TAG_NO_AUTH_REQUIRED => {
                    v.expect(UNIVERSAL, false, 5)?;
                    list.no_auth_required = true;
                }
                TAG_USER_AUTH_TYPE => list.user_auth_type = Some(v.integer()?),
                TAG_AUTH_TIMEOUT => list.auth_timeout = Some(v.integer()?),
                TAG_ORIGIN => list.origin = Some(v.integer()?),
                TAG_ROOT_OF_TRUST => {
                    let mut r = Der::new(v.expect(UNIVERSAL, true, 16)?);
                    list.root_of_trust = Some(RootOfTrust {
                        boot_key: r.octets()?.to_vec(),
                        locked: r.boolean()?,
                        state: r.enumerated()?,
                    });
                }
                TAG_APPLICATION_ID => list.application_id = Some(v.octets()?.to_vec()),
                _ => continue,
            }
            v.finish()?;
        }
        Ok(list)
    }
}

/// Judge the record; returns whether the device boots GrapheneOS.
fn judge(record: &KeyDescription, challenge: &[u8; 32]) -> Result<bool, String> {
    if record.attestation_version < MIN_ATTESTATION_VERSION {
        return Err("the attestation format is older than Keymaster 4".into());
    }
    if !matches!(record.attestation_level, SECURITY_TEE | SECURITY_STRONGBOX)
        || record.keymint_level != record.attestation_level
    {
        return Err("the approver key is not kept in secure hardware".into());
    }
    if record.challenge != challenge {
        return Err("the attestation was made for another pairing".into());
    }
    let hw = &record.hardware;
    let purposes = hw.purpose.as_deref().unwrap_or_default();
    if !purposes.contains(&PURPOSE_SIGN)
        || purposes
            .iter()
            .any(|p| !matches!(*p, PURPOSE_SIGN | PURPOSE_VERIFY))
    {
        return Err("the approver key is not only a signing key".into());
    }
    if hw.algorithm != Some(ALGORITHM_EC) || hw.ec_curve != Some(CURVE_P256) {
        return Err("the approver key is not a P-256 key".into());
    }
    if hw.origin != Some(ORIGIN_GENERATED) {
        return Err("the approver key was not generated in secure hardware".into());
    }
    let biometric_only = hw
        .user_auth_type
        .is_some_and(|t| t & AUTH_FINGERPRINT != 0 && t & AUTH_PASSWORD == 0);
    if hw.no_auth_required
        || record.software.no_auth_required
        || !biometric_only
        || hw.auth_timeout.is_some()
        || record.software.auth_timeout.is_some()
    {
        return Err("the approver key does not need a biometric for every use".into());
    }
    let root = hw
        .root_of_trust
        .as_ref()
        .ok_or("the attestation names no root of trust")?;
    if !root.locked {
        return Err("the phone's bootloader is unlocked".into());
    }
    let grapheneos = match root.state {
        BOOT_VERIFIED => false,
        BOOT_SELF_SIGNED
            if GRAPHENEOS_BOOT_KEYS.contains(&hex::encode(&root.boot_key).as_str()) =>
        {
            true
        }
        _ => return Err("the phone does not boot a verified OS".into()),
    };
    check_application(
        record
            .software
            .application_id
            .as_deref()
            .ok_or("the attestation names no app")?,
    )?;
    Ok(grapheneos)
}

/// The record's app must be the Keep app alone, signed with its release key.
fn check_application(der: &[u8]) -> Result<(), String> {
    let wrong = || "the approver key was not made by the Keep app".to_string();
    let mut outer = Der::new(der);
    let mut id = Der::new(outer.expect(UNIVERSAL, true, 16)?);
    outer.finish()?;
    let mut packages = Der::new(id.expect(UNIVERSAL, true, 17)?);
    let mut package = Der::new(packages.expect(UNIVERSAL, true, 16)?);
    let name = package.octets()?;
    package.integer()?;
    package.finish()?;
    if !packages.is_empty() || name != APP_PACKAGE.as_bytes() {
        return Err(wrong());
    }
    let mut digests = Der::new(id.expect(UNIVERSAL, true, 17)?);
    let digest = digests.octets()?;
    if !digests.is_empty() || hex::encode(digest) != APP_SIGNER {
        return Err(wrong());
    }
    Ok(())
}

const UNIVERSAL: u8 = 0;
const CONTEXT: u8 = 2;

/// One DER element.
struct Tlv<'a> {
    class: u8,
    constructed: bool,
    number: u32,
    value: &'a [u8],
    /// The element with its tag and length.
    whole: &'a [u8],
}

/// A strict reader of DER: minimal lengths and tag numbers, definite
/// lengths only.
struct Der<'a> {
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn finish(&self) -> Result<(), String> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(malformed())
        }
    }

    fn byte(&mut self) -> Result<u8, String> {
        let (&b, rest) = self.rest.split_first().ok_or_else(malformed)?;
        self.rest = rest;
        Ok(b)
    }

    fn read(&mut self) -> Result<Tlv<'a>, String> {
        let start = self.rest;
        let first = self.byte()?;
        let mut number = u32::from(first & 0x1f);
        if number == 0x1f {
            number = 0;
            for i in 0.. {
                let b = self.byte()?;
                if i == 0 && b == 0x80 || i == 4 {
                    return Err(malformed());
                }
                number = number << 7 | u32::from(b & 0x7f);
                if b & 0x80 == 0 {
                    break;
                }
            }
            if number < 0x1f {
                return Err(malformed());
            }
        }
        let len = match self.byte()? {
            l @ 0..=0x7f => usize::from(l),
            0x81 => match self.byte()? {
                l @ 0x80.. => usize::from(l),
                _ => return Err(malformed()),
            },
            0x82 => match usize::from(self.byte()?) << 8 | usize::from(self.byte()?) {
                l @ 0x100.. => l,
                _ => return Err(malformed()),
            },
            _ => return Err(malformed()),
        };
        if self.rest.len() < len {
            return Err(malformed());
        }
        let (value, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(Tlv {
            class: first >> 6,
            constructed: first & 0x20 != 0,
            number,
            value,
            whole: &start[..start.len() - rest.len()],
        })
    }

    fn expect(&mut self, class: u8, constructed: bool, number: u32) -> Result<&'a [u8], String> {
        let t = self.read()?;
        if t.class != class || t.constructed != constructed || t.number != number {
            return Err(malformed());
        }
        Ok(t.value)
    }

    fn octets(&mut self) -> Result<&'a [u8], String> {
        self.expect(UNIVERSAL, false, 4)
    }

    fn boolean(&mut self) -> Result<bool, String> {
        match self.expect(UNIVERSAL, false, 1)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(malformed()),
        }
    }

    fn integer(&mut self) -> Result<u64, String> {
        unsigned(self.expect(UNIVERSAL, false, 2)?)
    }

    fn enumerated(&mut self) -> Result<u64, String> {
        unsigned(self.expect(UNIVERSAL, false, 10)?)
    }
}

/// A non-negative DER integer that fits in 64 bits.
fn unsigned(bytes: &[u8]) -> Result<u64, String> {
    let digits = match bytes {
        [] => return Err(malformed()),
        [b, ..] if *b & 0x80 != 0 => return Err(malformed()),
        [0, next, ..] if *next & 0x80 == 0 => return Err(malformed()),
        [0, rest @ ..] => rest,
        all => all,
    };
    if digits.len() > 8 {
        return Err(malformed());
    }
    Ok(digits.iter().fold(0, |n, b| n << 8 | u64::from(*b)))
}

fn malformed() -> String {
    "the attestation record is malformed".into()
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod tests;
