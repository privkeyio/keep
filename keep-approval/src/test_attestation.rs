// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Android Key Attestation chains for tests and stand-in phones, under a
//! fixed test root that only test builds of the gateway trust. Nothing here
//! is built into a release.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;

use crate::pairing::{CertChain, APP_PACKAGE, APP_SIGNER};

/// The time the minted certificates are made for, Unix seconds.
pub const NOW: u64 = 1_800_000_000;

/// SHA-256 of the test root's public key.
pub fn root_key_hash() -> String {
    hex::encode(crate::sha256(&spki(&key(0xa1))))
}

/// The test root's private key, made from a fixed seed.
pub fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32].into()).expect("a valid P-256 scalar")
}

/// What a minted attestation record says. The default is what the gateway
/// takes: the Keep app's P-256 signing key, generated in a TEE, needing a
/// biometric for every use, on a locked device booting a verified OS.
#[derive(Clone, Debug)]
pub struct Record {
    pub version: u64,
    pub level: u64,
    pub keymint_level: u64,
    pub challenge: Vec<u8>,
    pub purposes: Vec<u64>,
    pub algorithm: u64,
    pub curve: u64,
    pub no_auth_required: bool,
    pub no_auth_required_in_software: bool,
    pub user_auth_type: Option<u64>,
    pub auth_timeout: Option<u64>,
    pub origin: u64,
    pub root_of_trust: bool,
    pub boot_key: Vec<u8>,
    pub locked: bool,
    pub boot_state: u64,
    pub packages: Vec<&'static str>,
    pub signers: Vec<Vec<u8>>,
}

impl Record {
    /// The record the gateway takes for `challenge`.
    pub fn new(challenge: &[u8; 32]) -> Self {
        Self {
            version: 400,
            level: 1,
            keymint_level: 1,
            challenge: challenge.to_vec(),
            purposes: vec![2],
            algorithm: 3,
            curve: 1,
            no_auth_required: false,
            no_auth_required_in_software: false,
            user_auth_type: Some(2),
            auth_timeout: None,
            origin: 0,
            root_of_trust: true,
            boot_key: vec![0x11; 32],
            locked: true,
            boot_state: 0,
            packages: vec![APP_PACKAGE],
            signers: vec![hex::decode(APP_SIGNER).expect("hex")],
        }
    }

    /// The record, DER, as the attestation extension holds it.
    pub fn der(&self) -> Vec<u8> {
        let app = seq(&[
            set(&self
                .packages
                .iter()
                .map(|p| seq(&[octets(p.as_bytes()), int(1)]))
                .collect::<Vec<_>>()),
            set(&self.signers.iter().map(|s| octets(s)).collect::<Vec<_>>()),
        ]);
        let null = || tlv(&[0x05], &[]);
        let mut software = vec![];
        if self.no_auth_required_in_software {
            software.push(tagged(503, null()));
        }
        software.push(tagged(701, int(NOW * 1000)));
        software.push(tagged(709, octets(&app)));
        let mut hardware = vec![
            tagged(
                1,
                set(&self.purposes.iter().map(|p| int(*p)).collect::<Vec<_>>()),
            ),
            tagged(2, int(self.algorithm)),
            tagged(3, int(256)),
            tagged(10, int(self.curve)),
        ];
        if self.no_auth_required {
            hardware.push(tagged(503, null()));
        }
        if let Some(t) = self.user_auth_type {
            hardware.push(tagged(504, int(t)));
        }
        if let Some(t) = self.auth_timeout {
            hardware.push(tagged(505, int(t)));
        }
        hardware.push(tagged(702, int(self.origin)));
        if self.root_of_trust {
            hardware.push(tagged(
                704,
                seq(&[
                    octets(&self.boot_key),
                    tlv(&[0x01], &[if self.locked { 0xff } else { 0x00 }]),
                    enumerated(self.boot_state),
                    octets(&[0x22; 32]),
                ]),
            ));
        }
        hardware.push(tagged(705, int(160000)));
        seq(&[
            int(self.version),
            enumerated(self.level),
            int(self.version),
            enumerated(self.keymint_level),
            octets(&self.challenge),
            octets(&[]),
            seq(&software),
            seq(&hardware),
        ])
    }
}

/// Dates for the intermediate, and whether it is named as a factory one is.
#[derive(Clone, Copy, Debug)]
pub struct Intermediate {
    pub not_before: u64,
    pub not_after: u64,
    pub factory: bool,
}

impl Default for Intermediate {
    fn default() -> Self {
        Self {
            not_before: 1_700_000_000,
            not_after: 2_000_000_000,
            factory: false,
        }
    }
}

/// The chain the gateway takes for `approver` (33 bytes, compressed P-256)
/// made with `challenge`.
pub fn chain(approver: &[u8; 33], challenge: &[u8; 32]) -> CertChain {
    mint(approver, &Record::new(challenge), Intermediate::default())
}

/// A leaf holding `approver` with `record`, under a test intermediate and
/// the test root.
pub fn mint(approver: &[u8; 33], record: &Record, intermediate: Intermediate) -> CertChain {
    let root_key = key(0xa1);
    let inter_key = key(0xa2);
    let approver = p256::PublicKey::from_sec1_bytes(approver).expect("a P-256 point");
    let root_name = name("Test Root", false);
    let inter_name = if intermediate.factory {
        name("f00d", true)
    } else {
        name("Droid CA2", false)
    };
    let root_spki = spki(&root_key);
    let root = cert(
        1,
        &root_name,
        &root_spki,
        &root_name,
        &root_key,
        (0, 2_000_000_000),
        None,
    );
    let inter = cert(
        0x2c8c,
        &inter_name,
        &spki(&inter_key),
        &root_name,
        &root_key,
        (intermediate.not_before, intermediate.not_after),
        None,
    );
    let leaf = cert(
        3,
        &name("Android Keystore Key", false),
        &point_spki(&approver),
        &inter_name,
        &inter_key,
        (0, NOW - 1),
        Some(&record.der()),
    );
    CertChain(vec![leaf, inter, root])
}

/// A certificate for the key `spki`, named `subject`, signed by
/// `issuer_key` as `issuer`, valid `dates`, holding `record` if given.
pub fn cert(
    serial: u64,
    subject: &[u8],
    spki: &[u8],
    issuer: &[u8],
    issuer_key: &SigningKey,
    dates: (u64, u64),
    record: Option<&[u8]>,
) -> Vec<u8> {
    let alg = seq(&[oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
    let mut tbs = vec![
        tagged(0, int(2)),
        int(serial),
        alg.clone(),
        issuer.to_vec(),
        seq(&[utc(dates.0), utc(dates.1)]),
        subject.to_vec(),
        spki.to_vec(),
    ];
    if let Some(r) = record {
        let attestation = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];
        tbs.push(tagged(3, seq(&[seq(&[oid(&attestation), octets(r)])])));
    }
    let tbs = seq(&tbs);
    let sig: Signature = issuer_key.sign(&tbs);
    let mut bits = vec![0];
    bits.extend_from_slice(sig.to_der().as_bytes());
    seq(&[tbs, alg, tlv(&[0x03], &bits)])
}

/// A name with one attribute: a common name, or a serial number as a
/// factory intermediate carries.
pub fn name(value: &str, serial: bool) -> Vec<u8> {
    let attr = if serial { 0x05 } else { 0x03 };
    seq(&[set(&[seq(&[
        oid(&[0x55, 0x04, attr]),
        tlv(&[0x0c], value.as_bytes()),
    ])])])
}

/// A key's SubjectPublicKeyInfo, DER.
pub fn spki(key: &SigningKey) -> Vec<u8> {
    point_spki(&p256::PublicKey::from(key.verifying_key()))
}

fn point_spki(key: &p256::PublicKey) -> Vec<u8> {
    let ec_key = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let p256_curve = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let mut bits = vec![0];
    bits.extend_from_slice(key.to_encoded_point(false).as_bytes());
    seq(&[seq(&[oid(&ec_key), oid(&p256_curve)]), tlv(&[0x03], &bits)])
}

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    match value.len() {
        l @ 0..=0x7f => out.push(l as u8),
        l @ 0x80..=0xff => out.extend([0x81, l as u8]),
        l => out.extend([0x82, (l >> 8) as u8, l as u8]),
    }
    out.extend_from_slice(value);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &parts.concat())
}

fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x31], &parts.concat())
}

fn int(n: u64) -> Vec<u8> {
    let mut bytes = n.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(&[0x02], &bytes)
}

fn enumerated(n: u64) -> Vec<u8> {
    let mut i = int(n);
    i[0] = 0x0a;
    i
}

fn octets(b: &[u8]) -> Vec<u8> {
    tlv(&[0x04], b)
}

fn oid(encoded: &[u8]) -> Vec<u8> {
    tlv(&[0x06], encoded)
}

/// An explicit context tag `[n]`.
fn tagged(n: u32, inner: Vec<u8>) -> Vec<u8> {
    let tag = if n < 31 {
        vec![0xa0 | n as u8]
    } else {
        let mut groups = vec![(n & 0x7f) as u8];
        let mut rest = n >> 7;
        while rest > 0 {
            groups.insert(0, (rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        [vec![0xbf], groups].concat()
    };
    tlv(&tag, &inner)
}

/// `secs` as an X.509 UTCTime.
fn utc(secs: u64) -> Vec<u8> {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    // Days since 1970-01-01 to a civil date (Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = format!(
        "{:02}{month:02}{day:02}{:02}{:02}{:02}Z",
        year % 100,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    tlv(&[0x17], text.as_bytes())
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_times_are_civil_dates() {
        assert_eq!(&super::utc(0)[2..], b"700101000000Z");
        assert_eq!(&super::utc(1_800_000_000)[2..], b"270115080000Z");
        assert_eq!(&super::utc(951_782_400)[2..], b"000229000000Z");
    }
}
