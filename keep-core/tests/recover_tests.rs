// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use keep_core::frost::{recover_nsec, ShareExport, ThresholdConfig, TrustedDealer};

fn group_pubkey_from_export(bech32: &str) -> [u8; 32] {
    let export = ShareExport::parse(bech32).unwrap();
    let bytes = hex::decode(&export.group_pubkey).unwrap();
    <[u8; 32]>::try_from(bytes.as_slice()).unwrap()
}

fn export_shares(passphrase: &str) -> Vec<String> {
    let config = ThresholdConfig::two_of_three();
    let dealer = TrustedDealer::new(config);
    let (shares, _) = dealer.generate("test").unwrap();

    shares
        .iter()
        .map(|s| {
            ShareExport::from_share(s, passphrase)
                .unwrap()
                .to_bech32()
                .unwrap()
        })
        .collect()
}

#[test]
fn recover_nsec_two_of_three() {
    let passphrase = "test-passphrase";
    let exports = export_shares(passphrase);
    let passphrases = vec![passphrase; 2];

    let nsec = recover_nsec(&exports[..2], &passphrases, None).unwrap();
    assert!(nsec.starts_with("nsec1"));
}

#[test]
fn recover_nsec_all_shares() {
    let passphrase = "test-passphrase";
    let exports = export_shares(passphrase);
    let passphrases = vec![passphrase; 3];

    let nsec_all = recover_nsec(&exports, &passphrases, None).unwrap();

    let nsec_two = recover_nsec(&exports[..2], &[passphrase; 2], None).unwrap();
    assert_eq!(*nsec_all, *nsec_two);
}

#[test]
fn recover_nsec_wrong_passphrase() {
    let exports = export_shares("correct");
    let result = recover_nsec(&exports[..2], &["wrong", "wrong"], None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("decrypt"));
}

#[test]
fn recover_nsec_duplicate_shares() {
    let passphrase = "test-passphrase";
    let exports = export_shares(passphrase);
    let dupes = vec![exports[0].clone(), exports[0].clone()];

    let result = recover_nsec(&dupes, &[passphrase, passphrase], None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Duplicate"));
}

#[test]
fn recover_nsec_mismatched_groups() {
    let passphrase = "test-passphrase";
    let exports_a = export_shares(passphrase);
    let exports_b = export_shares(passphrase);

    let mixed = vec![exports_a[0].clone(), exports_b[1].clone()];
    let result = recover_nsec(&mixed, &[passphrase, passphrase], None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("same group"));
}

#[test]
fn recover_nsec_expected_pubkey_match() {
    let passphrase = "test-passphrase";
    let exports = export_shares(passphrase);
    let group_pk = group_pubkey_from_export(&exports[0]);

    let nsec = recover_nsec(&exports[..2], &[passphrase; 2], Some(&group_pk)).unwrap();
    assert!(nsec.starts_with("nsec1"));
}

#[test]
fn recover_nsec_expected_pubkey_mismatch() {
    let passphrase = "test-passphrase";
    let exports_a = export_shares(passphrase);
    let exports_b = export_shares(passphrase);
    let wrong_pk = group_pubkey_from_export(&exports_b[0]);

    let result = recover_nsec(&exports_a[..2], &[passphrase; 2], Some(&wrong_pk));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("match"));
}

#[test]
fn recover_nsec_below_threshold() {
    let passphrase = "test-passphrase";
    let exports = export_shares(passphrase);

    let result = recover_nsec(&exports[..1], &[passphrase], None);
    assert!(result.is_err());
}
