// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use keep_core::frost::{recover_nsec, ShareExport, ThresholdConfig, TrustedDealer};

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

    let nsec = recover_nsec(&exports[..2], &passphrases).unwrap();
    assert!(nsec.starts_with("nsec1"));
}

#[test]
fn recover_nsec_all_shares() {
    let passphrase = "test-passphrase";
    let exports = export_shares(passphrase);
    let passphrases = vec![passphrase; 3];

    let nsec_all = recover_nsec(&exports, &passphrases).unwrap();

    let nsec_two = recover_nsec(&exports[..2], &[passphrase; 2]).unwrap();
    assert_eq!(*nsec_all, *nsec_two);
}

#[test]
fn recover_nsec_wrong_passphrase() {
    let exports = export_shares("correct");
    let result = recover_nsec(&exports[..2], &["wrong", "wrong"]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("decrypt"));
}

#[test]
fn recover_nsec_duplicate_shares() {
    let passphrase = "test-passphrase";
    let exports = export_shares(passphrase);
    let dupes = vec![exports[0].clone(), exports[0].clone()];

    let result = recover_nsec(&dupes, &[passphrase, passphrase]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Duplicate"));
}

#[test]
fn recover_nsec_mismatched_groups() {
    let passphrase = "test-passphrase";
    let exports_a = export_shares(passphrase);
    let exports_b = export_shares(passphrase);

    let mixed = vec![exports_a[0].clone(), exports_b[1].clone()];
    let result = recover_nsec(&mixed, &[passphrase, passphrase]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("same group"));
}

#[test]
fn recover_nsec_below_threshold() {
    let passphrase = "test-passphrase";
    let exports = export_shares(passphrase);

    let result = recover_nsec(&exports[..1], &[passphrase]);
    assert!(result.is_err());
}
