// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use zeroize::{Zeroize, Zeroizing};

use crate::error::{KeepError, Result};
use crate::keys::NostrKeypair;

use super::transport::ShareExport;

/// Recover a Nostr secret key from threshold FROST share exports.
///
/// Parses and decrypts each export with its corresponding passphrase,
/// validates all shares belong to the same group with no duplicates,
/// then reconstructs the secret scalar via FROST key reconstruction.
pub fn recover_nsec(
    share_data: &[impl AsRef<str>],
    passphrases: &[impl AsRef<str>],
) -> Result<Zeroizing<String>> {
    if share_data.len() != passphrases.len() {
        return Err(KeepError::InvalidInput(
            "share_data and passphrases must have the same length".into(),
        ));
    }
    if share_data.is_empty() {
        return Err(KeepError::InvalidInput("no shares provided".into()));
    }

    let mut key_packages = Vec::with_capacity(share_data.len());
    let mut group_pubkey: Option<String> = None;
    let mut seen_identifiers: Vec<u16> = Vec::new();

    let parse_result: Result<()> = (|| {
        for (data, passphrase) in share_data.iter().zip(passphrases.iter()) {
            let export = ShareExport::parse(data.as_ref())
                .map_err(|_| KeepError::Frost("Invalid share format".into()))?;

            match &group_pubkey {
                None => group_pubkey = Some(export.group_pubkey.clone()),
                Some(gp) if *gp != export.group_pubkey => {
                    return Err(KeepError::Frost(
                        "All shares must belong to the same group".into(),
                    ));
                }
                _ => {}
            }

            if seen_identifiers.contains(&export.identifier) {
                return Err(KeepError::Frost(
                    "Duplicate share \u{2014} each share must be unique".into(),
                ));
            }
            seen_identifiers.push(export.identifier);

            let share = export.to_share(passphrase.as_ref(), "recovery").map_err(|_| {
                KeepError::Frost("Failed to decrypt share (wrong passphrase?)".into())
            })?;
            key_packages.push(
                share
                    .key_package()
                    .map_err(|_| KeepError::Frost("Invalid share data".into()))?,
            );
        }
        Ok(())
    })();

    if let Err(e) = parse_result {
        key_packages.zeroize();
        return Err(e);
    }

    let reconstruct_result = frost_secp256k1_tr::keys::reconstruct(&key_packages);
    key_packages.zeroize();

    let signing_key =
        reconstruct_result.map_err(|_| KeepError::Frost("Reconstruction failed".into()))?;

    let mut secret_bytes: Vec<u8> = signing_key.serialize();
    let Ok(mut secret_arr) = <[u8; 32]>::try_from(secret_bytes.as_slice()) else {
        secret_bytes.zeroize();
        return Err(KeepError::Frost("Invalid secret key length".into()));
    };
    secret_bytes.zeroize();

    let keypair_result = NostrKeypair::from_secret_bytes(&mut secret_arr);
    secret_arr.zeroize();

    keypair_result
        .map(|kp| Zeroizing::new(kp.to_nsec()))
        .map_err(|_| KeepError::Frost("Failed to derive Nostr key".into()))
}
