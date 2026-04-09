// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use bitcoin::bip32::{ChainCode, DerivationPath, Xpriv};
use bitcoin::Network;
use zeroize::Zeroizing;

use crate::error::{KeepError, Result};

/// Derive a Nostr private key from a BIP-39 mnemonic using the NIP-06 derivation path.
pub fn derive_nostr_key(
    mnemonic: &str,
    passphrase: &str,
    account: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    if account > 0x7FFF_FFFF {
        return Err(KeepError::InvalidInput(format!(
            "account index {account} exceeds maximum hardened child index (2^31 - 1)"
        )));
    }

    let parsed: bip39::Mnemonic = mnemonic
        .parse()
        .map_err(|e: bip39::Error| KeepError::InvalidMnemonic(e.to_string()))?;

    let seed = Zeroizing::new(parsed.to_seed(passphrase));

    let mut master = Xpriv::new_master(Network::Bitcoin, &*seed)
        .map_err(|e| KeepError::InvalidMnemonic(format!("master key derivation failed: {e}")))?;

    let path: DerivationPath =
        format!("m/44'/1237'/{account}'/0/0")
            .parse()
            .map_err(|e: bitcoin::bip32::Error| {
                KeepError::InvalidMnemonic(format!("invalid derivation path: {e}"))
            })?;

    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    let mut derived = master
        .derive_priv(&secp, &path)
        .map_err(|e| KeepError::InvalidMnemonic(format!("key derivation failed: {e}")))?;

    let result = Zeroizing::new(derived.private_key.secret_bytes());

    erase_xpriv(&mut master);
    erase_xpriv(&mut derived);

    Ok(result)
}

fn erase_xpriv(key: &mut Xpriv) {
    key.private_key.non_secure_erase();
    key.chain_code = ChainCode::from([0u8; 32]);
    std::hint::black_box(key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nip06_test_vector_1() {
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let key = derive_nostr_key(mnemonic, "", 0).unwrap();
        let expected =
            hex::decode("7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a")
                .unwrap();
        assert_eq!(&key[..], &expected[..]);

        let signing_key = k256::SecretKey::from_slice(&*key).unwrap();
        let pubkey = signing_key.public_key();
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let point = pubkey.to_encoded_point(true);
        let pubkey_bytes = &point.as_bytes()[1..];
        assert_eq!(
            hex::encode(pubkey_bytes),
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
        );
    }

    #[test]
    fn nip06_test_vector_2() {
        let mnemonic = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";
        let key = derive_nostr_key(mnemonic, "", 0).unwrap();
        let expected =
            hex::decode("c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add")
                .unwrap();
        assert_eq!(&key[..], &expected[..]);

        let signing_key = k256::SecretKey::from_slice(&*key).unwrap();
        let pubkey = signing_key.public_key();
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let point = pubkey.to_encoded_point(true);
        let pubkey_bytes = &point.as_bytes()[1..];
        assert_eq!(
            hex::encode(pubkey_bytes),
            "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573"
        );
    }

    #[test]
    fn reject_invalid_mnemonic() {
        assert!(derive_nostr_key("not a valid mnemonic", "", 0).is_err());
    }

    #[test]
    fn derive_nonzero_account() {
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let key = derive_nostr_key(mnemonic, "", 1).unwrap();
        assert_eq!(key.len(), 32);
        let key0 = derive_nostr_key(mnemonic, "", 0).unwrap();
        assert_ne!(&key[..], &key0[..]);
    }

    #[test]
    fn derive_max_valid_account() {
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        assert!(derive_nostr_key(mnemonic, "", 0x7FFF_FFFF).is_ok());
    }

    #[test]
    fn reject_account_exceeding_hardened_limit() {
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        assert!(derive_nostr_key(mnemonic, "", 0x8000_0000).is_err());
    }
}
