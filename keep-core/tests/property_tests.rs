#![forbid(unsafe_code)]

use keep_core::{
    crypto::{
        self, decrypt, derive_key, derive_subkey, encrypt, Argon2Params, EncryptedData, SecretKey,
    },
    hidden::header::{HiddenHeader, OuterHeader, HEADER_SIZE},
    keys::{bytes_to_npub, npub_to_bytes, NostrKeypair},
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    #[ignore]
    fn encrypt_decrypt_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..4096)) {
        let key = SecretKey::generate().unwrap();
        let encrypted = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        let decrypted_bytes = decrypted.as_slice().unwrap();
        prop_assert_eq!(&plaintext[..], &decrypted_bytes[..]);
    }

    #[test]
    #[ignore]
    fn key_derivation_deterministic(
        password in prop::collection::vec(any::<u8>(), 1..128),
        salt in prop::array::uniform32(any::<u8>())
    ) {
        let key1 = derive_key(&password, &salt, Argon2Params::TESTING).unwrap();
        let key2 = derive_key(&password, &salt, Argon2Params::TESTING).unwrap();
        prop_assert_eq!(&*key1.decrypt().unwrap(), &*key2.decrypt().unwrap());
    }

    #[test]
    #[ignore]
    fn different_salts_produce_different_keys(
        password in prop::collection::vec(any::<u8>(), 1..64),
        salt1 in prop::array::uniform32(any::<u8>()),
        salt2 in prop::array::uniform32(any::<u8>())
    ) {
        prop_assume!(salt1 != salt2);
        let key1 = derive_key(&password, &salt1, Argon2Params::TESTING).unwrap();
        let key2 = derive_key(&password, &salt2, Argon2Params::TESTING).unwrap();
        prop_assert_ne!(&*key1.decrypt().unwrap(), &*key2.decrypt().unwrap());
    }

    #[test]
    #[ignore]
    fn subkey_derivation_deterministic(context in prop::collection::vec(any::<u8>(), 1..64)) {
        let master = SecretKey::generate().unwrap();
        let subkey1 = derive_subkey(&master, &context).unwrap();
        let subkey2 = derive_subkey(&master, &context).unwrap();
        prop_assert_eq!(&*subkey1.decrypt().unwrap(), &*subkey2.decrypt().unwrap());
    }

    #[test]
    #[ignore]
    fn different_contexts_produce_different_subkeys(
        ctx1 in prop::collection::vec(any::<u8>(), 1..32),
        ctx2 in prop::collection::vec(any::<u8>(), 1..32)
    ) {
        prop_assume!(ctx1 != ctx2);
        let master = SecretKey::generate().unwrap();
        let subkey1 = derive_subkey(&master, &ctx1).unwrap();
        let subkey2 = derive_subkey(&master, &ctx2).unwrap();
        prop_assert_ne!(&*subkey1.decrypt().unwrap(), &*subkey2.decrypt().unwrap());
    }

    #[test]
    #[ignore]
    fn sign_produces_valid_signature(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let kp = NostrKeypair::generate().unwrap();
        let sig = kp.sign(&message).unwrap();
        prop_assert_eq!(sig.len(), 64);
    }

    #[test]
    #[ignore]
    fn nsec_roundtrip(_ in Just(())) {
        let kp = NostrKeypair::generate().unwrap();
        let nsec = kp.to_nsec();
        let restored = NostrKeypair::from_nsec(&nsec).unwrap();
        prop_assert_eq!(kp.secret_bytes(), restored.secret_bytes());
        prop_assert_eq!(kp.public_bytes(), restored.public_bytes());
    }

    #[test]
    #[ignore]
    fn npub_roundtrip(pubkey in prop::array::uniform32(1u8..)) {
        let npub = bytes_to_npub(&pubkey);
        let restored = npub_to_bytes(&npub).unwrap();
        prop_assert_eq!(pubkey, restored);
    }

    #[test]
    #[ignore]
    fn outer_header_roundtrip(
        outer_size in 0u64..1_000_000,
        total_size in 0u64..10_000_000
    ) {
        let header = OuterHeader::new(Argon2Params::TESTING, outer_size, total_size);
        let bytes = header.to_bytes();
        prop_assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = OuterHeader::from_bytes(&bytes).unwrap();
        prop_assert_eq!(parsed.outer_data_size, outer_size);
        prop_assert_eq!(parsed.total_size, total_size);
        prop_assert_eq!(parsed.salt, header.salt);
    }

    #[test]
    #[ignore]
    fn hidden_header_roundtrip(
        offset in 1024u64..1_000_000,
        size in 0u64..1_000_000
    ) {
        let header = HiddenHeader::new(offset, size);
        prop_assert!(header.verify_checksum());
        let bytes = header.to_bytes();
        prop_assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = HiddenHeader::from_bytes(&bytes).unwrap();
        prop_assert!(parsed.verify_checksum());
        prop_assert_eq!(parsed.hidden_data_offset, offset);
        prop_assert_eq!(parsed.hidden_data_size, size);
    }

    #[test]
    #[ignore]
    fn encrypted_data_roundtrip(
        ciphertext in prop::collection::vec(any::<u8>(), 16..256),
        nonce in prop::array::uniform24(any::<u8>())
    ) {
        let data = EncryptedData { ciphertext: ciphertext.clone(), nonce };
        let bytes = data.to_bytes();
        let restored = EncryptedData::from_bytes(&bytes).unwrap();
        prop_assert_eq!(restored.ciphertext, ciphertext);
        prop_assert_eq!(restored.nonce, nonce);
    }

    #[test]
    #[ignore]
    fn blake2b_deterministic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let hash1 = crypto::blake2b_256(&data);
        let hash2 = crypto::blake2b_256(&data);
        prop_assert_eq!(hash1, hash2);
    }

    #[test]
    #[ignore]
    fn wrong_key_fails_decrypt(plaintext in prop::collection::vec(any::<u8>(), 1..256)) {
        let key1 = SecretKey::generate().unwrap();
        let key2 = SecretKey::generate().unwrap();
        let encrypted = encrypt(&plaintext, &key1).unwrap();
        let result = decrypt(&encrypted, &key2);
        prop_assert!(result.is_err());
    }
}

#[test]
fn header_boundary_sizes() {
    let header = OuterHeader::new(Argon2Params::TESTING, 0, 0);
    let bytes = header.to_bytes();
    let parsed = OuterHeader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.outer_data_size, 0);
    assert_eq!(parsed.total_size, 0);

    let header = OuterHeader::new(Argon2Params::TESTING, u64::MAX, u64::MAX);
    let bytes = header.to_bytes();
    let parsed = OuterHeader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.outer_data_size, u64::MAX);
    assert_eq!(parsed.total_size, u64::MAX);
}

mod frost_tests {
    use keep_core::frost::{sign_with_local_shares, ShareExport, ThresholdConfig, TrustedDealer};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        #[ignore]
        fn frost_threshold_sign_succeeds(message in prop::collection::vec(any::<u8>(), 1..256)) {
            let config = ThresholdConfig::two_of_three();
            let dealer = TrustedDealer::new(config);
            let (shares, _) = dealer.generate("test").unwrap();

            let sig = sign_with_local_shares(&shares[..2], &message).unwrap();
            prop_assert_eq!(sig.len(), 64);
        }

        #[test]
        #[ignore]
        fn frost_all_shares_sign_succeeds(message in prop::collection::vec(any::<u8>(), 1..256)) {
            let config = ThresholdConfig::two_of_three();
            let dealer = TrustedDealer::new(config);
            let (shares, _) = dealer.generate("test").unwrap();

            let sig = sign_with_local_shares(&shares, &message).unwrap();
            prop_assert_eq!(sig.len(), 64);
        }

        #[test]
        #[ignore]
        fn frost_below_threshold_fails(message in prop::collection::vec(any::<u8>(), 1..64)) {
            let config = ThresholdConfig::two_of_three();
            let dealer = TrustedDealer::new(config);
            let (shares, _) = dealer.generate("test").unwrap();

            let result = sign_with_local_shares(&shares[..1], &message);
            prop_assert!(result.is_err());
        }

        #[test]
        #[ignore]
        fn frost_share_export_roundtrip(password in "[a-zA-Z0-9]{8,32}") {
            let config = ThresholdConfig::two_of_three();
            let dealer = TrustedDealer::new(config);
            let (shares, _) = dealer.generate("test").unwrap();

            let export = ShareExport::from_share(&shares[0], &password).unwrap();
            let json = export.to_json().unwrap();
            let reimported = ShareExport::from_json(&json).unwrap();
            let restored = reimported.to_share(&password, "imported").unwrap();

            prop_assert_eq!(restored.metadata.threshold, shares[0].metadata.threshold);
            prop_assert_eq!(restored.metadata.identifier, shares[0].metadata.identifier);
            prop_assert_eq!(restored.group_pubkey(), shares[0].group_pubkey());
        }

        #[test]
        #[ignore]
        fn frost_wrong_password_fails(
            correct_pw in "[a-zA-Z0-9]{8,16}",
            wrong_pw in "[a-zA-Z0-9]{8,16}"
        ) {
            prop_assume!(correct_pw != wrong_pw);
            let config = ThresholdConfig::two_of_three();
            let dealer = TrustedDealer::new(config);
            let (shares, _) = dealer.generate("test").unwrap();

            let export = ShareExport::from_share(&shares[0], &correct_pw).unwrap();
            let result = export.to_share(&wrong_pw, "imported");
            prop_assert!(result.is_err());
        }

        #[test]
        #[ignore]
        fn frost_bech32_roundtrip(password in "[a-zA-Z0-9]{8,16}") {
            let config = ThresholdConfig::two_of_three();
            let dealer = TrustedDealer::new(config);
            let (shares, _) = dealer.generate("test").unwrap();

            let export = ShareExport::from_share(&shares[0], &password).unwrap();
            let encoded = export.to_bech32().unwrap();
            prop_assert!(encoded.starts_with("kshare"));

            let decoded = ShareExport::from_bech32(&encoded).unwrap();
            prop_assert_eq!(decoded.identifier, export.identifier);
            prop_assert_eq!(decoded.threshold, export.threshold);
        }
    }

    #[test]
    fn frost_three_of_five_threshold() {
        let config = ThresholdConfig::three_of_five();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        assert_eq!(shares.len(), 5);
        let sig = sign_with_local_shares(&shares[..3], b"message").unwrap();
        assert_eq!(sig.len(), 64);

        let result = sign_with_local_shares(&shares[..2], b"message");
        assert!(result.is_err());
    }

    #[test]
    fn frost_invalid_threshold_config() {
        assert!(ThresholdConfig::new(1, 3).is_err());
        assert!(ThresholdConfig::new(3, 2).is_err());
        assert!(ThresholdConfig::new(2, 256).is_err());
        assert!(ThresholdConfig::new(0, 0).is_err());
    }

    #[test]
    fn frost_animated_frames_roundtrip() {
        let config = ThresholdConfig::two_of_three();
        let dealer = TrustedDealer::new(config);
        let (shares, _) = dealer.generate("test").unwrap();

        let export = ShareExport::from_share(&shares[0], "password").unwrap();
        let frames = export.to_animated_frames(100).unwrap();
        assert!(frames.len() > 1);

        let reconstructed = ShareExport::from_animated_frames(&frames).unwrap();
        assert_eq!(reconstructed.identifier, export.identifier);
        assert_eq!(reconstructed.threshold, export.threshold);
    }
}
