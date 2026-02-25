#![forbid(unsafe_code)]

use keep_frost_net::{
    AnnouncePayload, AnnouncedXpub, CommitmentPayload, ErrorPayload, KfpMessage,
    SignRequestPayload, SignatureCompletePayload, SignatureSharePayload, XpubAnnouncePayload,
    MAX_CAPABILITIES, MAX_CAPABILITY_LENGTH, MAX_COMMITMENT_SIZE, MAX_ERROR_CODE_LENGTH,
    MAX_ERROR_MESSAGE_LENGTH, MAX_MESSAGE_SIZE, MAX_MESSAGE_TYPE_LENGTH, MAX_NAME_LENGTH,
    MAX_PARTICIPANTS, MAX_RECOVERY_XPUBS, MAX_SIGNATURE_SHARE_SIZE, MAX_XPUB_LABEL_LENGTH,
};
use proptest::prelude::*;

fn roundtrip(msg: KfpMessage) -> KfpMessage {
    let json = msg.to_json().unwrap();
    KfpMessage::from_json(&json).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn announce_roundtrip(share_index in 1u16..256, timestamp in any::<u64>()) {
        let payload = AnnouncePayload::new([1u8; 32], share_index, [2u8; 33], [3u8; 64], timestamp);
        let KfpMessage::Announce(p) = roundtrip(KfpMessage::Announce(payload)) else {
            panic!("Expected Announce");
        };
        prop_assert_eq!(p.share_index, share_index);
        prop_assert_eq!(p.timestamp, timestamp);
    }

    #[test]
    fn announce_with_name_roundtrip(name in "[a-zA-Z0-9 ]{1,64}") {
        let payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 12345).with_name(&name);
        let KfpMessage::Announce(p) = roundtrip(KfpMessage::Announce(payload)) else {
            panic!("Expected Announce");
        };
        prop_assert_eq!(p.name, Some(name));
    }

    #[test]
    fn sign_request_roundtrip(
        message in prop::collection::vec(any::<u8>(), 1..1024),
        msg_type in "[a-z_]{1,32}",
        participants in prop::collection::vec(1u16..256, 2..10)
    ) {
        let payload = SignRequestPayload::new(
            [1u8; 32], [2u8; 32], message.clone(), &msg_type, participants.clone(),
        );
        let KfpMessage::SignRequest(p) = roundtrip(KfpMessage::SignRequest(payload)) else {
            panic!("Expected SignRequest");
        };
        prop_assert_eq!(p.message, message);
        prop_assert_eq!(p.message_type, msg_type);
        prop_assert_eq!(p.participants, participants);
    }

    #[test]
    fn commitment_roundtrip(
        share_index in 1u16..256,
        commitment in prop::collection::vec(any::<u8>(), 32..64)
    ) {
        let payload = CommitmentPayload::new([1u8; 32], share_index, commitment.clone());
        let KfpMessage::Commitment(p) = roundtrip(KfpMessage::Commitment(payload)) else {
            panic!("Expected Commitment");
        };
        prop_assert_eq!(p.share_index, share_index);
        prop_assert_eq!(p.commitment, commitment);
    }

    #[test]
    fn signature_share_roundtrip(
        share_index in 1u16..256,
        sig_share in prop::collection::vec(any::<u8>(), 32..64)
    ) {
        let payload = SignatureSharePayload::new([1u8; 32], share_index, sig_share.clone());
        let KfpMessage::SignatureShare(p) = roundtrip(KfpMessage::SignatureShare(payload)) else {
            panic!("Expected SignatureShare");
        };
        prop_assert_eq!(p.share_index, share_index);
        prop_assert_eq!(p.signature_share, sig_share);
    }

    #[test]
    fn signature_complete_roundtrip(session_id in prop::array::uniform32(any::<u8>())) {
        let payload = SignatureCompletePayload::new(session_id, [5u8; 64], [6u8; 32]);
        let KfpMessage::SignatureComplete(p) = roundtrip(KfpMessage::SignatureComplete(payload)) else {
            panic!("Expected SignatureComplete");
        };
        prop_assert_eq!(p.session_id, session_id);
        prop_assert_eq!(p.signature, [5u8; 64]);
        prop_assert_eq!(p.message_hash, [6u8; 32]);
    }

    #[test]
    fn error_roundtrip(code in "[A-Z_]{4,32}", message in "[a-zA-Z0-9 .]{1,128}") {
        let payload = ErrorPayload::new(&code, &message);
        let KfpMessage::Error(p) = roundtrip(KfpMessage::Error(payload)) else {
            panic!("Expected Error");
        };
        prop_assert_eq!(p.code, code);
        prop_assert_eq!(p.message, message);
    }

    #[test]
    fn oversized_message_rejected(size in (MAX_MESSAGE_SIZE + 1)..=(MAX_MESSAGE_SIZE + 1000)) {
        let payload = SignRequestPayload::new([1u8; 32], [2u8; 32], vec![0u8; size], "raw", vec![1, 2]);
        prop_assert!(KfpMessage::SignRequest(payload).validate().is_err());
    }

    #[test]
    fn oversized_name_rejected(extra in 1usize..100) {
        let payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 12345)
            .with_name(&"a".repeat(MAX_NAME_LENGTH + extra));
        prop_assert!(KfpMessage::Announce(payload).validate().is_err());
    }

    #[test]
    fn oversized_commitment_rejected(extra in 1usize..100) {
        let payload = CommitmentPayload::new([1u8; 32], 1, vec![0u8; MAX_COMMITMENT_SIZE + extra]);
        prop_assert!(KfpMessage::Commitment(payload).validate().is_err());
    }

    #[test]
    fn oversized_signature_share_rejected(extra in 1usize..100) {
        let payload = SignatureSharePayload::new([1u8; 32], 1, vec![0u8; MAX_SIGNATURE_SHARE_SIZE + extra]);
        prop_assert!(KfpMessage::SignatureShare(payload).validate().is_err());
    }

    #[test]
    fn oversized_error_code_rejected(extra in 1usize..100) {
        let payload = ErrorPayload::new(&"E".repeat(MAX_ERROR_CODE_LENGTH + extra), "message");
        prop_assert!(KfpMessage::Error(payload).validate().is_err());
    }

    #[test]
    fn oversized_error_message_rejected(extra in 1usize..100) {
        let payload = ErrorPayload::new("CODE", &"m".repeat(MAX_ERROR_MESSAGE_LENGTH + extra));
        prop_assert!(KfpMessage::Error(payload).validate().is_err());
    }

    #[test]
    fn oversized_message_type_rejected(extra in 1usize..100) {
        let payload = SignRequestPayload::new([1u8; 32], [2u8; 32], vec![1], &"t".repeat(MAX_MESSAGE_TYPE_LENGTH + extra), vec![1]);
        prop_assert!(KfpMessage::SignRequest(payload).validate().is_err());
    }

    #[test]
    fn too_many_participants_rejected(extra in 1usize..100) {
        let participants: Vec<u16> = (0..=(MAX_PARTICIPANTS + extra) as u16).collect();
        let payload = SignRequestPayload::new([1u8; 32], [2u8; 32], vec![1], "raw", participants);
        prop_assert!(KfpMessage::SignRequest(payload).validate().is_err());
    }

    #[test]
    fn too_many_capabilities_rejected(extra in 1usize..10) {
        let caps: Vec<String> = (0..=(MAX_CAPABILITIES + extra)).map(|i| format!("cap{i}")).collect();
        let mut payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 12345);
        payload.capabilities = caps;
        prop_assert!(KfpMessage::Announce(payload).validate().is_err());
    }

    #[test]
    fn oversized_capability_rejected(extra in 1usize..50) {
        let mut payload = AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 12345);
        payload.capabilities = vec!["c".repeat(MAX_CAPABILITY_LENGTH + extra)];
        prop_assert!(KfpMessage::Announce(payload).validate().is_err());
    }

    #[test]
    fn xpub_announce_roundtrip(
        share_index in 1u16..256,
        xpub_count in 1usize..5,
        fingerprint_byte in 0u32..=0xFFFFFFFFu32,
    ) {
        let fingerprint = format!("{fingerprint_byte:08x}");
        let xpubs: Vec<AnnouncedXpub> = (0..xpub_count)
            .map(|i| AnnouncedXpub {
                xpub: format!("xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxy5eYg{i:02}"),
                fingerprint: fingerprint.clone(),
                label: None,
            })
            .collect();
        let payload = XpubAnnouncePayload::new([1u8; 32], share_index, xpubs.clone());
        let KfpMessage::XpubAnnounce(p) = roundtrip(KfpMessage::XpubAnnounce(payload)) else {
            panic!("Expected XpubAnnounce");
        };
        prop_assert_eq!(p.share_index, share_index);
        prop_assert_eq!(p.recovery_xpubs.len(), xpub_count);
        for (orig, decoded) in xpubs.iter().zip(p.recovery_xpubs.iter()) {
            prop_assert_eq!(&orig.xpub, &decoded.xpub);
            prop_assert_eq!(&orig.fingerprint, &decoded.fingerprint);
        }
    }

    #[test]
    fn xpub_announce_too_many_rejected(extra in 1usize..10) {
        let xpubs: Vec<AnnouncedXpub> = (0..MAX_RECOVERY_XPUBS + extra)
            .map(|i| AnnouncedXpub {
                xpub: format!("xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxy5eYg{i:04}"),
                fingerprint: "aabbccdd".into(),
                label: None,
            })
            .collect();
        let payload = XpubAnnouncePayload::new([1u8; 32], 1, xpubs);
        prop_assert!(KfpMessage::XpubAnnounce(payload).validate().is_err());
    }

    #[test]
    fn xpub_announce_invalid_prefix_rejected(prefix in "[a-z]{4}") {
        if prefix == "xpub" || prefix == "tpub" {
            return Ok(());
        }
        let xpubs = vec![AnnouncedXpub {
            xpub: format!("{prefix}661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK"),
            fingerprint: "aabbccdd".into(),
            label: None,
        }];
        let payload = XpubAnnouncePayload::new([1u8; 32], 1, xpubs);
        prop_assert!(KfpMessage::XpubAnnounce(payload).validate().is_err());
    }

    #[test]
    fn xpub_announce_invalid_fingerprint_rejected(bad_fp in "[g-z]{8}") {
        let xpubs = vec![AnnouncedXpub {
            xpub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK".into(),
            fingerprint: bad_fp,
            label: None,
        }];
        let payload = XpubAnnouncePayload::new([1u8; 32], 1, xpubs);
        prop_assert!(KfpMessage::XpubAnnounce(payload).validate().is_err());
    }

    #[test]
    fn xpub_announce_oversized_label_rejected(extra in 1usize..50) {
        let xpubs = vec![AnnouncedXpub {
            xpub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK".into(),
            fingerprint: "aabbccdd".into(),
            label: Some("L".repeat(MAX_XPUB_LABEL_LENGTH + extra)),
        }];
        let payload = XpubAnnouncePayload::new([1u8; 32], 1, xpubs);
        prop_assert!(KfpMessage::XpubAnnounce(payload).validate().is_err());
    }
}

#[test]
fn valid_messages_pass_validation() {
    assert!(KfpMessage::Announce(
        AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 12345)
            .with_name("Test")
            .with_capabilities(vec!["sign".into()])
    )
    .validate()
    .is_ok());

    assert!(KfpMessage::SignRequest(SignRequestPayload::new(
        [1u8; 32],
        [2u8; 32],
        vec![1, 2, 3],
        "raw",
        vec![1, 2]
    ))
    .validate()
    .is_ok());

    assert!(
        KfpMessage::Commitment(CommitmentPayload::new([1u8; 32], 1, vec![0u8; 64]))
            .validate()
            .is_ok()
    );

    assert!(
        KfpMessage::SignatureShare(SignatureSharePayload::new([1u8; 32], 1, vec![0u8; 32]))
            .validate()
            .is_ok()
    );

    assert!(
        KfpMessage::Error(ErrorPayload::new("INVALID_SESSION", "Session not found"))
            .validate()
            .is_ok()
    );
}

#[test]
fn message_type_accessor() {
    assert_eq!(
        KfpMessage::Announce(AnnouncePayload::new(
            [1u8; 32], 1, [2u8; 33], [3u8; 64], 12345
        ))
        .message_type(),
        "announce"
    );
    assert_eq!(
        KfpMessage::SignRequest(SignRequestPayload::new(
            [1u8; 32],
            [2u8; 32],
            vec![],
            "raw",
            vec![]
        ))
        .message_type(),
        "sign_request"
    );
}

#[test]
fn boundary_sizes_valid() {
    assert!(KfpMessage::SignRequest(SignRequestPayload::new(
        [1u8; 32],
        [2u8; 32],
        vec![0u8; MAX_MESSAGE_SIZE],
        "raw",
        vec![1]
    ))
    .validate()
    .is_ok());

    assert!(KfpMessage::Announce(
        AnnouncePayload::new([1u8; 32], 1, [2u8; 33], [3u8; 64], 12345)
            .with_name(&"n".repeat(MAX_NAME_LENGTH))
    )
    .validate()
    .is_ok());

    assert!(KfpMessage::Commitment(CommitmentPayload::new(
        [1u8; 32],
        1,
        vec![0u8; MAX_COMMITMENT_SIZE]
    ))
    .validate()
    .is_ok());
}

#[test]
fn valid_xpub_announce_passes_validation() {
    let xpubs = vec![
        AnnouncedXpub {
            xpub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK".into(),
            fingerprint: "aabbccdd".into(),
            label: Some("hot".into()),
        },
        AnnouncedXpub {
            xpub: "tpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK".into(),
            fingerprint: "00112233".into(),
            label: None,
        },
    ];
    let payload = XpubAnnouncePayload::new([1u8; 32], 1, xpubs);
    assert!(KfpMessage::XpubAnnounce(payload).validate().is_ok());
}

#[test]
fn xpub_announce_duplicate_xpubs_rejected() {
    let xpubs = vec![
        AnnouncedXpub {
            xpub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK".into(),
            fingerprint: "aabbccdd".into(),
            label: None,
        },
        AnnouncedXpub {
            xpub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK".into(),
            fingerprint: "11223344".into(),
            label: None,
        },
    ];
    let payload = XpubAnnouncePayload::new([1u8; 32], 1, xpubs);
    assert!(KfpMessage::XpubAnnounce(payload).validate().is_err());
}

#[test]
fn xpub_announce_empty_rejected() {
    let payload = XpubAnnouncePayload::new([1u8; 32], 1, vec![]);
    assert!(KfpMessage::XpubAnnounce(payload).validate().is_err());
}

#[test]
fn xpub_announce_zero_share_index_rejected() {
    let xpubs = vec![AnnouncedXpub {
        xpub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK".into(),
        fingerprint: "aabbccdd".into(),
        label: None,
    }];
    let payload = XpubAnnouncePayload::new([1u8; 32], 0, xpubs);
    assert!(KfpMessage::XpubAnnounce(payload).validate().is_err());
}

#[test]
fn xpub_announce_short_fingerprint_rejected() {
    let xpubs = vec![AnnouncedXpub {
        xpub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUK".into(),
        fingerprint: "aabb".into(),
        label: None,
    }];
    let payload = XpubAnnouncePayload::new([1u8; 32], 1, xpubs);
    assert!(KfpMessage::XpubAnnounce(payload).validate().is_err());
}
