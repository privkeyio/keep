// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use nostr_sdk::prelude::*;

use crate::error::{FrostNetError, Result};
use crate::proof;
use crate::protocol::*;

pub(crate) const TIMESTAMP_TWEAK_RANGE: std::ops::Range<u64> = 0..5;

pub struct KfpEventBuilder;

impl KfpEventBuilder {
    pub fn announcement(
        keys: &Keys,
        group_pubkey: &[u8; 32],
        share_index: u16,
        signing_share: &[u8; 32],
        verifying_share: &[u8; 33],
        name: Option<&str>,
    ) -> Result<Event> {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let proof_signature = proof::sign_proof(
            signing_share,
            group_pubkey,
            share_index,
            verifying_share,
            timestamp,
        )?;

        let mut payload = AnnouncePayload::new(
            *group_pubkey,
            share_index,
            *verifying_share,
            proof_signature,
            timestamp,
        );
        if let Some(n) = name {
            payload = payload.with_name(n);
        }

        let msg = KfpMessage::Announce(payload);
        let content = msg.to_json()?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), content)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::custom(
                TagKind::custom("g"),
                [hex::encode(group_pubkey)],
            ))
            .tag(Tag::custom(TagKind::custom("t"), ["announce"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn sign_request(
        keys: &Keys,
        recipient: &PublicKey,
        request: SignRequestPayload,
    ) -> Result<Event> {
        let msg = KfpMessage::SignRequest(request.clone());
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(
                TagKind::custom("g"),
                [hex::encode(request.group_pubkey)],
            ))
            .tag(Tag::custom(
                TagKind::custom("s"),
                [hex::encode(request.session_id)],
            ))
            .tag(Tag::custom(TagKind::custom("t"), ["sign_request"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn commitment(
        keys: &Keys,
        recipient: &PublicKey,
        payload: CommitmentPayload,
    ) -> Result<Event> {
        let msg = KfpMessage::Commitment(payload.clone());
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(
                TagKind::custom("s"),
                [hex::encode(payload.session_id)],
            ))
            .tag(Tag::custom(TagKind::custom("t"), ["commitment"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn signature_share(
        keys: &Keys,
        recipient: &PublicKey,
        payload: SignatureSharePayload,
    ) -> Result<Event> {
        let msg = KfpMessage::SignatureShare(payload.clone());
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(
                TagKind::custom("s"),
                [hex::encode(payload.session_id)],
            ))
            .tag(Tag::custom(TagKind::custom("t"), ["signature_share"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn signature_complete(
        keys: &Keys,
        recipient: &PublicKey,
        payload: SignatureCompletePayload,
    ) -> Result<Event> {
        let msg = KfpMessage::SignatureComplete(payload.clone());
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(
                TagKind::custom("s"),
                [hex::encode(payload.session_id)],
            ))
            .tag(Tag::custom(TagKind::custom("t"), ["signature_complete"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn ping(keys: &Keys, recipient: &PublicKey) -> Result<Event> {
        let payload = PingPayload::new();
        let msg = KfpMessage::Ping(payload);
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(TagKind::custom("t"), ["ping"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn pong(keys: &Keys, recipient: &PublicKey, challenge: [u8; 32]) -> Result<Event> {
        let payload = PongPayload {
            challenge,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        let msg = KfpMessage::Pong(payload);
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(TagKind::custom("t"), ["pong"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn error(
        keys: &Keys,
        recipient: &PublicKey,
        code: &str,
        message: &str,
        session_id: Option<[u8; 32]>,
    ) -> Result<Event> {
        let mut payload = ErrorPayload::new(code, message);
        if let Some(sid) = session_id {
            payload = payload.with_session(sid);
        }

        let msg = KfpMessage::Error(payload);
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        let mut builder = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(TagKind::custom("t"), ["error"]));

        if let Some(sid) = session_id {
            builder = builder.tag(Tag::custom(TagKind::custom("s"), [hex::encode(sid)]));
        }

        builder
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn ecdh_request(
        keys: &Keys,
        recipient: &PublicKey,
        request: EcdhRequestPayload,
    ) -> Result<Event> {
        let msg = KfpMessage::EcdhRequest(request.clone());
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(
                TagKind::custom("g"),
                [hex::encode(request.group_pubkey)],
            ))
            .tag(Tag::custom(
                TagKind::custom("s"),
                [hex::encode(request.session_id)],
            ))
            .tag(Tag::custom(TagKind::custom("t"), ["ecdh_request"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn ecdh_share(
        keys: &Keys,
        recipient: &PublicKey,
        payload: EcdhSharePayload,
    ) -> Result<Event> {
        let msg = KfpMessage::EcdhShare(payload.clone());
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(
                TagKind::custom("s"),
                [hex::encode(payload.session_id)],
            ))
            .tag(Tag::custom(TagKind::custom("t"), ["ecdh_share"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn ecdh_complete(
        keys: &Keys,
        recipient: &PublicKey,
        payload: EcdhCompletePayload,
    ) -> Result<Event> {
        let session_id = payload.session_id;
        let msg = KfpMessage::EcdhComplete(payload);
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(TagKind::custom("s"), [hex::encode(session_id)]))
            .tag(Tag::custom(TagKind::custom("t"), ["ecdh_complete"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn xpub_announce(
        keys: &Keys,
        recipient: &PublicKey,
        payload: XpubAnnouncePayload,
    ) -> Result<Event> {
        let group_pubkey = payload.group_pubkey;
        let msg = KfpMessage::XpubAnnounce(payload);
        let content = msg.to_json()?;

        let encrypted = nip44::encrypt(keys.secret_key(), recipient, &content, nip44::Version::V2)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(
                TagKind::custom("g"),
                [hex::encode(group_pubkey)],
            ))
            .tag(Tag::custom(TagKind::custom("t"), ["xpub_announce"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn decrypt_message(keys: &Keys, event: &Event) -> Result<KfpMessage> {
        const MAX_ENCRYPTED_CONTENT_SIZE: usize = MAX_MESSAGE_SIZE * 2;
        if event.content.len() > MAX_ENCRYPTED_CONTENT_SIZE {
            return Err(FrostNetError::Protocol(
                "Content exceeds maximum size".into(),
            ));
        }

        let is_addressed_to_us = event.tags.iter().any(|t| {
            if let Some(TagStandard::PublicKey { public_key, .. }) = t.as_standardized() {
                public_key == &keys.public_key()
            } else {
                false
            }
        });

        let content = if is_addressed_to_us {
            nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content)
                .map_err(|e| FrostNetError::Crypto(format!("Decryption failed: {e}")))?
        } else {
            event.content.clone()
        };

        if content.len() > MAX_MESSAGE_SIZE {
            return Err(FrostNetError::Protocol(
                "Decrypted content exceeds maximum size".into(),
            ));
        }

        KfpMessage::from_json(&content).map_err(FrostNetError::Json)
    }

    pub fn get_message_type(event: &Event) -> Option<String> {
        event
            .tags
            .find(TagKind::custom("t"))
            .and_then(|t| t.as_slice().get(1).map(|s| s.to_string()))
    }

    pub fn get_session_id(event: &Event) -> Option<[u8; 32]> {
        event
            .tags
            .find(TagKind::custom("s"))
            .and_then(|t| t.as_slice().get(1))
            .and_then(|hex_str| hex::decode(hex_str).ok())
            .and_then(|bytes| bytes.try_into().ok())
    }

    pub fn get_group_pubkey(event: &Event) -> Option<[u8; 32]> {
        event
            .tags
            .find(TagKind::custom("g"))
            .and_then(|t| t.as_slice().get(1))
            .and_then(|hex_str| hex::decode(hex_str).ok())
            .and_then(|bytes| bytes.try_into().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;

    #[test]
    fn test_announcement_event() {
        let keys = Keys::generate();
        let group_pubkey = [1u8; 32];

        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut signing_share = [0u8; 32];
        signing_share.copy_from_slice(&signing_key.to_bytes());
        let mut verifying_share = [0u8; 33];
        verifying_share[0] = 0x02;
        verifying_share[1..33].copy_from_slice(&verifying_key.to_bytes());

        let event = KfpEventBuilder::announcement(
            &keys,
            &group_pubkey,
            1,
            &signing_share,
            &verifying_share,
            Some("test"),
        )
        .unwrap();

        assert_eq!(event.kind, Kind::Custom(KFP_EVENT_KIND));

        let msg_type = KfpEventBuilder::get_message_type(&event);
        assert_eq!(msg_type, Some("announce".to_string()));

        let group = KfpEventBuilder::get_group_pubkey(&event);
        assert_eq!(group, Some(group_pubkey));

        let parsed = KfpMessage::from_json(&event.content).unwrap();
        if let KfpMessage::Announce(payload) = parsed {
            crate::proof::verify_proof(
                &payload.verifying_share,
                &payload.proof_signature,
                &payload.group_pubkey,
                payload.share_index,
                payload.timestamp,
            )
            .expect("proof verification should succeed");
        } else {
            panic!("expected Announce message");
        }
    }

    #[test]
    fn test_encrypted_message_roundtrip() {
        let sender = Keys::generate();
        let recipient = Keys::generate();

        let request =
            SignRequestPayload::new([1u8; 32], [2u8; 32], b"test".to_vec(), "raw", vec![1, 2]);

        let event =
            KfpEventBuilder::sign_request(&sender, &recipient.public_key(), request).unwrap();

        let decrypted = KfpEventBuilder::decrypt_message(&recipient, &event).unwrap();

        match decrypted {
            KfpMessage::SignRequest(p) => {
                assert_eq!(p.message, b"test".to_vec());
            }
            _ => panic!("expected SignRequest"),
        }
    }
}
