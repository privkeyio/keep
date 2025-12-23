#![forbid(unsafe_code)]

use nostr_sdk::prelude::*;

use crate::error::{FrostNetError, Result};
use crate::protocol::*;

pub struct KfpEventBuilder;

impl KfpEventBuilder {
    pub fn announcement(
        keys: &Keys,
        group_pubkey: &[u8; 32],
        share_index: u16,
        name: Option<&str>,
    ) -> Result<Event> {
        let mut payload = AnnouncePayload::new(*group_pubkey, share_index);
        if let Some(n) = name {
            payload = payload.with_name(n);
        }

        let msg = KfpMessage::Announce(payload);
        let content = msg.to_json()?;

        EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), content)
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
            .tag(Tag::public_key(*recipient))
            .tag(Tag::custom(TagKind::custom("t"), ["error"]));

        if let Some(sid) = session_id {
            builder = builder.tag(Tag::custom(TagKind::custom("s"), [hex::encode(sid)]));
        }

        builder
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn decrypt_message(keys: &Keys, event: &Event) -> Result<KfpMessage> {
        let is_addressed_to_us = event.tags.iter().any(|t| {
            if let Some(TagStandard::PublicKey { public_key, .. }) = t.as_standardized() {
                public_key == &keys.public_key()
            } else {
                false
            }
        });

        let content = if is_addressed_to_us {
            nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content)
                .map_err(|e| FrostNetError::Crypto(format!("Decryption failed: {}", e)))?
        } else {
            event.content.clone()
        };

        KfpMessage::from_json(&content).map_err(FrostNetError::Json)
    }

    pub fn get_message_type(event: &Event) -> Option<String> {
        event.tags.iter().find_map(|t| {
            let tag = t.as_slice();
            if tag.first()? == "t" {
                tag.get(1).map(|s| s.to_string())
            } else {
                None
            }
        })
    }

    pub fn get_session_id(event: &Event) -> Option<[u8; 32]> {
        event.tags.iter().find_map(|t| {
            let tag = t.as_slice();
            if tag.first()? == "s" {
                let hex_str = tag.get(1)?;
                let bytes = hex::decode(hex_str).ok()?;
                bytes.try_into().ok()
            } else {
                None
            }
        })
    }

    pub fn get_group_pubkey(event: &Event) -> Option<[u8; 32]> {
        event.tags.iter().find_map(|t| {
            let tag = t.as_slice();
            if tag.first()? == "g" {
                let hex_str = tag.get(1)?;
                let bytes = hex::decode(hex_str).ok()?;
                bytes.try_into().ok()
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announcement_event() {
        let keys = Keys::generate();
        let group_pubkey = [1u8; 32];

        let event = KfpEventBuilder::announcement(&keys, &group_pubkey, 1, Some("test")).unwrap();

        assert_eq!(event.kind, Kind::Custom(KFP_EVENT_KIND));

        let msg_type = KfpEventBuilder::get_message_type(&event);
        assert_eq!(msg_type, Some("announce".to_string()));

        let group = KfpEventBuilder::get_group_pubkey(&event);
        assert_eq!(group, Some(group_pubkey));
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
