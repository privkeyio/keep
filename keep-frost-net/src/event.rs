// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use nostr_sdk::prelude::*;

use keep_core::relay::TIMESTAMP_TWEAK_RANGE;

use crate::error::{FrostNetError, Result};
use crate::proof;
use crate::protocol::*;

pub struct KfpEventBuilder;

impl KfpEventBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn announcement(
        keys: &Keys,
        group_pubkey: &[u8; 32],
        share_index: u16,
        signing_share: &[u8; 32],
        verifying_share: &[u8; 33],
        name: Option<&str>,
        timestamp: u64,
        tpm_attestation: Option<TpmQuoteEvidence>,
    ) -> Result<Event> {
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
        if let Some(ev) = tpm_attestation {
            payload = payload.with_tpm_attestation(ev);
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

    /// Build a holder's duress beacon: a normal KFP event signed by the holder's
    /// dedicated duress-beacon `keys` (NOT the vault-derived identity, which
    /// duress mode never unlocks). `nonce` must be freshly random. The cluster
    /// authenticates it against the pinned beacon pubkey (see
    /// [`verify_unwrapped_duress_beacon`]), so no proof-of-share is needed.
    ///
    /// Metadata-private wire form (NIP-59 gift wrap): the `DuressBeaconPayload` is
    /// placed in an unsigned rumor authored by the beacon key, sealed by the beacon
    /// key (authenticity), then gift-wrapped to `recipient` (a group member's
    /// transport pubkey) with an EPHEMERAL key and a randomized timestamp. To a
    /// relay it is an ordinary `kind:1059` gift wrap , indistinguishable from a
    /// private DM, with no duress label, group, nonce, or beacon-key identity
    /// visible on the wire, and no fixed author to filter on. Broadcast is one wrap
    /// per group member (the caller wraps to each). Freshness is enforced on the
    /// payload's own `created_at`, independent of the wrap's tweaked timestamp.
    pub async fn duress_beacon(
        beacon_keys: &Keys,
        group_pubkey: &[u8; 32],
        nonce: &[u8; 32],
        recipient: &PublicKey,
    ) -> Result<Event> {
        let payload = DuressBeaconPayload::new(*group_pubkey, *nonce);
        let content = KfpMessage::DuressBeacon(payload).to_json()?;
        let rumor = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), content)
            .build(beacon_keys.public_key());
        EventBuilder::gift_wrap(beacon_keys, recipient, rumor, [])
            .await
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    /// Build one gift-wrapped duress beacon per group member (transport pubkeys
    /// derived from `group_pubkey` + `total_shares`), so a coerced holder can
    /// broadcast the beacon metadata-privately to every holder. All wraps carry the
    /// same `nonce` (one logical beacon) but each is a distinct `kind:1059` to a
    /// distinct recipient under its own ephemeral key. The caller publishes the
    /// returned wraps. A coerced holder cannot read its group's size once locked,
    /// so `total_shares` is supplied out of band (the serve `--group-total`).
    pub async fn duress_beacon_broadcast(
        beacon_keys: &Keys,
        group_pubkey: &[u8; 32],
        total_shares: u16,
        nonce: &[u8; 32],
    ) -> Result<Vec<Event>> {
        let recipients = crate::node::group_member_pubkeys(group_pubkey, total_shares);
        let mut wraps = Vec::with_capacity(recipients.len());
        for recipient in &recipients {
            wraps.push(Self::duress_beacon(beacon_keys, group_pubkey, nonce, recipient).await?);
        }
        Ok(wraps)
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

    pub fn nonce_commitment(
        keys: &Keys,
        recipient: &PublicKey,
        payload: NonceCommitmentPayload,
    ) -> Result<Event> {
        let group_pubkey = payload.group_pubkey;
        let msg = KfpMessage::NonceCommitment(payload);
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
            .tag(Tag::custom(TagKind::custom("t"), ["nonce_commitment"]))
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
            timestamp: Timestamp::now().as_secs(),
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

    pub fn oprf_eval_request(
        keys: &Keys,
        recipient: &PublicKey,
        request: OprfEvalRequestPayload,
    ) -> Result<Event> {
        let msg = KfpMessage::OprfEvalRequest(request.clone());
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
            .tag(Tag::custom(TagKind::custom("t"), ["oprf_eval_request"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    pub fn oprf_eval_share(
        keys: &Keys,
        recipient: &PublicKey,
        payload: OprfEvalSharePayload,
    ) -> Result<Event> {
        let msg = KfpMessage::OprfEvalShare(payload.clone());
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
            .tag(Tag::custom(TagKind::custom("t"), ["oprf_eval_share"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    /// Dealer → holder: the trusted-dealer OPRF enrollment carrying the holder's
    /// secret key share. NIP-44-encrypted to the target peer so the relay only
    /// ever sees ciphertext (the `share` is the most sensitive payload).
    pub fn oprf_enroll(
        keys: &Keys,
        recipient: &PublicKey,
        payload: OprfEnrollPayload,
    ) -> Result<Event> {
        let group_pubkey = payload.group_pubkey;
        let session_id = payload.session_id;
        let msg = KfpMessage::OprfEnroll(payload);
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
            .tag(Tag::custom(TagKind::custom("s"), [hex::encode(session_id)]))
            .tag(Tag::custom(TagKind::custom("t"), ["oprf_enroll"]))
            .sign_with_keys(keys)
            .map_err(|e| FrostNetError::Nostr(e.to_string()))
    }

    /// Holder → dealer: acknowledgement of a received enrollment share.
    pub fn oprf_enroll_ack(
        keys: &Keys,
        recipient: &PublicKey,
        payload: OprfEnrollAckPayload,
    ) -> Result<Event> {
        let msg = KfpMessage::OprfEnrollAck(payload.clone());
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
            .tag(Tag::custom(TagKind::custom("t"), ["oprf_enroll_ack"]))
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

    /// Build an encrypted PSBT coordination event for `recipient`. Used by
    /// `PsbtPropose` / `PsbtSign` / `PsbtFinalize` / `PsbtAbort`, which all
    /// share the same g/s/t tag layout.
    pub fn psbt_event(
        keys: &Keys,
        recipient: &PublicKey,
        group_pubkey: &[u8; 32],
        session_id: &[u8; 32],
        msg_type: &'static str,
        msg: &KfpMessage,
    ) -> Result<Event> {
        if msg.message_type() != msg_type {
            return Err(FrostNetError::Protocol(format!(
                "psbt_event msg_type tag '{msg_type}' does not match payload type '{}'",
                msg.message_type()
            )));
        }
        if msg.group_pubkey() != Some(group_pubkey) {
            return Err(FrostNetError::Protocol(
                "psbt_event group_pubkey tag does not match payload".into(),
            ));
        }
        if msg.session_id() != Some(session_id) {
            return Err(FrostNetError::Protocol(
                "psbt_event session_id tag does not match payload".into(),
            ));
        }

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
            .tag(Tag::custom(TagKind::custom("s"), [hex::encode(session_id)]))
            .tag(Tag::custom(TagKind::custom("t"), [msg_type]))
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

        let is_addressed_to_us =
            event
                .tags
                .filter(TagKind::p())
                .any(|t| match t.as_standardized() {
                    Some(TagStandard::PublicKey { public_key, .. }) => {
                        public_key == &keys.public_key()
                    }
                    _ => false,
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

        let msg = KfpMessage::from_json(&content).map_err(FrostNetError::Json)?;
        msg.validate()
            .map_err(|e| FrostNetError::Protocol(e.to_string()))?;
        Ok(msg)
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

/// Verify a duress beacon UNWRAPPED from a NIP-59 gift wrap (via
/// [`nostr_sdk::nips::nip59::extract_rumor`], which already decrypts and verifies
/// the gift-wrap + seal signatures). `sender` is the seal author; `rumor` the
/// inner payload event. Checks the seal author is the pinned beacon pubkey, the
/// rumor is a `DuressBeacon` for `group_pubkey`, and it is fresh. Replay dedup is
/// the caller's job; this only bounds the window.
pub fn verify_unwrapped_duress_beacon(
    sender: &PublicKey,
    rumor: &UnsignedEvent,
    expected_beacon_pubkey: &PublicKey,
    group_pubkey: &[u8; 32],
    window_secs: u64,
) -> Result<DuressBeaconPayload> {
    if sender != expected_beacon_pubkey {
        return Err(FrostNetError::UntrustedPeer(
            "duress beacon not sealed by the pinned beacon key".into(),
        ));
    }
    if rumor.kind != Kind::Custom(KFP_EVENT_KIND) {
        return Err(FrostNetError::Protocol("not a KFP rumor".into()));
    }
    let payload = match KfpMessage::from_json(&rumor.content)? {
        KfpMessage::DuressBeacon(p) => p,
        _ => {
            return Err(FrostNetError::Protocol(
                "rumor is not a duress beacon".into(),
            ))
        }
    };
    if &payload.group_pubkey != group_pubkey {
        return Err(FrostNetError::Protocol(
            "duress beacon group mismatch".into(),
        ));
    }
    if !payload.is_within_replay_window(window_secs) {
        return Err(FrostNetError::ReplayDetected(
            "duress beacon outside replay window".into(),
        ));
    }
    Ok(payload)
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
            Timestamp::now().as_secs(),
            None,
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
            assert!(payload.tpm_attestation.is_none());
        } else {
            panic!("expected Announce message");
        }
    }

    #[test]
    fn test_announcement_attaches_tpm_evidence() {
        let keys = Keys::generate();
        let group_pubkey = [2u8; 32];
        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut signing_share = [0u8; 32];
        signing_share.copy_from_slice(&signing_key.to_bytes());
        let mut verifying_share = [0u8; 33];
        verifying_share[0] = 0x02;
        verifying_share[1..33].copy_from_slice(&verifying_key.to_bytes());

        let evidence = TpmQuoteEvidence {
            attest: vec![0xff; 16],
            signature: vec![7u8; 64],
            ak_sec1: {
                let mut v = vec![0u8; 65];
                v[0] = 0x04;
                v
            },
            pcr_values: vec!["00".repeat(32)],
        };

        let event = KfpEventBuilder::announcement(
            &keys,
            &group_pubkey,
            1,
            &signing_share,
            &verifying_share,
            None,
            Timestamp::now().as_secs(),
            Some(evidence.clone()),
        )
        .unwrap();

        let parsed = KfpMessage::from_json(&event.content).unwrap();
        let KfpMessage::Announce(payload) = parsed else {
            panic!("expected Announce message");
        };
        let attached = payload.tpm_attestation.expect("evidence must be attached");
        assert_eq!(attached.attest, evidence.attest);
        assert_eq!(attached.signature, evidence.signature);
        assert_eq!(attached.ak_sec1, evidence.ak_sec1);
        assert_eq!(attached.pcr_values, evidence.pcr_values);
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

    /// Unwrap a gift wrap as `recipient` (decrypts + verifies the wrap/seal
    /// signatures) and return the seal author and inner rumor, as the node does.
    async fn unwrap(recipient: &Keys, wrap: &Event) -> (PublicKey, UnsignedEvent) {
        let g = nostr_sdk::nips::nip59::extract_rumor(recipient, wrap)
            .await
            .expect("gift wrap must unwrap for its recipient");
        (g.sender, g.rumor)
    }

    #[tokio::test]
    async fn duress_beacon_roundtrips_and_verifies() {
        let beacon_keys = Keys::generate();
        let recipient = Keys::generate();
        let group = [7u8; 32];
        let nonce = [9u8; 32];
        let wrap =
            KfpEventBuilder::duress_beacon(&beacon_keys, &group, &nonce, &recipient.public_key())
                .await
                .unwrap();

        // On the wire it is an ordinary kind:1059 gift wrap addressed to the
        // recipient, authored by an ephemeral key (never the beacon key).
        assert_eq!(wrap.kind, Kind::GiftWrap);
        assert_ne!(wrap.pubkey, beacon_keys.public_key());

        let (sender, rumor) = unwrap(&recipient, &wrap).await;
        let payload =
            verify_unwrapped_duress_beacon(&sender, &rumor, &beacon_keys.public_key(), &group, 300)
                .unwrap();
        assert_eq!(payload.group_pubkey, group);
        assert_eq!(payload.nonce, nonce);
    }

    #[tokio::test]
    async fn duress_beacon_rejects_wrong_signer() {
        // Sealed by a different key than the pinned beacon key: authorship rejected.
        // This is the load-bearing authenticity check (the beacon has no proof-of-share).
        let beacon_keys = Keys::generate();
        let recipient = Keys::generate();
        let attacker = Keys::generate();
        let group = [7u8; 32];
        let wrap = KfpEventBuilder::duress_beacon(
            &beacon_keys,
            &group,
            &[1u8; 32],
            &recipient.public_key(),
        )
        .await
        .unwrap();
        let (sender, rumor) = unwrap(&recipient, &wrap).await;
        let err =
            verify_unwrapped_duress_beacon(&sender, &rumor, &attacker.public_key(), &group, 300)
                .unwrap_err();
        assert!(matches!(err, FrostNetError::UntrustedPeer(_)));
    }

    #[tokio::test]
    async fn duress_beacon_rejects_group_mismatch() {
        let beacon_keys = Keys::generate();
        let recipient = Keys::generate();
        let wrap = KfpEventBuilder::duress_beacon(
            &beacon_keys,
            &[1u8; 32],
            &[2u8; 32],
            &recipient.public_key(),
        )
        .await
        .unwrap();
        let (sender, rumor) = unwrap(&recipient, &wrap).await;
        let err = verify_unwrapped_duress_beacon(
            &sender,
            &rumor,
            &beacon_keys.public_key(),
            &[9u8; 32],
            300,
        )
        .unwrap_err();
        assert!(matches!(err, FrostNetError::Protocol(_)));
    }

    #[test]
    fn duress_beacon_payload_freshness_window() {
        let mut p = DuressBeaconPayload::new([0u8; 32], [0u8; 32]);
        assert!(p.is_within_replay_window(300));
        p.created_at = 1; // ancient
        assert!(!p.is_within_replay_window(300));
    }

    #[tokio::test]
    async fn verify_duress_beacon_rejects_stale_end_to_end() {
        // A beacon whose inner payload created_at is far in the past is rejected by
        // the verifier's freshness check (drives ReplayDetected end-to-end through a
        // real gift wrap + unwrap, independent of the wrap's own tweaked timestamp).
        let beacon_keys = Keys::generate();
        let recipient = Keys::generate();
        let group = [7u8; 32];
        let mut payload = DuressBeaconPayload::new(group, [1u8; 32]);
        payload.created_at = 1; // ancient
        let content = KfpMessage::DuressBeacon(payload).to_json().unwrap();
        let rumor = EventBuilder::new(Kind::Custom(KFP_EVENT_KIND), content)
            .build(beacon_keys.public_key());
        let wrap = EventBuilder::gift_wrap(&beacon_keys, &recipient.public_key(), rumor, [])
            .await
            .unwrap();
        let (sender, rumor) = unwrap(&recipient, &wrap).await;
        let err =
            verify_unwrapped_duress_beacon(&sender, &rumor, &beacon_keys.public_key(), &group, 300)
                .unwrap_err();
        assert!(matches!(err, FrostNetError::ReplayDetected(_)));
    }
}
