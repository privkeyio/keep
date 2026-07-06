// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use keep_core::crypto::SecretKey;
use keep_core::error::{KeepError, Result};
use keep_core::frost::StoredShare;
use keep_frost_net::KfpNode;

#[derive(Clone)]
pub struct FrostSigner {
    group_pubkey: [u8; 32],
    shares: Vec<StoredShare>,
    data_key: SecretKey,
    threshold: u16,
}

impl FrostSigner {
    pub fn new(
        group_pubkey: [u8; 32],
        shares: Vec<StoredShare>,
        data_key: SecretKey,
    ) -> Result<Self> {
        if shares.is_empty() {
            return Err(KeepError::Frost("No shares provided".into()));
        }

        let threshold = shares[0].metadata.threshold;

        if shares.len() < threshold as usize {
            return Err(KeepError::Frost(format!(
                "Need {} shares, only {} provided",
                threshold,
                shares.len()
            )));
        }

        for share in &shares {
            if share.metadata.group_pubkey != group_pubkey {
                return Err(KeepError::Frost(
                    "Share group_pubkey mismatch: all shares must belong to the same group".into(),
                ));
            }
            if share.metadata.threshold != threshold {
                return Err(KeepError::Frost(
                    "Share threshold mismatch: all shares must have the same threshold".into(),
                ));
            }
        }

        Ok(Self {
            group_pubkey,
            shares,
            data_key,
            threshold,
        })
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let mut decrypted = Vec::new();
        for stored in self.shares.iter().take(self.threshold as usize) {
            decrypted.push(stored.decrypt(&self.data_key)?);
        }

        keep_core::frost::sign_with_local_shares(&decrypted, message)
    }
}

pub struct NetworkFrostSigner {
    group_pubkey: [u8; 32],
    node: Arc<KfpNode>,
}

impl NetworkFrostSigner {
    #[allow(dead_code)]
    pub fn new(group_pubkey: [u8; 32], node: KfpNode) -> Self {
        Self {
            group_pubkey,
            node: Arc::new(node),
        }
    }

    pub fn with_shared_node(group_pubkey: [u8; 32], node: Arc<KfpNode>) -> Self {
        Self { group_pubkey, node }
    }

    pub fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    pub async fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        self.node
            .request_signature(message.to_vec(), keep_frost_net::MSG_TYPE_NOSTR_EVENT)
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))
    }

    /// Sign the 32-byte Nostr event id `message` and attach the structured
    /// event body so co-signers recompute the id from `(pubkey, created_at,
    /// kind, tags, content)` and reject a cross-domain label spoof (#529).
    /// Call this whenever the full [`UnsignedEvent`] is in scope, so the
    /// signing path is domain-validated end-to-end.
    pub async fn sign_nostr_event(
        &self,
        message: &[u8],
        event: &nostr_sdk::UnsignedEvent,
    ) -> Result<[u8; 64]> {
        let payload = keep_frost_net::NostrEventPayload::from_unsigned_event(event);
        let structured =
            serde_json::to_vec(&payload).map_err(|e| KeepError::Frost(e.to_string()))?;
        self.node
            .request_signature_structured(
                message.to_vec(),
                keep_frost_net::MSG_TYPE_NOSTR_EVENT,
                Some(structured),
            )
            .await
            .map_err(|e| KeepError::Frost(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::crypto::SecretKey;
    use keep_core::frost::{ShareMetadata, SharePackage};
    use nostr_sdk::prelude::*;

    // Build a 1-of-1 FROST share the same way an imported nsec does: the lone
    // signing share is the full secret key, so the single holder satisfies the
    // threshold and can sign without any co-signer.
    fn make_1of1_share() -> ([u8; 32], SharePackage) {
        use frost_secp256k1_tr as frost;

        let secret = [0x11u8; 32];
        let signing_key = frost::SigningKey::deserialize(&secret).unwrap();
        let vk = frost::VerifyingKey::from(&signing_key);
        let vk_bytes = vk.serialize().unwrap();

        let identifier = frost::Identifier::try_from(1u16).unwrap();
        let signing_share = frost::keys::SigningShare::deserialize(&secret).unwrap();
        let verifying_share = frost::keys::VerifyingShare::deserialize(&vk_bytes).unwrap();
        let key_package =
            frost::keys::KeyPackage::new(identifier, signing_share, verifying_share, vk, 1);

        let mut verifying_shares = std::collections::BTreeMap::new();
        verifying_shares.insert(identifier, verifying_share);
        let pubkey_package = frost::keys::PublicKeyPackage::new(verifying_shares, vk, Some(1));

        let group_pubkey: [u8; 32] = vk_bytes[1..33].try_into().unwrap();
        let metadata = ShareMetadata::new(1, 1, 1, group_pubkey, "test".to_string());
        let share = SharePackage::new(metadata, &key_package, &pubkey_package).unwrap();

        (group_pubkey, share)
    }

    // The local-signing path: a 1-of-1 share builds a FrostSigner that produces
    // a BIP340 signature verifiable under the group pubkey, exactly as the
    // nip46 handler signs an event id and assembles the signed event.
    #[test]
    fn frost_signer_1of1_signs_and_verifies_against_group_pubkey() {
        let (group_pubkey, share) = make_1of1_share();

        let data_key = SecretKey::generate().unwrap();
        let stored = StoredShare::encrypt(&share, &data_key).unwrap();
        let signer = FrostSigner::new(group_pubkey, vec![stored], data_key).unwrap();
        assert_eq!(signer.group_pubkey(), &group_pubkey);

        let author = PublicKey::from_slice(&group_pubkey).unwrap();
        let mut unsigned = UnsignedEvent::new(
            author,
            Timestamp::from(1_700_000_000),
            Kind::TextNote,
            Vec::<Tag>::new(),
            "local frost signing",
        );
        unsigned.ensure_id();
        let event_id = unsigned.id.unwrap();

        let sig_bytes = signer.sign(event_id.as_bytes()).unwrap();

        let sig = nostr_sdk::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
        let event = Event::new(
            event_id,
            author,
            unsigned.created_at,
            unsigned.kind,
            unsigned.tags.clone(),
            unsigned.content.clone(),
            sig,
        );

        assert!(
            event.verify().is_ok(),
            "1-of-1 local FROST signature must verify under group_pubkey"
        );
    }
}
