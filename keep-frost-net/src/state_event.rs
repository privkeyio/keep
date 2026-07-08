// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Keep-state replication events (the wire format for replicating a vault's redb records over a
//! Nostr relay to a standby node; see keep-node qmc/ax2).
//!
//! Each replicated record is one NIP-78 addressable event (kind 30078) authored by the SHARED cluster
//! identity and addressed by a `d`-tag `keep:<table>:<record-id>`. Because addressable events are
//! parameterized-replaceable (NIP-01), a newer write to the same record supersedes the old one and the
//! relay keeps only the latest, giving per-record convergence for free. The record's already-vault-
//! encrypted bytes are NIP-44-encrypted to the shared identity (self-encryption), so the relay only
//! ever holds ciphertext; a standby that shares the cluster identity AND the vault password (same
//! Argon2 storage key) decrypts the NIP-44 layer and stores the inner bytes straight into its redb.
//! A delete is a same-`d`-tag tombstone (empty content, a `deleted` tag).
use nostr_sdk::prelude::*;

use crate::error::{FrostNetError, Result};

/// NIP-78 application-specific (addressable, parameterized-replaceable) data.
pub const KEEP_STATE_KIND: u16 = 30078;

/// The replicated redb tables. `SHARES` is intentionally absent: each node holds its OWN FROST share,
/// so replicating it would clobber the standby's share (see the qmc design).
pub const STATE_TABLES: [&str; 3] = ["keys", "descriptors", "relay_configs"];

fn d_tag(table: &str, record_id: &str) -> String {
    format!("keep:{table}:{record_id}")
}

/// Build an addressable state-record event: `NIP-44(hex(content))` authored by `keys`, addressed by
/// `keep:<table>:<record_id>`. `content` is the record's vault-encrypted redb bytes.
pub fn state_record_event(
    keys: &Keys,
    table: &str,
    record_id: &str,
    content: &[u8],
    created_at: u64,
) -> Result<Event> {
    let ciphertext = nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        hex::encode(content),
        nip44::Version::V2,
    )
    .map_err(|e| FrostNetError::Crypto(e.to_string()))?;

    // `created_at` is caller-controlled (strictly monotonic per d-tag) so the relay's created_at-based
    // addressable dedup always retains the latest write and the consumer's rollback guard never rejects
    // a legitimate same-second update (e.g. a record and its immediate delete).
    EventBuilder::new(Kind::Custom(KEEP_STATE_KIND), ciphertext)
        .tag(Tag::identifier(d_tag(table, record_id)))
        .tag(Tag::custom(TagKind::custom("t"), [table.to_string()]))
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .map_err(|e| FrostNetError::Nostr(e.to_string()))
}

/// Build a tombstone (delete) event for a record: same `d`-tag, empty content, a `deleted` marker tag.
pub fn state_tombstone_event(
    keys: &Keys,
    table: &str,
    record_id: &str,
    created_at: u64,
) -> Result<Event> {
    EventBuilder::new(Kind::Custom(KEEP_STATE_KIND), "")
        .tag(Tag::identifier(d_tag(table, record_id)))
        .tag(Tag::custom(TagKind::custom("t"), [table.to_string()]))
        .tag(Tag::custom(
            TagKind::custom("deleted"),
            Vec::<String>::new(),
        ))
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .map_err(|e| FrostNetError::Nostr(e.to_string()))
}

/// A parsed keep-state event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRecord {
    pub table: String,
    pub record_id: String,
    /// The decrypted record bytes, or `None` for a tombstone (delete).
    pub content: Option<Vec<u8>>,
    /// The event's signed `created_at` (unix seconds). The consumer uses it as a per-d-tag
    /// high-water-mark to reject stale/replayed events (rollback protection).
    pub created_at: u64,
}

/// Parse + decrypt a keep-state event authored by the shared identity (`keys`). Returns `Ok(None)` if
/// the event is not a well-formed keep-state event (wrong kind or malformed `d`-tag), so a subscriber
/// can ignore foreign events without erroring.
pub fn parse_state_event(keys: &Keys, event: &Event) -> Result<Option<StateRecord>> {
    if event.kind != Kind::Custom(KEEP_STATE_KIND) {
        return Ok(None);
    }
    // Authenticate authorship against the shared cluster identity, not just the subscription filter:
    // relays are untrusted and can deliver events the filter should have excluded. Without this, a
    // tombstone signed by any keypair would be accepted and delete standby records (records are also
    // guarded by NIP-44 self-encryption, but tombstones carry no ciphertext to gate on).
    if event.pubkey != keys.public_key() {
        return Ok(None);
    }
    let Some(d) = event.tags.identifier() else {
        return Ok(None);
    };
    // d-tag: keep:<table>:<record-id>. Production record_ids are hex, but splitn(3) keeps any ':' in
    // the remainder with the id (see tombstone_has_no_content) so a colon-bearing id survives intact.
    let mut parts = d.splitn(3, ':');
    if parts.next() != Some("keep") {
        return Ok(None);
    }
    let (Some(table), Some(record_id)) = (parts.next(), parts.next()) else {
        return Ok(None);
    };

    let is_tombstone = event
        .tags
        .iter()
        .any(|t| t.kind() == TagKind::custom("deleted"));
    let content = if is_tombstone {
        None
    } else {
        let hex_payload = nip44::decrypt(keys.secret_key(), &keys.public_key(), &event.content)
            .map_err(|e| FrostNetError::Crypto(e.to_string()))?;
        Some(hex::decode(hex_payload.trim()).map_err(|e| FrostNetError::Crypto(e.to_string()))?)
    };

    Ok(Some(StateRecord {
        table: table.to_string(),
        record_id: record_id.to_string(),
        content,
        created_at: event.created_at.as_secs(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_event_round_trips() {
        let keys = Keys::generate();
        let content = b"vault-encrypted-record-bytes\x00\x01\x02";
        let event = state_record_event(&keys, "keys", "abcd1234", content, 1000).unwrap();

        assert_eq!(event.kind, Kind::Custom(KEEP_STATE_KIND));
        assert_eq!(event.tags.identifier(), Some("keep:keys:abcd1234"));

        let parsed = parse_state_event(&keys, &event).unwrap().unwrap();
        assert_eq!(parsed.table, "keys");
        assert_eq!(parsed.record_id, "abcd1234");
        assert_eq!(parsed.content.as_deref(), Some(content.as_slice()));
        assert_eq!(parsed.created_at, 1000);
    }

    #[test]
    fn tombstone_has_no_content() {
        let keys = Keys::generate();
        let event = state_tombstone_event(&keys, "descriptors", "deadbeef:3", 1000).unwrap();
        let parsed = parse_state_event(&keys, &event).unwrap().unwrap();
        assert_eq!(parsed.table, "descriptors");
        // record_id keeps the remainder past the second ':', so a versioned id survives intact.
        assert_eq!(parsed.record_id, "deadbeef:3");
        assert_eq!(parsed.content, None);
    }

    #[test]
    fn foreign_kind_is_ignored() {
        let keys = Keys::generate();
        let foreign = EventBuilder::new(Kind::TextNote, "hello")
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(parse_state_event(&keys, &foreign).unwrap(), None);
    }

    #[test]
    fn foreign_author_is_rejected() {
        // A well-formed keep-state tombstone signed by a DIFFERENT identity must not be accepted:
        // the subscription filter is relay-enforced and untrusted, so authorship is verified here.
        let ours = Keys::generate();
        let attacker = Keys::generate();
        let forged = state_tombstone_event(&attacker, "keys", "abcd1234", 1000).unwrap();
        assert_eq!(parse_state_event(&ours, &forged).unwrap(), None);

        // The same holds for a record event built under a foreign identity.
        let forged_rec = state_record_event(&attacker, "keys", "abcd1234", b"x", 1000).unwrap();
        assert_eq!(parse_state_event(&ours, &forged_rec).unwrap(), None);
    }

    // End-to-end over a real in-process relay, exercising the exact publish/subscribe/notification path
    // keep-web's replication uses: a publisher sends a state event, a subscriber filtered on the shared
    // identity receives it and reconstructs the record.
    #[tokio::test]
    async fn state_event_round_trips_over_a_relay() {
        use nostr_relay_builder::MockRelay;

        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();

        let publisher = Client::new(keys.clone());
        publisher.add_relay(&url).await.unwrap();
        publisher.connect().await;

        let subscriber = Client::new(keys.clone());
        subscriber.add_relay(&url).await.unwrap();
        subscriber.connect().await;
        let filter = Filter::new()
            .author(keys.public_key())
            .kind(Kind::Custom(KEEP_STATE_KIND));
        subscriber.subscribe(filter, None).await.unwrap();
        // Let the REQ register on the relay, and take the notifications receiver BEFORE publishing so
        // the delivered event can't be broadcast before we are listening.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let mut notifications = subscriber.notifications();

        let content = b"encrypted-record-bytes";
        let event = state_record_event(&keys, "keys", "abc123", content, 1000).unwrap();
        publisher.send_event(&event).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Ok(RelayPoolNotification::Event { event, .. }) = notifications.recv().await {
                    if let Ok(Some(rec)) = parse_state_event(&keys, &event) {
                        return rec;
                    }
                }
            }
        })
        .await
        .expect("state event did not arrive over the relay");

        assert_eq!(received.table, "keys");
        assert_eq!(received.record_id, "abc123");
        assert_eq!(received.content.as_deref(), Some(content.as_slice()));
    }
}
