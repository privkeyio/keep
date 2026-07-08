// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
//! Keep-state replication over a Nostr relay (the keep-node keep-state-over-wisp feature).
//!
//! An ACTIVE node installs a [`StatePublisher`] on its vault storage and ships every replicated
//! vault-state write (keys / descriptors / relay configs) to the state relay as an addressable NIP-78
//! event under a SHARED cluster identity. A STANDBY subscribes to that identity, decrypts, and
//! reconstructs each record into its own storage, so a promoted standby serves the same keep secrets.
//! Single-writer: the active publishes, the standby consumes; roles flip on promotion (the node is
//! restarted with the new `KEEP_STATE_ROLE`).
use std::sync::Arc;

use nostr_sdk::prelude::*;
use tokio::sync::{mpsc, Mutex};

use keep_core::{Keep, StatePublisher};
use keep_frost_net::{
    parse_state_event, state_record_event, state_tombstone_event, KEEP_STATE_KIND,
};

/// A pending replication change, queued by the storage hook and drained by the publish task.
enum Change {
    Record {
        table: String,
        id: String,
        encrypted: Vec<u8>,
    },
    Delete {
        table: String,
        id: String,
    },
}

/// [`StatePublisher`] that enqueues each write to the async publish task. `on_*` run inside the
/// storage write path, so they only send on an unbounded channel -- never block, never touch the relay.
struct ChannelPublisher {
    tx: mpsc::UnboundedSender<Change>,
}

impl StatePublisher for ChannelPublisher {
    fn on_record(&self, table: &str, record_id: &str, encrypted: &[u8]) {
        let _ = self.tx.send(Change::Record {
            table: table.to_string(),
            id: record_id.to_string(),
            encrypted: encrypted.to_vec(),
        });
    }
    fn on_delete(&self, table: &str, record_id: &str) {
        let _ = self.tx.send(Change::Delete {
            table: table.to_string(),
            id: record_id.to_string(),
        });
    }
}

/// Load the shared cluster identity from `KEEP_STATE_IDENTITY` (an `nsec1...` bech32 or a 64-char hex
/// secret key). This key is a cluster secret distributed out-of-band to every node, like the shared
/// Vaultwarden JWT key.
pub fn load_state_identity() -> Result<Keys, String> {
    let raw = std::env::var("KEEP_STATE_IDENTITY")
        .map_err(|_| "KEEP_STATE_RELAY is set but KEEP_STATE_IDENTITY is missing".to_string())?;
    Keys::parse(raw.trim()).map_err(|e| format!("invalid KEEP_STATE_IDENTITY: {e}"))
}

/// Wire keep-state replication. `role` is `"active"` (publish local writes) or `"standby"` (consume +
/// reconstruct). Returns once connected; the publish/consume loop runs in a background task.
pub async fn spawn(
    keep: Arc<Mutex<Keep>>,
    relay_url: String,
    identity: Keys,
    role: &str,
) -> Result<(), String> {
    let client = Client::new(identity.clone());
    client
        .add_relay(&relay_url)
        .await
        .map_err(|e| format!("state relay add failed: {e}"))?;
    client.connect().await;

    if role == "standby" {
        spawn_consumer(keep, client, identity).await?;
    } else {
        spawn_publisher(keep, client, identity).await;
    }
    Ok(())
}

async fn spawn_publisher(keep: Arc<Mutex<Keep>>, client: Client, identity: Keys) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Change>();
    keep.lock()
        .await
        .set_state_publisher(Arc::new(ChannelPublisher { tx }));

    tokio::spawn(async move {
        while let Some(change) = rx.recv().await {
            let event = match &change {
                Change::Record {
                    table,
                    id,
                    encrypted,
                } => state_record_event(&identity, table, id, encrypted),
                Change::Delete { table, id } => state_tombstone_event(&identity, table, id),
            };
            match event {
                Ok(ev) => {
                    if let Err(e) = client.send_event(&ev).await {
                        tracing::warn!("keep-state publish failed: {e}");
                    }
                }
                Err(e) => tracing::warn!("keep-state event build failed: {e}"),
            }
        }
    });
}

async fn spawn_consumer(
    keep: Arc<Mutex<Keep>>,
    client: Client,
    identity: Keys,
) -> Result<(), String> {
    let filter = Filter::new()
        .author(identity.public_key())
        .kind(Kind::Custom(KEEP_STATE_KIND));
    client
        .subscribe(filter, None)
        .await
        .map_err(|e| format!("state relay subscribe failed: {e}"))?;

    tokio::spawn(async move {
        let mut notifications = client.notifications();
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event { event, .. } = notification {
                match parse_state_event(&identity, &event) {
                    Ok(Some(rec)) => {
                        let k = keep.lock().await;
                        let outcome = match rec.content {
                            Some(bytes) => {
                                k.apply_replicated_record(&rec.table, &rec.record_id, &bytes)
                            }
                            None => k.apply_replicated_delete(&rec.table, &rec.record_id),
                        };
                        if let Err(e) = outcome {
                            tracing::warn!(table = %rec.table, "keep-state apply failed: {e}");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!("keep-state parse failed: {e}"),
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_core::crypto::Argon2Params;
    use keep_core::{Keep, RelayConfig};
    use nostr_relay_builder::MockRelay;

    // Full end-to-end: an ACTIVE keep-web node writes vault state, it flows through a live relay, and a
    // STANDBY node reconstructs it AND reads it back decrypted. The two vaults share the data key (the
    // standby is a copy of the active's header + db), which is the real deployment invariant (one shared
    // vault password across the cluster), so this exercises the whole path -- storage hook -> publish ->
    // relay -> subscribe -> apply -> decrypt -- with no mocking of the pieces under test.
    #[tokio::test]
    async fn active_write_reaches_standby_end_to_end() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let identity = Keys::generate();

        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("active");
        let path_b = dir.path().join("standby");

        // Fast Argon2 params for the test (the production `TESTING` const is test-gated in keep-core).
        let fast = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let active = Keep::create_with_params(&path_a, "vaultpass", fast).unwrap();
        std::fs::create_dir_all(&path_b).unwrap();
        std::fs::copy(path_a.join("keep.hdr"), path_b.join("keep.hdr")).unwrap();
        std::fs::copy(path_a.join("keep.db"), path_b.join("keep.db")).unwrap();
        let mut standby = Keep::open(&path_b).unwrap();
        standby.unlock("vaultpass").unwrap();

        let active = Arc::new(Mutex::new(active));
        let standby = Arc::new(Mutex::new(standby));

        spawn(active.clone(), url.clone(), identity.clone(), "active")
            .await
            .unwrap();
        spawn(standby.clone(), url.clone(), identity.clone(), "standby")
            .await
            .unwrap();
        // Let both connections + the standby subscription settle before the write.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // The active writes a relay config -> storage hook -> publish. Empty on a fresh standby vault,
        // so a later Some(config) with the right group proves the record replicated AND decrypted.
        let group = [7u8; 32];
        let config = RelayConfig::new(group);
        assert!(standby
            .lock()
            .await
            .get_relay_config(&group)
            .unwrap()
            .is_none());
        active.lock().await.store_relay_config(&config).unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Ok(Some(c)) = standby.lock().await.get_relay_config(&group) {
                    return c;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("standby never reconstructed the replicated relay config");
        assert_eq!(got.group_pubkey, group);
    }
}
