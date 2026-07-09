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
//!
//! Rollback protection: each event carries the signed `created_at`, and the consumer keeps a persisted
//! per-d-tag high-water-mark (keep-core `state_versions`), rejecting anything not strictly newer, so an
//! untrusted relay cannot replay a stale record/tombstone to roll a synced standby back. Residual risks
//! it does NOT cover (untrusted-relay + no-liveness model): a relay may still WITHHOLD a newer record or
//! a tombstone (keeping a revoked key live), and on FIRST sync it may serve an arbitrarily old but
//! validly-signed version (TOFU) -- detecting omission needs a signed cluster manifest/epoch.
//!
//! Operational requirement: the active node's wall clock must be monotonic and must not regress below
//! any `created_at` it has already published, because each per-d-tag mark only advances, so a forward
//! clock jump followed by a correction makes the consumer reject legitimate newer writes until wall-clock
//! catches up. Seeding the publisher floor from stored marks covers a promoted standby, but not a live
//! active whose own clock regresses.
use std::sync::Arc;

use nostr_sdk::prelude::*;
use tokio::sync::{broadcast, mpsc, Mutex};

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
    // Validate role before connecting: an unrecognized value (e.g. a "stanby" typo) must NOT silently
    // fall through to active, which would start a second publisher under the shared identity and cause
    // split-brain last-write-wins updates.
    if role != "active" && role != "standby" {
        return Err(format!(
            "invalid KEEP_STATE_ROLE {role:?}: expected \"active\" or \"standby\""
        ));
    }

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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How far ahead of wall-clock a published `created_at` may drift before we warn. Same-second bumps
/// drift only ~1-2s; a much larger gap means the seeded floor is ahead of wall-clock (a clock
/// regression), which a relay enforcing a NIP-11 `created_at_upper_limit` may reject.
const MAX_FUTURE_DRIFT_SECS: u64 = 60;

/// Compute the strictly-monotonic per-d-tag `created_at` for the next publish. `last` is the in-memory
/// per-d-tag high-water-mark, seeded at startup from the persisted floor (see `spawn_publisher`). A new
/// slot starts at `floor`; each write returns `now` unless that is not strictly greater than the last
/// timestamp, in which case it bumps to `last + 1` (`saturating_add` so it cannot overflow).
fn next_ts(
    last: &mut std::collections::HashMap<String, u64>,
    dtag: &str,
    floor: u64,
    now: u64,
) -> u64 {
    let slot = last.entry(dtag.to_string()).or_insert(floor);
    let ts = now.max(slot.saturating_add(1));
    *slot = ts;
    ts
}

async fn spawn_publisher(keep: Arc<Mutex<Keep>>, client: Client, identity: Keys) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Change>();
    keep.lock()
        .await
        .set_state_publisher(Arc::new(ChannelPublisher { tx }));

    // Seed the per-d-tag monotonic floor from the highest mark this node has already persisted. On a
    // promoted standby (restarted as active) whose stored marks were inflated above wall-clock
    // (same-second bumps) or under inter-node clock skew, starting from 0 could publish a created_at
    // <= a mark standbys already applied and be rejected; seeding guarantees the first publish for any
    // d-tag is strictly greater than every previously-applied mark.
    let floor = match keep.lock().await.max_state_version() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "keep-state: could not read persisted high-water floor, seeding from 0: {e}"
            );
            0
        }
    };

    tokio::spawn(async move {
        // `last_ts` is an in-memory per-d-tag high-water-mark seeded from `floor` (the persisted mark).
        // Within a run it guarantees strict per-d-tag monotonicity of created_at: a record and its
        // immediate delete (or two rapid writes) must not collide on the same second, or the relay's
        // created_at dedup could keep the wrong one and the standby's rollback guard would reject the
        // newer as "not newer". Same-second writes bump to last+1; otherwise wall-clock is used.
        let mut last_ts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        while let Some(change) = rx.recv().await {
            let dtag = match &change {
                Change::Record { table, id, .. } | Change::Delete { table, id } => {
                    format!("{table}:{id}")
                }
            };
            let now = now_secs();
            let ts = next_ts(&mut last_ts, &dtag, floor, now);
            // A created_at far ahead of wall-clock (a floor seeded after a clock regression, or a long
            // same-second burst) risks a strict relay rejecting it as too-far-future. Surface the drift
            // so a rejection below is explainable.
            if ts > now.saturating_add(MAX_FUTURE_DRIFT_SECS) {
                tracing::warn!(
                    dtag = ?dtag,
                    created_at = ts,
                    now,
                    "keep-state: created_at is far ahead of wall-clock; a relay enforcing a created_at_upper_limit may reject this event"
                );
            }
            let event = match &change {
                Change::Record {
                    table,
                    id,
                    encrypted,
                } => state_record_event(&identity, table, id, encrypted, ts),
                Change::Delete { table, id } => state_tombstone_event(&identity, table, id, ts),
            };
            match event {
                Ok(ev) => match client.send_event(&ev).await {
                    // No relay accepted it -- rejected (e.g. NIP-01 "invalid: created_at too far off")
                    // or unreachable. It did NOT replicate; log loudly instead of losing it silently.
                    Ok(out) if out.success.is_empty() => tracing::error!(
                        dtag = ?dtag,
                        created_at = ts,
                        failed = ?out.failed,
                        "keep-state publish accepted by NO relay; record did not replicate"
                    ),
                    // Replicated, but some relay still said no. Not loss today (`spawn` adds exactly one
                    // relay, so this cannot fire), yet the reasons must never be silently discarded.
                    Ok(out) if !out.failed.is_empty() => tracing::warn!(
                        dtag = ?dtag,
                        created_at = ts,
                        failed = ?out.failed,
                        "keep-state publish rejected by some relays"
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("keep-state publish failed: {e}"),
                },
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
    // Take the notifications receiver BEFORE subscribing: the REQ returns the standby's backfill (the
    // already-stored addressable records), and those can be broadcast before a receiver taken later
    // exists, silently dropping vault state a starting standby needs.
    let mut notifications = client.notifications();
    client
        .subscribe(filter, None)
        .await
        .map_err(|e| format!("state relay subscribe failed: {e}"))?;

    tokio::spawn(async move {
        // Keep `client` owned by the task: its pool is ref-counted and shuts the relay down when the
        // last handle drops, so letting it fall out of scope here would silently kill the subscription.
        let _client = client;
        loop {
            let notification = match notifications.recv().await {
                Ok(n) => n,
                // A lagged consumer has only missed already-replaced records; the relay still holds the
                // latest per d-tag, so skip the gap and keep consuming rather than exiting for good.
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("keep-state consumer lagged, skipped {n} notifications");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            };
            if let RelayPoolNotification::Event { event, .. } = notification {
                match parse_state_event(&identity, &event) {
                    Ok(Some(rec)) => {
                        let k = keep.lock().await;
                        let outcome = match rec.content {
                            Some(bytes) => k.apply_replicated_record(
                                &rec.table,
                                &rec.record_id,
                                &bytes,
                                rec.created_at,
                            ),
                            None => k.apply_replicated_delete(
                                &rec.table,
                                &rec.record_id,
                                rec.created_at,
                            ),
                        };
                        match outcome {
                            Ok(true) => {}
                            // Not strictly newer than what we already applied: a stale or replayed event
                            // (rollback attempt from an untrusted relay). Ignore it, but record it.
                            Ok(false) => tracing::warn!(
                                table = %rec.table,
                                created_at = rec.created_at,
                                "keep-state: ignored stale/replayed event (rollback guard)"
                            ),
                            Err(e) => {
                                tracing::warn!(table = %rec.table, "keep-state apply failed: {e}")
                            }
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
    use std::collections::HashMap;

    #[test]
    fn next_ts_is_strictly_monotonic_per_dtag() {
        let mut last: HashMap<String, u64> = HashMap::new();

        // (a) first write for a d-tag with floor 0 returns wall-clock.
        assert_eq!(next_ts(&mut last, "keys:a", 0, 100), 100);
        // (b) a second write in the same wall-clock second bumps to last+1.
        assert_eq!(next_ts(&mut last, "keys:a", 0, 100), 101);
        // (c) a later write with wall-clock advanced past the mark uses wall-clock.
        assert_eq!(next_ts(&mut last, "keys:a", 0, 500), 500);
        // (d) an independent d-tag has its own slot and does not interfere.
        assert_eq!(next_ts(&mut last, "keys:b", 0, 100), 100);
        assert_eq!(next_ts(&mut last, "keys:a", 0, 500), 501);
        // (e) a seeded floor above wall-clock produces floor+1 (the promotion case).
        assert_eq!(next_ts(&mut last, "keys:c", 1_000, 100), 1_001);
    }

    // The publisher warns when a computed created_at lands more than `MAX_FUTURE_DRIFT_SECS` ahead of
    // wall-clock, because a relay enforcing a NIP-11 `created_at_upper_limit` may reject it. Pin both
    // sides of that threshold: routine same-second bumps must not trip it, a seeded floor must.
    #[test]
    fn only_a_far_future_floor_trips_the_drift_threshold() {
        let mut last: HashMap<String, u64> = HashMap::new();
        let now = 1_000_000;

        // A burst of same-second writes drifts one second per write, so it stays well inside the
        // threshold -- the warning cannot false-positive on ordinary collision bumps.
        for _ in 0..10 {
            assert!(next_ts(&mut last, "keys:a", 0, now) <= now + MAX_FUTURE_DRIFT_SECS);
        }

        // A floor seeded above wall-clock (promoted standby, or a clock regression) pushes created_at
        // past the threshold: exactly the case the warning exists to surface.
        let ts = next_ts(&mut last, "keys:b", now + MAX_FUTURE_DRIFT_SECS, now);
        assert!(ts > now + MAX_FUTURE_DRIFT_SECS);
    }

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
        // Create the active vault, then drop it so its redb handle releases the
        // file lock before copying: Windows refuses to copy a file another
        // handle holds open, unlike Unix. Reopen the active afterward.
        Keep::create_with_params(&path_a, "vaultpass", fast).unwrap();
        std::fs::create_dir_all(&path_b).unwrap();
        std::fs::copy(path_a.join("keep.hdr"), path_b.join("keep.hdr")).unwrap();
        std::fs::copy(path_a.join("keep.db"), path_b.join("keep.db")).unwrap();
        let mut active = Keep::open(&path_a).unwrap();
        active.unlock("vaultpass").unwrap();
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
