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
//! untrusted relay cannot replay a stale record/tombstone to roll a synced standby back. The consumer
//! also rejects an event dated implausibly far ahead of local wall-clock, so a holder of the cluster key
//! cannot stamp a mark near `u64::MAX` and freeze a record forever; a bounded suppression (up to the
//! ~300s future margin) remains but self-heals once wall-clock passes it. Residual risks
//! it does NOT cover (untrusted-relay + no-liveness model): a relay may still WITHHOLD a newer record or
//! a tombstone (keeping a revoked key live), and on FIRST sync it may serve an arbitrarily old but
//! validly-signed version (TOFU) -- detecting omission needs a signed cluster manifest/epoch.
//!
//! Operational requirement: the active node's wall clock must be monotonic and must not regress below
//! any `created_at` it has already published, because each per-d-tag mark only advances, so a forward
//! clock jump followed by a correction makes the consumer reject legitimate newer writes until wall-clock
//! catches up. Seeding the publisher floor from stored marks covers a promoted standby, but not a live
//! active whose own clock regresses.
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use nostr_sdk::prelude::*;
use tokio::sync::{broadcast, Mutex, Notify};

use keep_core::{Keep, ReplicatedApply, StatePublisher};
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

/// How long the publish task waits after a failed publish sweep before retrying the still-pending
/// changes; it wakes early if a new write arrives. The pending set is coalesced per d-tag, so a
/// sustained outage cannot grow it beyond one entry per record.
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

/// [`StatePublisher`] that records each write into a coalescing pending map keyed by d-tag and wakes the
/// publish task. `on_*` run inside the storage write path, so they only take a brief lock -- never block,
/// never touch the relay. Coalescing (the latest change per record wins) bounds the map by RECORD COUNT,
/// not write rate, so a slow/down relay cannot grow it without bound; and a delete or a write-once record
/// is HELD until it is sent rather than dropped (a dropped tombstone would keep a revoked key live).
struct ChannelPublisher {
    pending: Arc<StdMutex<HashMap<String, Change>>>,
    notify: Arc<Notify>,
}

impl StatePublisher for ChannelPublisher {
    fn on_record(&self, table: &str, record_id: &str, encrypted: &[u8]) {
        self.pending.lock().unwrap().insert(
            format!("{table}:{record_id}"),
            Change::Record {
                table: table.to_string(),
                id: record_id.to_string(),
                encrypted: encrypted.to_vec(),
            },
        );
        self.notify.notify_one();
    }
    fn on_delete(&self, table: &str, record_id: &str) {
        self.pending.lock().unwrap().insert(
            format!("{table}:{record_id}"),
            Change::Delete {
                table: table.to_string(),
                id: record_id.to_string(),
            },
        );
        self.notify.notify_one();
    }
}

/// Re-queue a change that failed to publish, for the next retry sweep. Coalesces: if a NEWER change for
/// the same d-tag arrived while we were sending, keep the newer one -- it supersedes this stale attempt.
fn requeue(pending: &StdMutex<HashMap<String, Change>>, dtag: String, change: Change) {
    pending.lock().unwrap().entry(dtag).or_insert(change);
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

/// How a relay pool responded to a publish. `RelayPool::send_event_to` returns `Ok(output)` even when
/// every relay said no: a relay replying `OK: false` (including NIP-01 `invalid:` prefixes) lands in
/// `failed`, leaving `success` empty. Classifying on the outer `Result` alone therefore reads a
/// rejection as a success, which is the silent replication loss this exists to prevent.
#[derive(Debug, PartialEq, Eq)]
enum SendOutcome {
    /// Every relay accepted the event.
    Accepted,
    /// At least one relay accepted, but others rejected it.
    PartiallyRejected,
    /// No relay accepted it: the record did NOT replicate.
    NoRelayAccepted,
}

fn classify_send(out: &Output<EventId>) -> SendOutcome {
    if out.success.is_empty() {
        SendOutcome::NoRelayAccepted
    } else if !out.failed.is_empty() {
        SendOutcome::PartiallyRejected
    } else {
        SendOutcome::Accepted
    }
}

/// Compute the strictly-monotonic per-d-tag `created_at` for the next publish. `last` is the in-memory
/// per-d-tag high-water-mark. Each write returns `now` unless that is not strictly greater than the last
/// timestamp, in which case it bumps to `last + 1` (`saturating_add` so it cannot overflow).
///
/// `floor` seeds a d-tag's slot ONLY the first time that d-tag is seen (see `spawn_publisher`, which
/// reads the record's persisted mark lazily and passes a don't-care `0` once the slot is cached). Keep
/// it that way: applying `floor` to an already-cached slot would let a stale `0` clamp `created_at` back
/// to wall-clock and silently break the strict per-d-tag monotonicity the rollback guard depends on.
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
    let pending: Arc<StdMutex<HashMap<String, Change>>> = Arc::new(StdMutex::new(HashMap::new()));
    let notify = Arc::new(Notify::new());
    keep.lock()
        .await
        .set_state_publisher(Arc::new(ChannelPublisher {
            pending: pending.clone(),
            notify: notify.clone(),
        }));

    tokio::spawn(async move {
        // `last_ts` is an in-memory per-d-tag high-water-mark guaranteeing strict per-d-tag monotonicity
        // of created_at within a run: a record and its immediate delete (or two rapid writes) must not
        // collide on the same second, or the relay's created_at dedup could keep the wrong one and the
        // standby's rollback guard would reject the newer as "not newer". Same-second writes bump to
        // last+1. Each d-tag's floor is seeded on first sight from THAT record's OWN persisted mark (per
        // record, not a global maximum), so a quiet record is not future-dated to the newest record's
        // timestamp -- which is what a promoted standby, whose marks may be inflated above wall-clock,
        // needs to stay strictly greater than what standbys already applied.
        //
        // The floor therefore covers only this record's own mark. A record this node never applied seeds
        // from wall-clock, so if a peer holds a FUTURE-dated mark for it (this node was desynced while a
        // prior active published it under a fast clock), that peer's rollback guard drops our publish as
        // "not newer". Accepted deliberately: a global maximum would cover that case only by inflating
        // every d-tag, which is the drift this seeding exists to remove, and the residual needs a real
        // clock regression -- already an operational requirement above.
        let mut last_ts: HashMap<String, u64> = HashMap::new();
        loop {
            // Drain the coalesced pending set (the latest change per d-tag). Empty -> wait to be woken.
            let batch: Vec<(String, Change)> = { pending.lock().unwrap().drain().collect() };
            if batch.is_empty() {
                notify.notified().await;
                continue;
            }

            let mut failed = false;
            for (dtag, change) in batch {
                let (table, id) = match &change {
                    Change::Record { table, id, .. } | Change::Delete { table, id } => (table, id),
                };
                let now = now_secs();
                // Read this record's own persisted mark only on first sight (then cached in last_ts).
                let floor = if last_ts.contains_key(&dtag) {
                    0
                } else {
                    match keep.lock().await.state_version(table, id) {
                        Ok(v) => v.unwrap_or(0),
                        Err(e) => {
                            tracing::warn!(dtag = ?dtag, "keep-state: could not read persisted mark for d-tag, seeding from 0: {e}");
                            0
                        }
                    }
                };
                let ts = next_ts(&mut last_ts, &dtag, floor, now);
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
                        Ok(out) => match classify_send(&out) {
                            SendOutcome::Accepted => {}
                            // Replicated, but some relay said no; never discard the reasons.
                            SendOutcome::PartiallyRejected => tracing::warn!(
                                dtag = ?dtag,
                                created_at = ts,
                                failed = ?out.failed,
                                "keep-state publish rejected by some relays"
                            ),
                            // No relay accepted it (unreachable, or rejected e.g. as future-dated). Keep it
                            // pending and retry after a backoff; a re-publish recomputes a fresh created_at,
                            // so a future-dating rejection self-heals as wall-clock advances.
                            SendOutcome::NoRelayAccepted => {
                                tracing::warn!(
                                    dtag = ?dtag,
                                    created_at = ts,
                                    failed = ?out.failed,
                                    "keep-state publish accepted by no relay; will retry"
                                );
                                requeue(&pending, dtag, change);
                                failed = true;
                            }
                        },
                        // Transport error (relay unreachable): keep it pending and retry.
                        Err(e) => {
                            tracing::warn!(dtag = ?dtag, "keep-state publish transport error; will retry: {e}");
                            requeue(&pending, dtag, change);
                            failed = true;
                        }
                    },
                    // A build error won't fix on retry; drop it loudly rather than spin forever.
                    Err(e) => {
                        tracing::error!(dtag = ?dtag, "keep-state event build failed; dropped: {e}")
                    }
                }
            }

            if failed {
                // Back off before the next sweep, waking early if a new write arrives. The pending set
                // stays bounded by record count (coalesced) throughout a sustained outage.
                let _ = tokio::time::timeout(RETRY_BACKOFF, notify.notified()).await;
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
                        let now = now_secs();
                        let outcome = match rec.content {
                            Some(bytes) => k.apply_replicated_record(
                                &rec.table,
                                &rec.record_id,
                                &bytes,
                                rec.created_at,
                                now,
                            ),
                            None => k.apply_replicated_delete(
                                &rec.table,
                                &rec.record_id,
                                rec.created_at,
                                now,
                            ),
                        };
                        // Debug-format the event-supplied table and record id: neither is charset-
                        // constrained until `apply_*` checks the allowlist, so Display would let a
                        // control character forge log lines.
                        match outcome {
                            Ok(ReplicatedApply::Applied) => {}
                            // Not strictly newer than what we already applied: a stale or replayed event
                            // (rollback attempt from an untrusted relay). Ignore it, but record it.
                            Ok(ReplicatedApply::IgnoredStale) => tracing::warn!(
                                table = ?rec.table,
                                record_id = ?rec.record_id,
                                created_at = rec.created_at,
                                "keep-state: ignored stale/replayed event (rollback guard)"
                            ),
                            // created_at beyond the future bound. Two causes: a cluster-key poison attempt
                            // (would otherwise freeze this record's mark), OR THIS node's clock is far
                            // behind its peers -- in which case every legitimate event is rejected until
                            // the clock is corrected, so check NTP before assuming an attack. Loud either
                            // way; mark untouched, so it self-heals once wall-clock passes created_at.
                            Ok(ReplicatedApply::RejectedFuture) => tracing::error!(
                                table = ?rec.table,
                                record_id = ?rec.record_id,
                                created_at = rec.created_at,
                                now,
                                "keep-state: rejected event past the future bound (cluster-key poison attempt, or this node's clock is behind its peers -- check NTP)"
                            ),
                            Err(e) => tracing::warn!(
                                table = ?rec.table,
                                record_id = ?rec.record_id,
                                "keep-state apply failed: {e}"
                            ),
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
    fn pending_coalesces_latest_change_per_dtag() {
        // A slow/down relay must not grow the queue by write RATE: repeated writes to one record collapse
        // to a single pending entry, and a delete supersedes an earlier record write, so a tombstone is
        // never lost behind a stale record.
        let pending = Arc::new(StdMutex::new(HashMap::new()));
        let p = ChannelPublisher {
            pending: pending.clone(),
            notify: Arc::new(Notify::new()),
        };
        p.on_record("keys", "aa", b"v1");
        p.on_record("keys", "aa", b"v2");
        p.on_delete("keys", "aa");
        p.on_record("keys", "bb", b"x");
        let map = pending.lock().unwrap();
        assert_eq!(map.len(), 2); // aa + bb (coalesced), not four
        assert!(matches!(map.get("keys:aa"), Some(Change::Delete { .. }))); // latest for aa is the delete
        assert!(matches!(map.get("keys:bb"), Some(Change::Record { .. })));
    }

    #[test]
    fn requeue_does_not_clobber_a_newer_pending_change() {
        // A failed send re-queues what it tried, but if a NEWER write for that record arrived while it was
        // in flight, the newer one must win -- else a re-queued stale record could resurrect a just-
        // deleted key.
        let pending = Arc::new(StdMutex::new(HashMap::new()));
        pending.lock().unwrap().insert(
            "keys:aa".to_string(),
            Change::Delete {
                table: "keys".into(),
                id: "aa".into(),
            },
        );
        requeue(
            &pending,
            "keys:aa".to_string(),
            Change::Record {
                table: "keys".into(),
                id: "aa".into(),
                encrypted: b"stale".to_vec(),
            },
        );
        assert!(matches!(
            pending.lock().unwrap().get("keys:aa"),
            Some(Change::Delete { .. })
        ));
    }

    // A relay that rejects an event (NIP-01 `OK: false`, e.g. an `invalid:` far-future `created_at`)
    // still leaves `send_event` returning `Ok(output)` -- the rejection only shows up as an empty
    // `success` set. Pin the classification, because reading `Ok(_)` as success is the silent
    // replication loss this whole path exists to surface.
    #[test]
    fn a_send_no_relay_accepted_is_not_a_success() {
        let out = |success: &[&str], failed: &[&str]| Output {
            val: EventId::from_byte_array([0u8; 32]),
            success: success
                .iter()
                .map(|u| RelayUrl::parse(u).unwrap())
                .collect(),
            failed: failed
                .iter()
                .map(|u| {
                    (
                        RelayUrl::parse(u).unwrap(),
                        "invalid: event creation date is too far off from the current time".into(),
                    )
                })
                .collect(),
        };
        let (a, b) = ("wss://a.example", "wss://b.example");

        // Every relay rejected: the record did not replicate, even though the call returned `Ok`.
        assert_eq!(
            classify_send(&out(&[], &[a, b])),
            SendOutcome::NoRelayAccepted
        );
        // No relay reachable at all: also did not replicate.
        assert_eq!(classify_send(&out(&[], &[])), SendOutcome::NoRelayAccepted);
        // Accepted somewhere, rejected elsewhere: replicated, but the reasons must not be discarded.
        assert_eq!(
            classify_send(&out(&[a], &[b])),
            SendOutcome::PartiallyRejected
        );
        assert_eq!(classify_send(&out(&[a, b], &[])), SendOutcome::Accepted);
    }

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
