// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! NIP-46 bunker request rate limiting: a global cap across all connected
//! clients, a per-client sliding window, and per-client exponential backoff.
//! In-memory and monotonic (the caller supplies `elapsedRealtime`). Faithful
//! port of keep-android `BunkerService.isRateLimited`. The in-flight concurrency
//! cap stays on the Android side -- it bounds pending approval activities, a UI
//! concern, not a request rate.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

const RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const MAX_REQUESTS_PER_WINDOW: usize = 30;
const BACKOFF_BASE_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 60_000;
const BACKOFF_MAX_EXPONENT: u32 = 6;
const GLOBAL_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const GLOBAL_MAX_REQUESTS_PER_WINDOW: usize = 100;
const MAX_TRACKED_CLIENTS: usize = 1000;

#[derive(Default)]
struct ClientState {
    history: Vec<u64>,
    backoff_until: u64,
    consecutive: u32,
    last_seen: u64,
}

#[derive(Default)]
struct State {
    global_history: VecDeque<u64>,
    clients: HashMap<String, ClientState>,
}

/// Per-client + global rate limiter for the mobile NIP-46 bunker. Gates each
/// incoming request before it reaches the approval flow.
#[derive(uniffi::Object)]
pub struct Nip46BunkerRateLimiter {
    state: Mutex<State>,
}

impl Default for Nip46BunkerRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl Nip46BunkerRateLimiter {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }

    /// Returns true if the request should be rejected. Records the request when
    /// allowed; trips per-client exponential backoff when the per-client window
    /// is exceeded. `now_elapsed_ms` is the monotonic clock.
    pub fn is_rate_limited(&self, client_pubkey: String, now_elapsed_ms: u64) -> bool {
        let now = now_elapsed_ms;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let State {
            global_history,
            clients,
        } = &mut *state;

        // Global window first.
        let global_cutoff = now.saturating_sub(GLOBAL_RATE_LIMIT_WINDOW_MS);
        while global_history.front().is_some_and(|&t| t < global_cutoff) {
            global_history.pop_front();
        }
        if global_history.len() >= GLOBAL_MAX_REQUESTS_PER_WINDOW {
            return true;
        }

        // Per-client backoff. Refresh last_seen on every request that passes the
        // global cap so a backed-off client is not the eviction victim, which
        // would reset its penalty (see the eviction guard below).
        if let Some(c) = clients.get_mut(&client_pubkey) {
            c.last_seen = now;
            if now < c.backoff_until {
                return true;
            }
        }

        // Bound the tracked-client set. Evict the least-recently-seen client
        // that is not currently in backoff, so attacker pubkey churn cannot
        // flush an active penalty; fall back to the overall least-recently-seen
        // only if every tracked client is still backing off.
        if clients.len() >= MAX_TRACKED_CLIENTS && !clients.contains_key(&client_pubkey) {
            let victim = clients
                .iter()
                .filter(|(_, c)| now >= c.backoff_until)
                .min_by_key(|(_, c)| c.last_seen)
                .map(|(k, _)| k.clone())
                .or_else(|| {
                    clients
                        .iter()
                        .min_by_key(|(_, c)| c.last_seen)
                        .map(|(k, _)| k.clone())
                });
            if let Some(oldest) = victim {
                clients.remove(&oldest);
            }
        }

        let client = clients.entry(client_pubkey).or_default();
        client.last_seen = now;
        let client_cutoff = now.saturating_sub(RATE_LIMIT_WINDOW_MS);
        client.history.retain(|&t| t >= client_cutoff);

        if client.history.len() >= MAX_REQUESTS_PER_WINDOW {
            let exponent = client.consecutive.min(BACKOFF_MAX_EXPONENT);
            let backoff = (BACKOFF_BASE_MS << exponent).min(BACKOFF_MAX_MS);
            client.consecutive = client.consecutive.saturating_add(1);
            client.backoff_until = now.saturating_add(backoff);
            return true;
        }

        client.history.push(now);
        global_history.push_back(now);
        false
    }

    /// Reset a client's consecutive-violation counter after a successful
    /// approval, so its backoff starts fresh next time. Mirrors the reset in
    /// `respondToApproval`.
    pub fn reset_consecutive(&self, client_pubkey: String) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = state.clients.get_mut(&client_pubkey) {
            c.consecutive = 0;
        }
    }

    pub fn clear(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.global_history.clear();
        state.clients.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_per_client_limit() {
        let limiter = Nip46BunkerRateLimiter::new();
        for _ in 0..MAX_REQUESTS_PER_WINDOW {
            assert!(!limiter.is_rate_limited("a".into(), 1000));
        }
        // The next request in the same window trips the limit.
        assert!(limiter.is_rate_limited("a".into(), 1000));
    }

    #[test]
    fn per_client_window_resets() {
        let limiter = Nip46BunkerRateLimiter::new();
        for _ in 0..MAX_REQUESTS_PER_WINDOW {
            limiter.is_rate_limited("a".into(), 1000);
        }
        assert!(limiter.is_rate_limited("a".into(), 1000));
        // After the window passes (and backoff), requests are allowed again.
        assert!(!limiter.is_rate_limited("a".into(), 1000 + RATE_LIMIT_WINDOW_MS + BACKOFF_MAX_MS));
    }

    #[test]
    fn backoff_escalates_and_blocks() {
        let limiter = Nip46BunkerRateLimiter::new();
        for _ in 0..MAX_REQUESTS_PER_WINDOW {
            limiter.is_rate_limited("a".into(), 1000);
        }
        // First violation -> backoff BACKOFF_BASE_MS (1s). Still blocked at +500ms.
        assert!(limiter.is_rate_limited("a".into(), 1000));
        assert!(limiter.is_rate_limited("a".into(), 1500));
    }

    #[test]
    fn global_cap_blocks_across_clients() {
        let limiter = Nip46BunkerRateLimiter::new();
        // Spread requests across many clients so per-client limits never trip,
        // but the global cap (100) does.
        for i in 0..GLOBAL_MAX_REQUESTS_PER_WINDOW {
            assert!(!limiter.is_rate_limited(format!("client-{i}"), 1000));
        }
        assert!(limiter.is_rate_limited("client-new".into(), 1000));
    }

    #[test]
    fn reset_consecutive_shortens_subsequent_backoff() {
        // Escalate the same client to a high consecutive count in two limiters,
        // reset one of them, then show the reset limiter recovers while the
        // other is still serving a long (capped) backoff. The window fill is
        // spread across ~29s so the per-client window drops below the limit
        // before a full 60s backoff would expire, isolating backoff length from
        // the window check. A no-op `reset_consecutive` would make both
        // limiters behave identically and fail the final assertions.
        fn escalate(limiter: &Nip46BunkerRateLimiter) {
            for _ in 0..MAX_REQUESTS_PER_WINDOW {
                limiter.is_rate_limited("a".into(), 1000);
            }
            // Trip the window repeatedly, each call landing exactly when the
            // previous backoff expires (so it isn't swallowed by the backoff
            // early-return) while the t=1000 window is still full. Backoff
            // doubles 1->2->4->8->16->32s, all inside the 60s window, climbing
            // `consecutive` to the exponent cap.
            let mut t = 1000u64;
            let mut applied = BACKOFF_BASE_MS;
            for _ in 0..BACKOFF_MAX_EXPONENT {
                assert!(limiter.is_rate_limited("a".into(), t));
                t = t.saturating_add(applied);
                applied = (applied * 2).min(BACKOFF_MAX_MS);
            }
        }

        let with_reset = Nip46BunkerRateLimiter::new();
        let without_reset = Nip46BunkerRateLimiter::new();
        escalate(&with_reset);
        escalate(&without_reset);
        with_reset.reset_consecutive("a".into());

        let t0 = 1000 + RATE_LIMIT_WINDOW_MS + BACKOFF_MAX_MS + 1;
        let step = 1_000;
        for limiter in [&with_reset, &without_reset] {
            for i in 0..MAX_REQUESTS_PER_WINDOW as u64 {
                limiter.is_rate_limited("a".into(), t0 + i * step);
            }
        }
        let trip = t0 + (MAX_REQUESTS_PER_WINDOW as u64 - 1) * step;
        assert!(with_reset.is_rate_limited("a".into(), trip));
        assert!(without_reset.is_rate_limited("a".into(), trip));

        // Probe where the per-client window has aged below the limit but a full
        // 60s backoff is still active.
        let probe = trip + 32_000;
        assert!(
            !with_reset.is_rate_limited("a".into(), probe),
            "reset client should recover on the short base backoff"
        );
        assert!(
            without_reset.is_rate_limited("a".into(), probe),
            "un-reset client should still be in the long escalated backoff"
        );
    }

    #[test]
    fn eviction_is_bounded_and_drops_least_recently_seen() {
        let limiter = Nip46BunkerRateLimiter::new();
        // Register MAX_TRACKED_CLIENTS unique clients, advancing the clock each
        // global window so the global cap does not block registrations, and
        // giving each client a distinct, increasing last_seen.
        let mut t = 0u64;
        for i in 0..MAX_TRACKED_CLIENTS {
            if i % GLOBAL_MAX_REQUESTS_PER_WINDOW == 0 {
                t += GLOBAL_RATE_LIMIT_WINDOW_MS + 1;
            }
            t += 1;
            assert!(!limiter.is_rate_limited(format!("c{i}"), t));
        }
        // Re-touch c0 so it is no longer the least-recently-seen entry.
        let later = t + GLOBAL_RATE_LIMIT_WINDOW_MS + 1;
        assert!(!limiter.is_rate_limited("c0".into(), later));
        // A newcomer must evict exactly one entry (c1, the earliest last_seen),
        // keeping the table bounded at the cap.
        assert!(!limiter.is_rate_limited("newcomer".into(), later + 1));

        let state = limiter.state.lock().unwrap();
        assert_eq!(state.clients.len(), MAX_TRACKED_CLIENTS);
        assert!(state.clients.contains_key("c0"));
        assert!(state.clients.contains_key("newcomer"));
        assert!(!state.clients.contains_key("c1"));
    }

    #[test]
    fn eviction_spares_backed_off_client_over_idle_lru() {
        // White-box: reaching MAX_TRACKED_CLIENTS through the global cap takes
        // far longer than any backoff lasts, so construct a full table directly
        // with the overall least-recently-seen client (c0) currently in backoff.
        let limiter = Nip46BunkerRateLimiter::new();
        let now = 1_000_000u64;
        {
            let mut state = limiter.state.lock().unwrap();
            for i in 0..MAX_TRACKED_CLIENTS {
                let c = ClientState {
                    last_seen: i as u64, // c0 is the oldest, c{N-1} the newest
                    backoff_until: if i == 0 { now + 10_000 } else { 0 }, // c0 still backing off
                    ..Default::default()
                };
                state.clients.insert(format!("c{i}"), c);
            }
        }
        // A newcomer triggers eviction. Plain LRU would drop c0; the fix must
        // spare the backed-off c0 and instead drop c1, the oldest client that
        // is not currently in backoff.
        assert!(!limiter.is_rate_limited("newcomer".into(), now));

        let state = limiter.state.lock().unwrap();
        assert_eq!(state.clients.len(), MAX_TRACKED_CLIENTS);
        assert!(
            state.clients.contains_key("c0"),
            "backed-off least-recently-seen client must be spared"
        );
        assert!(
            !state.clients.contains_key("c1"),
            "oldest non-backed-off client should be evicted instead"
        );
        assert!(state.clients.contains_key("newcomer"));
    }

    #[test]
    fn blank_clients_are_tracked_independently() {
        let limiter = Nip46BunkerRateLimiter::new();
        for _ in 0..MAX_REQUESTS_PER_WINDOW {
            assert!(!limiter.is_rate_limited("a".into(), 1000));
        }
        assert!(limiter.is_rate_limited("a".into(), 1000));
        // A different client is unaffected.
        assert!(!limiter.is_rate_limited("b".into(), 1000));
    }
}
