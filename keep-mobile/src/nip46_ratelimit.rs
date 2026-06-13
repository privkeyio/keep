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
const GLOBAL_REQUEST_HISTORY_MAX_SIZE: usize = 200;
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

        // Per-client backoff.
        if let Some(c) = clients.get(&client_pubkey) {
            if now < c.backoff_until {
                return true;
            }
        }

        // Bound the tracked-client set, evicting the least-recently-seen.
        if clients.len() >= MAX_TRACKED_CLIENTS && !clients.contains_key(&client_pubkey) {
            if let Some(oldest) = clients
                .iter()
                .min_by_key(|(_, c)| c.last_seen)
                .map(|(k, _)| k.clone())
            {
                clients.remove(&oldest);
            }
        }

        let client = clients.entry(client_pubkey).or_default();
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
        client.last_seen = now;

        if global_history.len() >= GLOBAL_REQUEST_HISTORY_MAX_SIZE {
            global_history.pop_front();
        }
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
    fn reset_consecutive_is_callable_and_limiter_recovers() {
        let limiter = Nip46BunkerRateLimiter::new();
        for _ in 0..MAX_REQUESTS_PER_WINDOW {
            limiter.is_rate_limited("a".into(), 1000);
        }
        assert!(limiter.is_rate_limited("a".into(), 1000));
        limiter.reset_consecutive("a".into());
        // Well past both the per-client window and the max backoff, the client
        // is served again.
        assert!(
            !limiter.is_rate_limited("a".into(), 1000 + RATE_LIMIT_WINDOW_MS + BACKOFF_MAX_MS + 1)
        );
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
