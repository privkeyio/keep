// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use nostr_sdk::prelude::*;
use tokio::sync::broadcast;

use crate::error::{FrostNetError, Result};
use crate::pinned_transport::TlsPinning;

/// Transport seam between [`KfpNode`](super::KfpNode) and the relay layer. Moves
/// opaque, already-signed nostr [`Event`]s and [`Filter`]s only; all crypto
/// (event building, NIP-44/59, [`Keys`]) stays node-side. Each method folds the
/// underlying transport error into [`FrostNetError::Transport`] so callers get a
/// crate error directly.
///
/// Returns boxed futures rather than using `async fn` so the trait stays
/// object-safe (`Arc<dyn CosignTransport>`), mirroring
/// [`SigningHooks::approve_oprf_eval`](super::SigningHooks::approve_oprf_eval)
/// and avoiding an `async-trait` dependency.
pub trait CosignTransport: Send + Sync {
    fn send_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    fn subscribe<'a>(
        &'a self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    fn fetch_events<'a>(
        &'a self,
        filter: Filter,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Event>>> + Send + 'a>>;
    fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification>;
    /// Connection state of relays already in the pool. This does not dial or
    /// ping; it reads the status and stats the pool is already tracking.
    /// Transports with no relay sockets return an empty list.
    fn relay_health<'a>(&'a self) -> Pin<Box<dyn Future<Output = Vec<RelayHealth>> + Send + 'a>>;
}

/// One relay's connection state, as already tracked by the nostr pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayHealth {
    /// Pool URL without a trailing slash, so a caller can match its configured
    /// string after the same normalization.
    pub url: String,
    pub status: RelayHealthStatus,
    /// Unix milliseconds of the last successful connection. `0` if never.
    pub last_connected_ms: u64,
    /// Smoothed round trip in milliseconds, once the pool has enough samples.
    pub rtt_ms: Option<u64>,
}

/// Coarse relay status. The pool's eight states collapse to the three a
/// surface can show without re-implementing connection logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayHealthStatus {
    Connecting,
    Connected,
    Offline,
}

pub(crate) fn relay_health_from_parts(
    url: &RelayUrl,
    status: RelayStatus,
    connected_at_secs: u64,
    latency: Option<Duration>,
) -> RelayHealth {
    let status = match status {
        RelayStatus::Initialized
        | RelayStatus::Pending
        | RelayStatus::Connecting
        | RelayStatus::Sleeping => RelayHealthStatus::Connecting,
        RelayStatus::Connected => RelayHealthStatus::Connected,
        RelayStatus::Disconnected | RelayStatus::Terminated | RelayStatus::Banned => {
            RelayHealthStatus::Offline
        }
    };
    RelayHealth {
        url: url.as_str_without_trailing_slash().to_string(),
        status,
        last_connected_ms: connected_at_secs.saturating_mul(1_000),
        rtt_ms: latency.map(|delay| u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)),
    }
}

/// [`CosignTransport`] backed by a concrete `nostr_sdk::Client`.
pub(crate) struct NostrTransport {
    client: Client,
}

impl NostrTransport {
    /// Build the client, add the relays, connect, and wait (bounded) for at
    /// least one relay to reach `Connected`. Relay URLs are validated by the
    /// caller before this runs.
    ///
    /// With `pinning` set, the relay sockets enforce the SPKI pin inside their
    /// own TLS handshake (see [`crate::PinnedWebSocketTransport`]); without it
    /// they do standard CA validation only.
    pub(crate) async fn connect(
        keys: Keys,
        relays: &[String],
        proxy: Option<SocketAddr>,
        relay_opts: RelayOptions,
        pinning: Option<TlsPinning>,
    ) -> Result<Self> {
        let client = crate::pinned_transport::build_client(&keys, proxy, pinning)?;
        let relay_opts = crate::pinned_transport::with_proxy(relay_opts, proxy);

        for relay in relays {
            client
                .pool()
                .add_relay(relay, relay_opts.clone())
                .await
                .map_err(|e| {
                    FrostNetError::Transport(format!("Failed to add relay {relay}: {e}"))
                })?;
        }

        client.connect().await;

        crate::pinned_transport::wait_for_any_relay(&client, Duration::from_secs(10)).await?;

        Ok(Self { client })
    }
}

/// `Client::send_event` returns `Ok` even when every relay refused the event,
/// so a send counts only once at least one relay accepted it.
pub(crate) fn require_accepted(output: &Output<EventId>) -> std::result::Result<(), String> {
    if !output.success.is_empty() {
        return Ok(());
    }
    let reasons: Vec<String> = output
        .failed
        .iter()
        .map(|(url, why)| format!("{url}: {why}"))
        .collect();
    Err(format!(
        "no relay accepted the event ({})",
        if reasons.is_empty() {
            "no relays".to_string()
        } else {
            reasons.join("; ")
        }
    ))
}

impl CosignTransport for NostrTransport {
    fn send_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let output = self
                .client
                .send_event(event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;
            require_accepted(&output).map_err(FrostNetError::Transport)
        })
    }

    fn subscribe<'a>(
        &'a self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.client
                .subscribe(filter, None)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;
            Ok(())
        })
    }

    fn fetch_events<'a>(
        &'a self,
        filter: Filter,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Event>>> + Send + 'a>> {
        Box::pin(async move {
            self.client
                .fetch_events(filter, timeout)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))
                .map(|evs| evs.into_iter().collect())
        })
    }

    fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    fn relay_health<'a>(&'a self) -> Pin<Box<dyn Future<Output = Vec<RelayHealth>> + Send + 'a>> {
        Box::pin(async move {
            let mut health: Vec<RelayHealth> = self
                .client
                .relays()
                .await
                .iter()
                .map(|(url, relay)| {
                    let stats = relay.stats();
                    relay_health_from_parts(
                        url,
                        relay.status(),
                        stats.connected_at().as_secs(),
                        stats.latency(),
                    )
                })
                .collect();
            health.sort_by(|left, right| left.url.cmp(&right.url));
            health
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// A relay the transport can reach directly must stay unreachable once a
    /// proxy is configured, otherwise the proxy is being dropped and the socket
    /// is direct. Nothing listens on the proxy port, so the SOCKS handshake
    /// cannot complete and no relay reaches `Connected`.
    #[tokio::test]
    async fn a_configured_proxy_reaches_the_node_relay_sockets() {
        use crate::test_relay::start_mock_relay;

        let relay = start_mock_relay().await;
        let url = relay.url().await;
        let relays = vec![url.to_string()];

        let direct = NostrTransport::connect(
            Keys::generate(),
            &relays,
            None,
            RelayOptions::default(),
            None,
        )
        .await
        .expect("the mock relay must be reachable without a proxy, or the negative below proves nothing");
        direct.client.shutdown().await;

        let proxy: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(
            NostrTransport::connect(
                Keys::generate(),
                &relays,
                Some(proxy),
                RelayOptions::default(),
                None,
            )
            .await
            .is_err(),
            "connected through a dead proxy, so the relay socket ignored it"
        );
    }

    fn output(success: &[&str], failed: &[(&str, &str)]) -> Output<EventId> {
        Output {
            val: EventId::all_zeros(),
            success: success
                .iter()
                .map(|u| RelayUrl::parse(u).unwrap())
                .collect::<HashSet<_>>(),
            failed: failed
                .iter()
                .map(|(u, why)| (RelayUrl::parse(u).unwrap(), why.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn a_send_no_relay_accepted_is_an_error() {
        assert!(require_accepted(&output(&["wss://a.example"], &[])).is_ok());
        assert!(require_accepted(&output(
            &["wss://a.example"],
            &[("wss://b.example", "blocked")]
        ))
        .is_ok());
        let err =
            require_accepted(&output(&[], &[("wss://b.example", "blocked: kind")])).unwrap_err();
        assert!(err.contains("blocked: kind"), "{err}");
        assert!(require_accepted(&output(&[], &[])).is_err());
    }

    #[test]
    fn relay_health_collapses_pool_status_and_timing() {
        let url = RelayUrl::parse("wss://relay.example.com/").unwrap();
        let cases = [
            (RelayStatus::Initialized, RelayHealthStatus::Connecting),
            (RelayStatus::Pending, RelayHealthStatus::Connecting),
            (RelayStatus::Connecting, RelayHealthStatus::Connecting),
            (RelayStatus::Sleeping, RelayHealthStatus::Connecting),
            (RelayStatus::Connected, RelayHealthStatus::Connected),
            (RelayStatus::Disconnected, RelayHealthStatus::Offline),
            (RelayStatus::Terminated, RelayHealthStatus::Offline),
            (RelayStatus::Banned, RelayHealthStatus::Offline),
        ];
        for (status, expected) in cases {
            let health = relay_health_from_parts(
                &url,
                status,
                1_700_000_000,
                Some(Duration::from_millis(42)),
            );
            assert_eq!(health.status, expected, "{status}");
            assert_eq!(health.url, "wss://relay.example.com");
            assert_eq!(health.last_connected_ms, 1_700_000_000_000);
            assert_eq!(health.rtt_ms, Some(42));
        }

        let unseen = relay_health_from_parts(&url, RelayStatus::Disconnected, 0, None);
        assert_eq!(unseen.last_connected_ms, 0);
        assert_eq!(unseen.rtt_ms, None);
    }

    #[test]
    fn pool_relay_url_identity_strips_slash_case_and_default_port() {
        let url = RelayUrl::parse("wss://Relay.Example.com:443/").unwrap();
        assert_eq!(
            url.as_str_without_trailing_slash(),
            "wss://relay.example.com"
        );
        let plain = RelayUrl::parse("wss://relay.example.com").unwrap();
        assert_eq!(
            plain.as_str_without_trailing_slash(),
            "wss://relay.example.com"
        );
        let path = RelayUrl::parse("wss://relay.example.com/path/").unwrap();
        assert_eq!(
            path.as_str_without_trailing_slash(),
            "wss://relay.example.com/path"
        );
    }
}
