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
        use nostr_relay_builder::MockRelay;

        let relay = MockRelay::run().await.unwrap();
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
}
