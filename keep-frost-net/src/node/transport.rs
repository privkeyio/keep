// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use nostr_sdk::prelude::*;
use tokio::sync::broadcast;

use crate::error::{FrostNetError, Result};

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
    pub(crate) async fn connect(
        keys: Keys,
        relays: &[String],
        proxy: Option<SocketAddr>,
        relay_opts: RelayOptions,
    ) -> Result<Self> {
        let client = match proxy {
            Some(addr) => {
                let connection = Connection::new().proxy(addr).target(ConnectionTarget::All);
                let opts = ClientOptions::new().connection(connection);
                Client::builder().signer(keys.clone()).opts(opts).build()
            }
            None => Client::new(keys.clone()),
        };

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

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let relay_map = client.relays().await;
                let any_connected = relay_map
                    .values()
                    .any(|r| matches!(r.status(), RelayStatus::Connected));
                if any_connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| FrostNetError::Transport("Timed out waiting for relay connection".into()))?;

        Ok(Self { client })
    }
}

impl CosignTransport for NostrTransport {
    fn send_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.client
                .send_event(event)
                .await
                .map_err(|e| FrostNetError::Transport(e.to_string()))?;
            Ok(())
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
