// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::path::Path;

use keep_core::error::{KeepError, Result};
use keep_frost_net::{KfpNode, RelayPinStore, TlsPinning};
use keep_nip46::ServerConfig;

/// Open the vault directory's pin store. Strict mode is on when the CLI
/// config says so or when `KEEP_STRICT_CERT_PINNING` is `1` or `true`.
fn store(vault: &Path) -> Result<RelayPinStore> {
    let strict = crate::config::Config::load()?.strict_cert_pinning
        || keep_frost_net::env_requests_strict_pinning();
    RelayPinStore::open(vault, strict).map_err(|e| KeepError::Frost(e.to_string()))
}

async fn probed(vault: &Path, relays: &[String]) -> Result<TlsPinning> {
    let pins = store(vault)?;
    pins.probe(relays, None)
        .await
        .map_err(|e| KeepError::Frost(e.to_string()))?;
    Ok(pins.pinning())
}

/// Bring up a coordination node whose relay sockets enforce the SPKI pin
/// inside their own handshake. The probe runs first and is what records a
/// trust-on-first-use pin; the handshake only checks it.
pub async fn connect_node(
    vault: &Path,
    share: keep_core::frost::SharePackage,
    relays: Vec<String>,
) -> Result<KfpNode> {
    let pinning = probed(vault, &relays).await?;
    KfpNode::new_pinned(share, relays, None, pinning)
        .await
        .map_err(|e| KeepError::Frost(e.to_string()))
}

/// Probe `relays` and attach the resulting pin handle to a bunker config.
pub async fn pin_bunker(
    vault: &Path,
    relays: &[String],
    config: ServerConfig,
) -> Result<ServerConfig> {
    let tls_pinning = Some(probed(vault, relays).await?);
    Ok(ServerConfig {
        tls_pinning,
        ..config
    })
}

/// A nostr client whose sockets enforce the vault pin. The probe runs first.
pub async fn connect_client(
    vault: &Path,
    relays: &[String],
    keys: nostr_sdk::prelude::Keys,
) -> Result<nostr_sdk::Client> {
    let pinning = probed(vault, relays).await?;
    let client = keep_frost_net::build_client(&keys, None, Some(pinning))
        .map_err(|e| KeepError::Frost(e.to_string()))?;
    for relay in relays {
        client
            .add_relay(relay)
            .await
            .map_err(|e| KeepError::Frost(format!("add relay {relay}: {e}")))?;
    }
    client.connect().await;
    Ok(client)
}

/// Dial a remote bunker. The relays come from the URI, so they are probed
/// before the client exists; passing no pin handle is what this replaces.
pub async fn connect_signer(vault: &Path, uri: &str) -> Result<keep_nip46::Nip46Client> {
    let (_, relays, _) = keep_nip46::parse_bunker_url(uri)
        .map_err(|e| KeepError::InvalidInput(format!("invalid NIP-46 URI: {e}")))?;
    let pinning = probed(vault, &relays).await?;
    keep_nip46::Nip46Client::connect_to(uri, None, Some(pinning)).await
}
