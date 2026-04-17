// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::time::Duration;

use nostr_sdk::prelude::*;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use keep_core::error::{CryptoError, KeepError, NetworkError, StorageError};
use keep_core::relay::{
    normalize_relay_url, validate_relay_url, validate_relay_url_allow_internal,
    ALLOW_INTERNAL_HOSTS, TIMESTAMP_TWEAK_RANGE,
};

use crate::bunker::parse_bunker_url;
use crate::error::Result;
use crate::types::Nip46Response;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const REGISTER_WALLET_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_RESPONSE_SIZE: usize = 64 * 1024;
const MAX_HMAC_HEX_LEN: usize = 128;
pub const MAX_WALLET_NAME_LEN: usize = 64;
pub const MAX_DESCRIPTOR_LEN: usize = 4096;

/// Outcome of a successful `register_wallet` request.
#[derive(Debug, Clone)]
pub struct RegisterWalletResponse {
    pub hmac: Option<Vec<u8>>,
}

/// Client that sends NIP-46 requests to a remote signer (e.g. a hardware wallet).
pub struct Nip46Client {
    signer_pubkey: PublicKey,
    relays: Vec<String>,
    secret: Option<Zeroizing<String>>,
    client_keys: Keys,
    client: Client,
}

impl Nip46Client {
    pub async fn connect_to(uri: &str) -> Result<Self> {
        let (signer_pubkey, relays, secret) = parse_bunker_url(uri)
            .map_err(|e| KeepError::InvalidInput(format!("invalid NIP-46 URI: {e}")))?;
        Self::connect_with(signer_pubkey, relays, secret).await
    }

    pub async fn connect_with(
        signer_pubkey: PublicKey,
        relays: Vec<String>,
        secret: Option<String>,
    ) -> Result<Self> {
        if relays.is_empty() {
            return Err(NetworkError::relay("at least one relay required").into());
        }

        let validate = if ALLOW_INTERNAL_HOSTS {
            validate_relay_url_allow_internal
        } else {
            validate_relay_url
        };
        let mut normalized = Vec::with_capacity(relays.len());
        for relay in &relays {
            validate(relay).map_err(|e| {
                KeepError::InvalidInput(format!("invalid relay URL '{relay}': {e}"))
            })?;
            normalized.push(normalize_relay_url(relay));
        }
        let relays = normalized;

        let client_keys = Keys::generate();
        let client = Client::new(client_keys.clone());
        for relay in &relays {
            client
                .add_relay(relay.as_str())
                .await
                .map_err(|e| NetworkError::relay(format!("add relay: {e}")))?;
        }
        client.connect().await;

        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .pubkey(client_keys.public_key());
        client
            .subscribe(filter, None)
            .await
            .map_err(|e| NetworkError::subscribe(e.to_string()))?;

        Ok(Self {
            signer_pubkey,
            relays,
            secret: secret.map(Zeroizing::new),
            client_keys,
            client,
        })
    }

    pub fn signer_pubkey(&self) -> PublicKey {
        self.signer_pubkey
    }

    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    pub async fn disconnect(self) {
        self.client.disconnect().await;
    }

    pub async fn connect(&self) -> Result<()> {
        let mut params = vec![self.signer_pubkey.to_hex()];
        if let Some(ref s) = self.secret {
            params.push(s.as_str().to_string());
        }
        let id = new_request_id();
        let response = self.request(&id, "connect", params).await?;
        match (response.result.as_deref(), response.error.as_deref()) {
            (Some(_), None) => Ok(()),
            (_, Some(err)) => {
                Err(NetworkError::response(format!("connect rejected: {err}")).into())
            }
            _ => Err(NetworkError::response("connect returned no result").into()),
        }
    }

    /// Register a wallet descriptor on the remote signer.
    ///
    /// The `descriptor` must already encode both the external (receive) and
    /// internal (change) paths, typically as a BIP-389 multipath descriptor
    /// (e.g. `tr(...<0;1>/*)`). Sending only a single-path descriptor prevents
    /// the device from deriving change addresses.
    pub async fn register_wallet(
        &self,
        name: &str,
        descriptor: &str,
    ) -> Result<RegisterWalletResponse> {
        if name.is_empty() {
            return Err(KeepError::InvalidInput(
                "wallet name must not be empty".into(),
            ));
        }
        if name.len() > MAX_WALLET_NAME_LEN {
            return Err(KeepError::InvalidInput(format!(
                "wallet name exceeds {MAX_WALLET_NAME_LEN} bytes"
            )));
        }
        if descriptor.is_empty() {
            return Err(KeepError::InvalidInput(
                "descriptor must not be empty".into(),
            ));
        }
        if descriptor.len() > MAX_DESCRIPTOR_LEN {
            return Err(KeepError::InvalidInput(format!(
                "descriptor exceeds {MAX_DESCRIPTOR_LEN} bytes"
            )));
        }
        let has_multipath = descriptor.contains("<0;1>") || descriptor.contains("<1;0>");
        let has_single_path = ["/0/*)", "/0/*,", "/1/*)", "/1/*,"]
            .iter()
            .any(|p| descriptor.contains(p));
        if has_single_path {
            let msg = if has_multipath {
                "descriptor mixes multipath and single-path keys; normalize all keys to <0;1>"
            } else {
                "descriptor must be multipath (e.g. <0;1>) so the device can derive change"
            };
            return Err(KeepError::InvalidInput(msg.into()));
        }

        let id = new_request_id();
        let response = self
            .request_with_timeout(
                &id,
                "register_wallet",
                vec![name.to_string(), descriptor.to_string()],
                REGISTER_WALLET_TIMEOUT,
            )
            .await?;

        if let Some(err) = response.error {
            return Err(NetworkError::response(format!("register_wallet rejected: {err}")).into());
        }

        let hmac = match response.result.as_deref() {
            None | Some("") => None,
            Some(hex_str) => {
                let trimmed = hex_str.trim();
                if trimmed.len() > MAX_HMAC_HEX_LEN {
                    return Err(KeepError::InvalidInput(format!(
                        "register_wallet hmac too long: {} hex chars (max {MAX_HMAC_HEX_LEN})",
                        trimmed.len()
                    )));
                }
                Some(hex::decode(trimmed).map_err(|e| {
                    StorageError::invalid_format(format!("register_wallet hmac hex: {e}"))
                })?)
            }
        };
        Ok(RegisterWalletResponse { hmac })
    }

    async fn request(&self, id: &str, method: &str, params: Vec<String>) -> Result<Nip46Response> {
        self.request_with_timeout(id, method, params, DEFAULT_REQUEST_TIMEOUT)
            .await
    }

    async fn request_with_timeout(
        &self,
        id: &str,
        method: &str,
        params: Vec<String>,
        timeout: Duration,
    ) -> Result<Nip46Response> {
        let mut notifications = self.client.notifications();

        let request = serde_json::json!({
            "id": id,
            "method": method,
            "params": params,
        });
        let payload = Zeroizing::new(
            serde_json::to_string(&request)
                .map_err(|e| StorageError::serialization(e.to_string()))?,
        );

        let encrypted = nip44::encrypt(
            self.client_keys.secret_key(),
            &self.signer_pubkey,
            payload.as_str(),
            nip44::Version::V2,
        )
        .map_err(|e| CryptoError::encryption(e.to_string()))?;

        let event = EventBuilder::new(Kind::NostrConnect, encrypted)
            .custom_created_at(Timestamp::tweaked(TIMESTAMP_TWEAK_RANGE))
            .tag(Tag::public_key(self.signer_pubkey))
            .sign_with_keys(&self.client_keys)
            .map_err(|e| CryptoError::invalid_signature(format!("sign request: {e}")))?;

        self.client
            .send_event(&event)
            .await
            .map_err(|e| NetworkError::publish(format!("send request: {e}")))?;

        debug!(method, id, "NIP-46 client request sent");

        self.wait_for_response(id, &mut notifications, timeout)
            .await
    }

    async fn wait_for_response(
        &self,
        id: &str,
        notifications: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
        timeout: Duration,
    ) -> Result<Nip46Response> {
        let deadline = tokio::time::Instant::now() + timeout;
        let timeout_err = || NetworkError::timeout(format!("no response for request {id}"));

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(timeout_err().into());
            }

            let notif = match tokio::time::timeout(remaining, notifications.recv()).await {
                Ok(Ok(n)) => n,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                    warn!(dropped = n, "NIP-46 notification stream lagged");
                    continue;
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                    return Err(NetworkError::response("notification stream closed").into());
                }
                Err(_) => return Err(timeout_err().into()),
            };

            let RelayPoolNotification::Event { event, .. } = notif else {
                continue;
            };
            if event.kind != Kind::NostrConnect {
                continue;
            }
            if event.pubkey != self.signer_pubkey {
                continue;
            }

            if event.content.len() > MAX_RESPONSE_SIZE {
                warn!("NIP-46 response too large, ignoring");
                continue;
            }

            let plaintext = match nip44::decrypt(
                self.client_keys.secret_key(),
                &event.pubkey,
                &event.content,
            ) {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = %e, "failed to decrypt NIP-46 response");
                    continue;
                }
            };

            let response: Nip46Response = match serde_json::from_str(&plaintext) {
                Ok(r) => r,
                Err(e) => {
                    debug!(error = %e, "failed to parse NIP-46 response");
                    continue;
                }
            };

            if response.id != id {
                continue;
            }
            return Ok(response);
        }
    }
}

fn new_request_id() -> String {
    hex::encode(keep_core::crypto::random_bytes::<16>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_request_id_is_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }
}
