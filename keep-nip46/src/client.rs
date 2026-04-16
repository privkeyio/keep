// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::time::Duration;

use nostr_sdk::prelude::*;
use tracing::{debug, warn};

use keep_core::error::{CryptoError, NetworkError, StorageError};
use keep_core::relay::TIMESTAMP_TWEAK_RANGE;

use crate::bunker::parse_bunker_url;
use crate::error::Result;
use crate::types::Nip46Response;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE_SIZE: usize = 64 * 1024;
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
    secret: Option<String>,
    client_keys: Keys,
    client: Client,
}

impl Nip46Client {
    pub async fn connect_to(uri: &str) -> Result<Self> {
        let (signer_pubkey, relays, secret) = parse_bunker_url(uri).map_err(|e| {
            keep_core::error::KeepError::InvalidInput(format!("invalid NIP-46 URI: {e}"))
        })?;
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
            secret,
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
            params.push(s.clone());
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

    pub async fn register_wallet(
        &self,
        name: &str,
        descriptor: &str,
    ) -> Result<RegisterWalletResponse> {
        if name.is_empty() {
            return Err(keep_core::error::KeepError::InvalidInput(
                "wallet name must not be empty".into(),
            ));
        }
        if name.len() > MAX_WALLET_NAME_LEN {
            return Err(keep_core::error::KeepError::InvalidInput(format!(
                "wallet name exceeds {MAX_WALLET_NAME_LEN} bytes"
            )));
        }
        if descriptor.is_empty() {
            return Err(keep_core::error::KeepError::InvalidInput(
                "descriptor must not be empty".into(),
            ));
        }
        if descriptor.len() > MAX_DESCRIPTOR_LEN {
            return Err(keep_core::error::KeepError::InvalidInput(format!(
                "descriptor exceeds {MAX_DESCRIPTOR_LEN} bytes"
            )));
        }

        let id = new_request_id();
        let response = self
            .request(
                &id,
                "register_wallet",
                vec![name.to_string(), descriptor.to_string()],
            )
            .await?;

        if let Some(err) = response.error {
            return Err(NetworkError::response(format!("register_wallet rejected: {err}")).into());
        }

        let hmac = match response.result.as_deref() {
            None | Some("") | Some("null") => None,
            Some(hex_str) => Some(hex::decode(hex_str.trim()).map_err(|e| {
                StorageError::invalid_format(format!("register_wallet hmac hex: {e}"))
            })?),
        };
        Ok(RegisterWalletResponse { hmac })
    }

    async fn request(&self, id: &str, method: &str, params: Vec<String>) -> Result<Nip46Response> {
        let mut notifications = self.client.notifications();

        let request = serde_json::json!({
            "id": id,
            "method": method,
            "params": params,
        });
        let payload = serde_json::to_string(&request)
            .map_err(|e| StorageError::serialization(e.to_string()))?;

        let encrypted = nip44::encrypt(
            self.client_keys.secret_key(),
            &self.signer_pubkey,
            &payload,
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

        self.wait_for_response(id, &mut notifications).await
    }

    async fn wait_for_response(
        &self,
        id: &str,
        notifications: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
    ) -> Result<Nip46Response> {
        let deadline = tokio::time::Instant::now() + DEFAULT_REQUEST_TIMEOUT;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(NetworkError::timeout(format!("no response for request {id}")).into());
            }

            let notif = match tokio::time::timeout(remaining, notifications.recv()).await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) => {
                    return Err(NetworkError::response("notification stream closed").into());
                }
                Err(_) => {
                    return Err(
                        NetworkError::timeout(format!("no response for request {id}")).into(),
                    );
                }
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
