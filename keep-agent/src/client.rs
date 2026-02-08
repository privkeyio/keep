// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::time::Duration;

use nostr_sdk::prelude::*;

use crate::error::{AgentError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
}

pub struct PendingSession {
    request_id: String,
    signer_pubkey: PublicKey,
    relay_url: String,
    client_keys: Keys,
    client: Client,
}

impl PendingSession {
    pub async fn new(bunker_url: &str, timeout: Duration) -> Result<Self> {
        let (signer_pubkey, relay_url, _) = AgentClient::parse_bunker_url(bunker_url)?;

        let client_keys = Keys::generate();
        let client = Client::new(client_keys.clone());

        client
            .add_relay(&relay_url)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        client.connect().await;

        tokio::time::timeout(timeout, async {
            loop {
                if let Ok(relay) = client.relay(&relay_url).await {
                    if matches!(relay.status(), RelayStatus::Connected) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| AgentError::Connection("Relay connection timeout".into()))?;

        let request_id = generate_uuid();

        Ok(Self {
            request_id,
            signer_pubkey,
            relay_url,
            client_keys,
            client,
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn approval_url(&self) -> String {
        let encoded_relay = urlencoding::encode(&self.relay_url);
        format!(
            "nostrconnect://{}?relay={}&metadata={}",
            self.client_keys
                .public_key()
                .to_bech32()
                .unwrap_or_default(),
            encoded_relay,
            urlencoding::encode("{\"name\":\"Keep Agent\"}")
        )
    }

    pub async fn poll(&self, timeout: Duration) -> Result<ApprovalStatus> {
        let request = serde_json::json!({
            "id": &self.request_id,
            "method": "connect",
            "params": [self.signer_pubkey.to_hex()]
        });

        let encrypted = nip44::encrypt(
            self.client_keys.secret_key(),
            &self.signer_pubkey,
            request.to_string(),
            nip44::Version::default(),
        )
        .map_err(|e| AgentError::Nostr(e.to_string()))?;

        let tags = vec![Tag::public_key(self.signer_pubkey)];
        let unsigned = UnsignedEvent::new(
            self.client_keys.public_key(),
            Timestamp::now(),
            Kind::NostrConnect,
            tags,
            encrypted,
        );
        let event = unsigned
            .sign(&self.client_keys)
            .await
            .map_err(|e| AgentError::Nostr(e.to_string()))?;

        self.client
            .send_event(&event)
            .await
            .map_err(|e| AgentError::Nostr(e.to_string()))?;

        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .author(self.signer_pubkey)
            .pubkey(self.client_keys.public_key())
            .since(Timestamp::now());

        let sub_output = self
            .client
            .subscribe(filter, None)
            .await
            .map_err(|e| AgentError::Nostr(e.to_string()))?;

        let sub_id = sub_output.id();
        let mut notifications = self.client.notifications();

        let result = tokio::time::timeout(timeout, async {
            while let Ok(notification) = notifications.recv().await {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::NostrConnect && event.pubkey == self.signer_pubkey {
                        if let Ok(decrypted) = nip44::decrypt(
                            self.client_keys.secret_key(),
                            &self.signer_pubkey,
                            &event.content,
                        ) {
                            let parsed: serde_json::Value = serde_json::from_str(&decrypted)
                                .map_err(|e| AgentError::Serialization(e.to_string()))?;

                            if let Some(id) = parsed.get("id").and_then(|v| v.as_str()) {
                                if id == self.request_id {
                                    if let Some(error) = parsed.get("error") {
                                        if !error.is_null() {
                                            return Ok(ApprovalStatus::Denied);
                                        }
                                    }
                                    if parsed.get("result").is_some() {
                                        return Ok(ApprovalStatus::Approved);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(ApprovalStatus::Pending)
        })
        .await;

        self.client.unsubscribe(sub_id).await;

        match result {
            Ok(inner) => inner,
            Err(_) => Ok(ApprovalStatus::Pending),
        }
    }

    pub async fn wait_for_approval(&self, timeout: Duration) -> Result<AgentClient> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_secs(2);

        while start.elapsed() < timeout {
            match self.poll(poll_interval).await? {
                ApprovalStatus::Approved => {
                    return Ok(AgentClient {
                        signer_pubkey: self.signer_pubkey,
                        relay_url: self.relay_url.clone(),
                        client_keys: self.client_keys.clone(),
                        client: self.client.clone(),
                    });
                }
                ApprovalStatus::Denied => {
                    return Err(AgentError::AuthFailed("Session request denied".into()));
                }
                ApprovalStatus::Pending => {
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }

        Err(AgentError::Connection("Approval timeout".into()))
    }

    pub async fn disconnect(&self) {
        self.client.disconnect().await;
    }
}

pub struct AgentClient {
    signer_pubkey: PublicKey,
    #[allow(dead_code)]
    relay_url: String,
    client_keys: Keys,
    client: Client,
}

impl AgentClient {
    pub async fn connect(bunker_url: &str, timeout: Duration) -> Result<Self> {
        let (signer_pubkey, relay_url, secret) = Self::parse_bunker_url(bunker_url)?;

        let client_keys = Keys::generate();
        let client = Client::new(client_keys.clone());

        client
            .add_relay(&relay_url)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        client.connect().await;

        tokio::time::timeout(timeout, async {
            loop {
                if let Ok(relay) = client.relay(&relay_url).await {
                    if matches!(relay.status(), RelayStatus::Connected) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| AgentError::Connection("Relay connection timeout".into()))?;

        let agent_client = Self {
            signer_pubkey,
            relay_url,
            client_keys,
            client,
        };

        agent_client.send_connect(secret.as_deref()).await?;

        Ok(agent_client)
    }

    fn parse_bunker_url(url: &str) -> Result<(PublicKey, String, Option<String>)> {
        if !url.starts_with("bunker://") {
            return Err(AgentError::Connection("Invalid bunker URL format".into()));
        }

        let rest = &url[9..];
        let (pubkey_part, query) = rest.split_once('?').unwrap_or((rest, ""));

        let signer_pubkey = PublicKey::from_bech32(pubkey_part)
            .or_else(|_| PublicKey::from_hex(pubkey_part))
            .map_err(|e| AgentError::Connection(format!("Invalid pubkey: {e}")))?;

        let mut relay_url = None;
        let mut secret = None;

        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "relay" => {
                        relay_url = Some(
                            urlencoding::decode(value)
                                .map_err(|e| AgentError::Connection(e.to_string()))?
                                .to_string(),
                        );
                    }
                    "secret" => {
                        secret = Some(value.to_string());
                    }
                    _ => {}
                }
            }
        }

        let relay_url = relay_url.ok_or_else(|| {
            AgentError::Connection("Missing relay parameter in bunker URL".into())
        })?;

        Ok((signer_pubkey, relay_url, secret))
    }

    async fn send_connect(&self, secret: Option<&str>) -> Result<()> {
        let params = match secret {
            Some(s) => vec![self.signer_pubkey.to_hex(), s.to_string()],
            None => vec![self.signer_pubkey.to_hex()],
        };

        let request = serde_json::json!({
            "id": generate_uuid(),
            "method": "connect",
            "params": params
        });

        let response = self.send_request(&request.to_string()).await?;

        let parsed: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| AgentError::Serialization(e.to_string()))?;

        if let Some(error) = parsed.get("error") {
            if !error.is_null() {
                return Err(AgentError::AuthFailed(error.to_string()));
            }
        }

        Ok(())
    }

    pub async fn get_public_key(&self) -> Result<String> {
        let request = serde_json::json!({
            "id": generate_uuid(),
            "method": "get_public_key",
            "params": []
        });

        let response = self.send_request(&request.to_string()).await?;
        Self::extract_result(&response)
    }

    pub async fn sign_event(&self, event_json: &str) -> Result<String> {
        let request = serde_json::json!({
            "id": generate_uuid(),
            "method": "sign_event",
            "params": [event_json]
        });

        let response = self.send_request(&request.to_string()).await?;
        Self::extract_result(&response)
    }

    pub async fn nip44_encrypt(&self, pubkey: &str, plaintext: &str) -> Result<String> {
        let request = serde_json::json!({
            "id": generate_uuid(),
            "method": "nip44_encrypt",
            "params": [pubkey, plaintext]
        });

        let response = self.send_request(&request.to_string()).await?;
        Self::extract_result(&response)
    }

    pub async fn nip44_decrypt(&self, pubkey: &str, ciphertext: &str) -> Result<String> {
        let request = serde_json::json!({
            "id": generate_uuid(),
            "method": "nip44_decrypt",
            "params": [pubkey, ciphertext]
        });

        let response = self.send_request(&request.to_string()).await?;
        Self::extract_result(&response)
    }

    pub async fn ping(&self) -> Result<bool> {
        let request = serde_json::json!({
            "id": generate_uuid(),
            "method": "ping",
            "params": []
        });

        let response = self.send_request(&request.to_string()).await?;

        let parsed: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| AgentError::Serialization(e.to_string()))?;

        if let Some(result) = parsed.get("result") {
            if let Some(s) = result.as_str() {
                return Ok(s == "pong");
            }
        }

        Ok(false)
    }

    async fn send_request(&self, content: &str) -> Result<String> {
        let encrypted = nip44::encrypt(
            self.client_keys.secret_key(),
            &self.signer_pubkey,
            content,
            nip44::Version::default(),
        )
        .map_err(|e| AgentError::Nostr(e.to_string()))?;

        let tags = vec![Tag::public_key(self.signer_pubkey)];
        let unsigned = UnsignedEvent::new(
            self.client_keys.public_key(),
            Timestamp::now(),
            Kind::NostrConnect,
            tags,
            encrypted,
        );
        let event = unsigned
            .sign(&self.client_keys)
            .await
            .map_err(|e| AgentError::Nostr(e.to_string()))?;

        self.client
            .send_event(&event)
            .await
            .map_err(|e| AgentError::Nostr(e.to_string()))?;

        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .author(self.signer_pubkey)
            .pubkey(self.client_keys.public_key())
            .since(Timestamp::now());

        let sub_output = self
            .client
            .subscribe(filter, None)
            .await
            .map_err(|e| AgentError::Nostr(e.to_string()))?;

        let sub_id = sub_output.id();
        let mut notifications = self.client.notifications();

        let result = tokio::time::timeout(Duration::from_secs(30), async {
            while let Ok(notification) = notifications.recv().await {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::NostrConnect && event.pubkey == self.signer_pubkey {
                        if let Ok(decrypted) = nip44::decrypt(
                            self.client_keys.secret_key(),
                            &self.signer_pubkey,
                            &event.content,
                        ) {
                            return Ok(decrypted);
                        }
                    }
                }
            }
            Err(AgentError::Connection("No response received".into()))
        })
        .await;

        self.client.unsubscribe(sub_id).await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(AgentError::Connection("Response timeout".into())),
        }
    }

    fn extract_result(response: &str) -> Result<String> {
        let parsed: serde_json::Value =
            serde_json::from_str(response).map_err(|e| AgentError::Serialization(e.to_string()))?;

        if let Some(error) = parsed.get("error") {
            if !error.is_null() {
                return Err(AgentError::Nostr(error.to_string()));
            }
        }

        parsed
            .get("result")
            .map(|v| {
                if v.is_string() {
                    v.as_str().unwrap().to_string()
                } else {
                    v.to_string()
                }
            })
            .ok_or_else(|| AgentError::Serialization("Missing result field".into()))
    }

    pub fn signer_pubkey(&self) -> &PublicKey {
        &self.signer_pubkey
    }

    pub fn client_pubkey(&self) -> PublicKey {
        self.client_keys.public_key()
    }

    pub async fn disconnect(&self) {
        let _ = self.client.disconnect().await;
    }
}

fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_generation() {
        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();
        assert_ne!(uuid1, uuid2);
        assert_eq!(uuid1.len(), 36);
    }
}
