// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::sync::atomic::{AtomicBool, Ordering};
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
    connect_sent: AtomicBool,
}

impl PendingSession {
    pub async fn new(bunker_url: &str, timeout: Duration) -> Result<Self> {
        let (signer_pubkey, relay_url, _) = AgentClient::parse_bunker_url(bunker_url)?;

        let client_keys = Keys::generate();
        let client = Client::new(client_keys.clone());

        client
            .pool()
            .add_relay(&relay_url, default_relay_opts())
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
            connect_sent: AtomicBool::new(false),
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn approval_url(&self) -> String {
        let encoded_relay = urlencoding::encode(&self.relay_url);
        format!(
            "nostrconnect://{}?relay={}&metadata={}",
            self.client_keys.public_key().to_hex(),
            encoded_relay,
            urlencoding::encode("{\"name\":\"Keep Agent\"}")
        )
    }

    async fn send_connect_once(&self) -> Result<()> {
        if self.connect_sent.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

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
            Timestamp::tweaked(0..5),
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

        Ok(())
    }

    pub async fn poll(&self, timeout: Duration) -> Result<ApprovalStatus> {
        self.send_connect_once().await?;

        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .author(self.signer_pubkey)
            .pubkey(self.client_keys.public_key())
            .since(Timestamp::now() - Duration::from_secs(10));

        let mut stream = self
            .client
            .pool()
            .stream_events(filter, timeout, ReqExitPolicy::WaitForEventsAfterEOSE(1))
            .await
            .map_err(|e| AgentError::Nostr(e.to_string()))?;

        let result = tokio::time::timeout(timeout, async {
            while let Some(event) = stream.next().await {
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
            Ok(ApprovalStatus::Pending)
        })
        .await;

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
                    let mut client = AgentClient {
                        signer_pubkey: self.signer_pubkey,
                        relay_url: self.relay_url.clone(),
                        client_keys: self.client_keys.clone(),
                        client: self.client.clone(),
                    };
                    let _ = client.switch_relays().await;
                    return Ok(client);
                }
                ApprovalStatus::Denied => {
                    return Err(AgentError::AuthFailed("Session request denied".into()));
                }
                ApprovalStatus::Pending => {}
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
            .pool()
            .add_relay(&relay_url, default_relay_opts())
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

        let mut agent_client = Self {
            signer_pubkey,
            relay_url,
            client_keys,
            client,
        };

        agent_client.send_connect(secret.as_deref()).await?;
        let _ = agent_client.switch_relays().await;

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

        keep_core::relay::validate_relay_url(&relay_url)
            .map_err(|e| AgentError::Connection(format!("Invalid relay URL: {e}")))?;

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

    pub async fn switch_relays(&mut self) -> Result<Option<Vec<String>>> {
        let request = serde_json::json!({
            "id": generate_uuid(),
            "method": "switch_relays",
            "params": []
        });

        let response = self.send_request(&request.to_string()).await?;
        let parsed: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| AgentError::Serialization(e.to_string()))?;

        if let Some(error) = parsed.get("error") {
            if !error.is_null() {
                return Err(AgentError::Nostr(error.to_string()));
            }
        }

        let result = parsed
            .get("result")
            .ok_or_else(|| AgentError::Serialization("Missing result field".into()))?;

        if result.is_null() || (result.is_string() && result.as_str() == Some("null")) {
            return Ok(None);
        }

        let relays: Vec<String> = if result.is_string() {
            serde_json::from_str(result.as_str().expect("guarded by is_string check"))
                .map_err(|e| AgentError::Serialization(format!("Invalid relay list: {e}")))?
        } else if result.is_array() {
            serde_json::from_value(result.clone())
                .map_err(|e| AgentError::Serialization(format!("Invalid relay list: {e}")))?
        } else {
            return Err(AgentError::Serialization(
                "Unexpected switch_relays result format".into(),
            ));
        };

        if relays.is_empty() {
            return Ok(None);
        }

        let valid_relays: Vec<String> = relays
            .into_iter()
            .filter(|r| keep_core::relay::validate_relay_url(r).is_ok())
            .collect();

        if valid_relays.is_empty() {
            return Ok(None);
        }

        self.client.disconnect().await;
        self.client.remove_all_relays().await;
        let relay_opts = default_relay_opts();
        let mut added = Vec::new();
        for relay in &valid_relays {
            if self
                .client
                .pool()
                .add_relay(relay, relay_opts.clone())
                .await
                .is_ok()
            {
                added.push(relay.clone());
            }
        }
        if added.is_empty() {
            return Err(AgentError::Connection(
                "Failed to add any relay during switch".into(),
            ));
        }
        self.client.connect().await;

        self.relay_url = added[0].clone();

        Ok(Some(added))
    }

    async fn send_request(&self, content: &str) -> Result<String> {
        let request_id = {
            let parsed: serde_json::Value = serde_json::from_str(content)
                .map_err(|e| AgentError::Serialization(e.to_string()))?;
            parsed
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };

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
            Timestamp::tweaked(0..5),
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
            .since(Timestamp::now() - Duration::from_secs(10));

        let mut stream = self
            .client
            .pool()
            .stream_events(
                filter,
                Duration::from_secs(30),
                ReqExitPolicy::WaitForEventsAfterEOSE(5),
            )
            .await
            .map_err(|e| AgentError::Nostr(e.to_string()))?;

        let result = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(event) = stream.next().await {
                if event.kind == Kind::NostrConnect && event.pubkey == self.signer_pubkey {
                    if let Ok(decrypted) = nip44::decrypt(
                        self.client_keys.secret_key(),
                        &self.signer_pubkey,
                        &event.content,
                    ) {
                        if let Some(ref expected_id) = request_id {
                            if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&decrypted)
                            {
                                if resp.get("id").and_then(|v| v.as_str()) != Some(expected_id) {
                                    continue;
                                }
                            }
                        }
                        return Ok(decrypted);
                    }
                }
            }
            Err(AgentError::Connection("No response received".into()))
        })
        .await;

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
                    v.as_str().expect("guarded by is_string check").to_string()
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

fn default_relay_opts() -> RelayOptions {
    RelayOptions::default()
        .reconnect(true)
        .ping(true)
        .retry_interval(Duration::from_secs(10))
        .adjust_retry_interval(true)
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

    #[test]
    fn test_switch_relays_parse() {
        let null_response = r#"{"id":"abc","result":null}"#;
        let parsed: serde_json::Value = serde_json::from_str(null_response).unwrap();
        let result = parsed.get("result").unwrap();
        assert!(result.is_null());

        let null_string_response = r#"{"id":"abc","result":"null"}"#;
        let parsed: serde_json::Value = serde_json::from_str(null_string_response).unwrap();
        let result = parsed.get("result").unwrap();
        assert!(result.is_string() && result.as_str() == Some("null"));

        let array_response =
            r#"{"id":"abc","result":["wss://relay1.example.com","wss://relay2.example.com"]}"#;
        let parsed: serde_json::Value = serde_json::from_str(array_response).unwrap();
        let result = parsed.get("result").unwrap();
        assert!(result.is_array());
        let relays: Vec<String> = serde_json::from_value(result.clone()).unwrap();
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0], "wss://relay1.example.com");
        assert_eq!(relays[1], "wss://relay2.example.com");

        let string_array_response = r#"{"id":"abc","result":"[\"wss://relay1.example.com\",\"wss://relay2.example.com\"]"}"#;
        let parsed: serde_json::Value = serde_json::from_str(string_array_response).unwrap();
        let result = parsed.get("result").unwrap();
        assert!(result.is_string());
        let relays: Vec<String> = serde_json::from_str(result.as_str().unwrap()).unwrap();
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0], "wss://relay1.example.com");
    }
}
