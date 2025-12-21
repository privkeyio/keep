#![forbid(unsafe_code)]

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::error::{AgentError, Result};
use crate::manager::SessionManager;
use crate::scope::Operation;
use crate::session::SessionToken;

use super::tools::{self, ToolResult};

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

pub struct McpServer {
    name: String,
    version: String,
    session_manager: Arc<RwLock<Option<(SessionToken, String)>>>,
    manager: SessionManager,
    secret_key: Option<[u8; 32]>,
}

impl McpServer {
    pub fn new(name: impl Into<String>, version: impl Into<String>, pubkey: [u8; 32]) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            session_manager: Arc::new(RwLock::new(None)),
            manager: SessionManager::new(pubkey),
            secret_key: None,
        }
    }

    pub fn with_signing(pubkey: [u8; 32], secret: [u8; 32]) -> Self {
        Self {
            name: "keep-signer".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            session_manager: Arc::new(RwLock::new(None)),
            manager: SessionManager::new(pubkey),
            secret_key: Some(secret),
        }
    }

    pub fn handle_request(&self, input: &str) -> String {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create runtime");
        let response = rt.block_on(self.handle_request_async(input));
        serde_json::to_string(&response).unwrap_or_else(|e| {
            format!(
                r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32603,"message":"{}"}}}}"#,
                e
            )
        })
    }

    pub async fn set_session(&self, token: SessionToken, session_id: String) {
        let mut session = self.session_manager.write().await;
        *session = Some((token, session_id));
    }

    pub async fn create_session(
        &self,
        config: crate::session::SessionConfig,
    ) -> Result<(SessionToken, String)> {
        let metadata = crate::session::SessionMetadata {
            agent_name: Some("mcp_server".into()),
            agent_framework: Some("keep-agent".into()),
            agent_version: Some(env!("CARGO_PKG_VERSION").into()),
        };

        self.manager.create_session(config, metadata)
    }

    pub async fn run_stdio(&self) -> Result<()> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?
        {
            if line.trim().is_empty() {
                continue;
            }

            let response = self.handle_request_async(&line).await;
            let response_str = serde_json::to_string(&response)
                .map_err(|e| AgentError::Serialization(e.to_string()))?;

            stdout
                .write_all(format!("{}\n", response_str).as_bytes())
                .await
                .map_err(|e| AgentError::Other(e.to_string()))?;
            stdout
                .flush()
                .await
                .map_err(|e| AgentError::Other(e.to_string()))?;
        }

        Ok(())
    }

    async fn handle_request_async(&self, input: &str) -> JsonRpcResponse {
        let request: JsonRpcRequest = match serde_json::from_str(input) {
            Ok(r) => r,
            Err(e) => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: Value::Null,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                    }),
                };
            }
        };

        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(&request.params).await,
            "tools/list" => self.handle_tools_list().await,
            "tools/call" => self.handle_tools_call(&request.params).await,
            "resources/list" => self.handle_resources_list().await,
            "resources/read" => self.handle_resources_read(&request.params).await,
            _ => Err(AgentError::Other(format!(
                "Unknown method: {}",
                request.method
            ))),
        };

        match result {
            Ok(value) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: e.to_string(),
                }),
            },
        }
    }

    async fn handle_initialize(&self, _params: &Value) -> Result<Value> {
        Ok(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {}
            },
            "serverInfo": {
                "name": self.name,
                "version": self.version
            }
        }))
    }

    async fn handle_tools_list(&self) -> Result<Value> {
        let tools: Vec<Value> = tools::all_tools()
            .into_iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema
                })
            })
            .collect();

        Ok(serde_json::json!({ "tools": tools }))
    }

    async fn handle_tools_call(&self, params: &Value) -> Result<Value> {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::Other("Missing tool name".into()))?;

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(Value::Object(Default::default()));

        let (session, session_id) = {
            let session_guard = self.session_manager.read().await;
            let (token, session_id) = session_guard
                .as_ref()
                .ok_or_else(|| AgentError::Other("No active session".into()))?;

            let session = self.manager.validate_and_get(token, session_id)?;
            (session, session_id.clone())
        };

        let result = match name {
            "sign_nostr_event" => {
                session.check_operation(&Operation::SignNostrEvent)?;

                let kind_u64 = arguments
                    .get("kind")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| AgentError::Other("Missing kind".into()))?;

                if kind_u64 > u16::MAX as u64 {
                    return Err(AgentError::Other(format!(
                        "Event kind {} exceeds maximum value {}",
                        kind_u64,
                        u16::MAX
                    )));
                }
                let kind = kind_u64 as u16;

                session.check_event_kind(kind)?;

                let content = arguments
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let tags: Vec<Vec<String>> = arguments
                    .get("tags")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                if let Some(secret) = self.secret_key {
                    use nostr_sdk::prelude::*;

                    let keys = Keys::parse(&hex::encode(secret))
                        .map_err(|e| AgentError::Other(e.to_string()))?;

                    let nostr_tags: Vec<Tag> = tags
                        .into_iter()
                        .filter_map(|t| {
                            if t.is_empty() {
                                None
                            } else {
                                Tag::parse(&t).ok()
                            }
                        })
                        .collect();

                    let event_kind = Kind::from(kind);

                    let event = EventBuilder::new(event_kind, content)
                        .tags(nostr_tags)
                        .sign_with_keys(&keys)
                        .map_err(|e| AgentError::Other(e.to_string()))?;

                    let tags_vec: Vec<Vec<String>> = event
                        .tags
                        .iter()
                        .map(|t: &Tag| t.as_slice().iter().map(|s| s.to_string()).collect())
                        .collect();

                    ToolResult::success(serde_json::json!({
                        "id": event.id.to_hex(),
                        "pubkey": event.pubkey.to_hex(),
                        "created_at": event.created_at.as_secs(),
                        "kind": u16::from(event.kind),
                        "tags": tags_vec,
                        "content": event.content,
                        "sig": hex::encode(event.sig.serialize())
                    }))
                } else {
                    ToolResult::error("No signing key available".to_string())
                }
            }

            "sign_bitcoin_psbt" => {
                session.check_operation(&Operation::SignPsbt)?;

                let psbt_base64 = arguments
                    .get("psbt")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AgentError::Other("Missing psbt".into()))?;

                let network_str = arguments
                    .get("network")
                    .and_then(|v| v.as_str())
                    .unwrap_or("testnet");

                if let Some(secret) = self.secret_key {
                    let network = match network_str {
                        "mainnet" | "bitcoin" => keep_bitcoin::Network::Bitcoin,
                        "signet" => keep_bitcoin::Network::Signet,
                        "regtest" => keep_bitcoin::Network::Regtest,
                        _ => keep_bitcoin::Network::Testnet,
                    };

                    let mut psbt = keep_bitcoin::psbt::parse_psbt_base64(psbt_base64)
                        .map_err(|e| AgentError::Other(format!("Invalid PSBT: {}", e)))?;

                    let signer = keep_bitcoin::BitcoinSigner::new(secret, network)
                        .map_err(|e| AgentError::Other(e.to_string()))?;

                    let analysis = signer
                        .analyze_psbt(&psbt)
                        .map_err(|e| AgentError::Other(e.to_string()))?;

                    if let Some(max_sats) = session.scope().max_amount_sats {
                        if analysis.total_output_sats > max_sats {
                            return Err(AgentError::AmountExceeded {
                                requested: analysis.total_output_sats,
                                limit: max_sats,
                            });
                        }
                    }

                    if let Some(ref allowlist) = session.scope().address_allowlist {
                        for output in &analysis.outputs {
                            if !output.is_change {
                                if let Some(ref addr) = output.address {
                                    if !allowlist.contains(&addr.to_string()) {
                                        return Err(AgentError::AddressNotAllowed(
                                            addr.to_string(),
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    let signed_count = signer
                        .sign_psbt(&mut psbt)
                        .map_err(|e| AgentError::Other(e.to_string()))?;

                    let signed_base64 = keep_bitcoin::psbt::serialize_psbt_base64(&psbt);

                    ToolResult::success(serde_json::json!({
                        "signed_psbt": signed_base64,
                        "inputs_signed": signed_count,
                        "fee_sats": analysis.fee_sats
                    }))
                } else {
                    ToolResult::error("No signing key available".to_string())
                }
            }

            "get_nostr_pubkey" => {
                session.check_operation(&Operation::GetPublicKey)?;

                let pubkey_bytes = session.pubkey();
                let npub = keep_core::keys::bytes_to_npub(pubkey_bytes);

                ToolResult::success(serde_json::json!({
                    "npub": npub,
                    "hex": hex::encode(pubkey_bytes)
                }))
            }

            "get_bitcoin_address" => {
                session.check_operation(&Operation::GetBitcoinAddress)?;

                let addr_type = arguments
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("p2tr");

                if addr_type != "p2tr" {
                    return Ok(serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string(&serde_json::json!({
                                "error": format!("Unsupported address type '{}'. Only 'p2tr' is currently supported.", addr_type)
                            })).unwrap_or_default()
                        }],
                        "isError": true
                    }));
                }

                let network_str = arguments
                    .get("network")
                    .and_then(|v| v.as_str())
                    .unwrap_or("testnet");

                if let Some(secret) = self.secret_key {
                    let network = match network_str {
                        "mainnet" | "bitcoin" => keep_bitcoin::Network::Bitcoin,
                        "signet" => keep_bitcoin::Network::Signet,
                        "regtest" => keep_bitcoin::Network::Regtest,
                        _ => keep_bitcoin::Network::Testnet,
                    };

                    let signer = keep_bitcoin::BitcoinSigner::new(secret, network)
                        .map_err(|e| AgentError::Other(e.to_string()))?;

                    let address = signer
                        .get_receive_address(0)
                        .map_err(|e| AgentError::Other(e.to_string()))?;

                    ToolResult::success(serde_json::json!({
                        "address": address,
                        "type": addr_type,
                        "network": network_str
                    }))
                } else {
                    ToolResult::error("No signing key available".to_string())
                }
            }

            "get_session_info" => {
                let info = session.info();
                ToolResult::success(serde_json::to_value(info).unwrap_or(Value::Null))
            }

            _ => ToolResult::error(format!("Unknown tool: {}", name)),
        };

        self.manager.record_request(&session_id)?;

        let text = serde_json::to_string(&result.content)
            .map_err(|e| AgentError::Serialization(e.to_string()))?;

        Ok(serde_json::json!({
            "content": [{
                "type": "text",
                "text": text
            }],
            "isError": !result.success
        }))
    }

    async fn handle_resources_list(&self) -> Result<Value> {
        Ok(serde_json::json!({
            "resources": [{
                "uri": "session://info",
                "name": "Session Information",
                "description": "Current session permissions and limits",
                "mimeType": "application/json"
            }]
        }))
    }

    async fn handle_resources_read(&self, params: &Value) -> Result<Value> {
        let uri = params
            .get("uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::Other("Missing uri".into()))?;

        match uri {
            "session://info" => {
                let session_guard = self.session_manager.read().await;

                if let Some((token, session_id)) = session_guard.as_ref() {
                    let session = self.manager.validate_and_get(token, session_id)?;
                    let info = session.info();
                    let text = serde_json::to_string_pretty(&info)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    Ok(serde_json::json!({
                        "contents": [{
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": text
                        }]
                    }))
                } else {
                    Err(AgentError::Other("No active session".into()))
                }
            }
            _ => Err(AgentError::Other(format!("Unknown resource: {}", uri))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mcp_initialize() {
        let server = McpServer::new("test", "1.0.0", [0u8; 32]);
        let result = server.handle_initialize(&Value::Null).await.unwrap();

        assert!(result.get("protocolVersion").is_some());
        assert!(result.get("serverInfo").is_some());
    }

    #[tokio::test]
    async fn test_mcp_tools_list() {
        let server = McpServer::new("test", "1.0.0", [0u8; 32]);
        let result = server.handle_tools_list().await.unwrap();

        let tools = result.get("tools").unwrap().as_array().unwrap();
        assert!(!tools.is_empty());
    }
}
