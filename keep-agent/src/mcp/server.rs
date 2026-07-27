// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use zeroize::Zeroizing;

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
    secret_key: Option<Zeroizing<[u8; 32]>>,
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
            secret_key: Some(Zeroizing::new(secret)),
        }
    }

    pub fn handle_request(&self, input: &str) -> String {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create runtime");
        let response = rt.block_on(self.handle_request_async(input));
        serde_json::to_string(&response).unwrap_or_else(|e| {
            serde_json::to_string(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32603,
                    "message": e.to_string()
                }
            }))
            .expect("static JSON structure must serialize")
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
                .write_all(format!("{response_str}\n").as_bytes())
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
                        message: format!("Parse error: {e}"),
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

                if let Some(ref secret) = self.secret_key {
                    use nostr_sdk::prelude::*;

                    let hex_secret = Zeroizing::new(hex::encode(**secret));
                    let keys = Keys::parse(hex_secret.as_str())
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

                if let Some(ref secret) = self.secret_key {
                    let mut secret_copy = Zeroizing::new(**secret);
                    let network = match network_str {
                        "mainnet" | "bitcoin" => keep_bitcoin::Network::Bitcoin,
                        "signet" => keep_bitcoin::Network::Signet,
                        "regtest" => keep_bitcoin::Network::Regtest,
                        _ => keep_bitcoin::Network::Testnet,
                    };

                    let mut psbt = keep_bitcoin::psbt::parse_psbt_base64(psbt_base64)
                        .map_err(|e| AgentError::Other(format!("Invalid PSBT: {e}")))?;

                    let signer = keep_bitcoin::BitcoinSigner::new(&mut secret_copy, network)
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
                            if output.is_change {
                                continue;
                            }
                            // Fail closed. A spend output whose address cannot be
                            // determined (a non-standard script, or an address for a
                            // network other than the signer's) cannot be confirmed
                            // against the allowlist, so refuse rather than sign an
                            // unverifiable destination.
                            match output.address {
                                Some(ref addr) if allowlist.contains(addr) => {}
                                Some(ref addr) => {
                                    return Err(AgentError::AddressNotAllowed(addr.clone()))
                                }
                                None => {
                                    return Err(AgentError::AddressNotAllowed(format!(
                                        "output {} has no recognizable address",
                                        output.index
                                    )))
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

                if let Some(ref secret) = self.secret_key {
                    let mut secret_copy = Zeroizing::new(**secret);
                    let network = match network_str {
                        "mainnet" | "bitcoin" => keep_bitcoin::Network::Bitcoin,
                        "signet" => keep_bitcoin::Network::Signet,
                        "regtest" => keep_bitcoin::Network::Regtest,
                        _ => keep_bitcoin::Network::Testnet,
                    };

                    let signer = keep_bitcoin::BitcoinSigner::new(&mut secret_copy, network)
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

            _ => ToolResult::error(format!("Unknown tool: {name}")),
        };

        if result.success {
            self.manager.record_request(&session_id)?;
        }

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
            _ => Err(AgentError::Other(format!("Unknown resource: {uri}"))),
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

    // End-to-end coverage of the JSON-RPC surface (#461): drive real requests
    // through `handle_request_async` and assert the initialize handshake, the
    // advertised toolset, per-tool call results, and the session permission
    // model (which gates every signing tool).
    use crate::scope::SessionScope;
    use crate::session::SessionConfig;

    fn signing_server() -> McpServer {
        // Deterministic key so a produced signature is reproducible in shape.
        let secret = [7u8; 32];
        let keys = nostr_sdk::Keys::parse(&hex::encode(secret)).expect("valid key");
        let pubkey: [u8; 32] = keys.public_key().to_bytes();
        McpServer::with_signing(pubkey, secret)
    }

    async fn install_session(server: &McpServer, scope: SessionScope) {
        let config = SessionConfig::new(scope).with_duration_hours(1);
        let (token, sid) = server.create_session(config).await.expect("create session");
        server.set_session(token, sid).await;
    }

    fn rpc_id(id: i64, method: &str, params: Value) -> String {
        serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
            .to_string()
    }

    fn rpc(method: &str, params: Value) -> String {
        rpc_id(1, method, params)
    }

    fn call(name: &str, arguments: Value) -> String {
        rpc(
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        )
    }

    #[tokio::test]
    async fn mcp_initialize_handshake_over_jsonrpc() {
        let server = signing_server();
        let resp = server
            .handle_request_async(&rpc_id(42, "initialize", Value::Null))
            .await;
        assert!(resp.error.is_none());
        // The response must echo the request id (JSON-RPC correlation).
        assert_eq!(resp.id, serde_json::json!(42));
        let r = resp.result.expect("initialize result");
        // Assert usable values, not just presence: `get()` also succeeds on null.
        assert!(
            r["protocolVersion"].as_str().is_some(),
            "protocolVersion must be a non-null string"
        );
        assert!(
            r["serverInfo"].as_object().is_some(),
            "serverInfo must be a non-null object"
        );
    }

    #[tokio::test]
    async fn mcp_tools_list_reports_the_signing_toolset() {
        let server = signing_server();
        let resp = server
            .handle_request_async(&rpc("tools/list", Value::Null))
            .await;
        let r = resp.result.expect("tools/list result");
        let names: Vec<String> = r["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        for expected in [
            "sign_nostr_event",
            "sign_bitcoin_psbt",
            "get_nostr_pubkey",
            "get_bitcoin_address",
            "get_session_info",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "tools/list missing {expected}; got {names:?}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_tools_call_requires_an_active_session() {
        // Fail-closed: with no session established, a signing tool is refused
        // rather than executed.
        let server = signing_server();
        let resp = server
            .handle_request_async(&call("get_nostr_pubkey", serde_json::json!({})))
            .await;
        let e = resp.error.expect("no-session call must error");
        assert!(
            e.message.contains("No active session"),
            "got: {}",
            e.message
        );
    }

    #[tokio::test]
    async fn mcp_get_nostr_pubkey_succeeds_within_scope() {
        let server = signing_server();
        install_session(&server, SessionScope::nostr_only()).await;
        let resp = server
            .handle_request_async(&call("get_nostr_pubkey", serde_json::json!({})))
            .await;
        assert!(resp.error.is_none());
        let r = resp.result.expect("result");
        assert_eq!(r["isError"], serde_json::json!(false));
        let text = r["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert!(payload.get("npub").is_some() && payload.get("hex").is_some());
    }

    #[tokio::test]
    async fn mcp_sign_nostr_event_produces_a_signed_event() {
        let server = signing_server();
        install_session(&server, SessionScope::nostr_only()).await;
        let resp = server
            .handle_request_async(&call(
                "sign_nostr_event",
                serde_json::json!({"kind": 1, "content": "hello from the mcp test", "tags": []}),
            ))
            .await;
        assert!(resp.error.is_none(), "sign failed: {:?}", resp.error);
        let r = resp.result.expect("result");
        assert_eq!(r["isError"], serde_json::json!(false));
        let text = r["content"][0]["text"].as_str().unwrap();
        let event: Value = serde_json::from_str(text).unwrap();
        assert!(event.get("id").is_some() && event.get("sig").is_some());
        assert_eq!(event["kind"], serde_json::json!(1));
    }

    #[tokio::test]
    async fn mcp_enforces_the_operation_scope() {
        // The permission model: a bitcoin-only session must NOT be able to sign a
        // Nostr event; the operation is refused before any key is used.
        let server = signing_server();
        install_session(&server, SessionScope::bitcoin_only()).await;
        let resp = server
            .handle_request_async(&call(
                "sign_nostr_event",
                serde_json::json!({"kind": 1, "content": "x", "tags": []}),
            ))
            .await;
        // Assert it failed for the RIGHT reason (the scope check), not some
        // unrelated error that would also set `error`.
        let e = resp
            .error
            .unwrap_or_else(|| panic!("out-of-scope op must be refused, got {:?}", resp.result));
        assert!(
            e.message.contains("not allowed"),
            "expected an operation-not-allowed refusal, got: {}",
            e.message
        );
    }

    #[tokio::test]
    async fn mcp_get_bitcoin_address_succeeds_within_scope() {
        let server = signing_server();
        install_session(&server, SessionScope::bitcoin_only()).await;
        let resp = server
            .handle_request_async(&call(
                "get_bitcoin_address",
                serde_json::json!({"type": "p2tr", "network": "testnet"}),
            ))
            .await;
        assert!(
            resp.error.is_none(),
            "get_bitcoin_address failed: {:?}",
            resp.error
        );
        let r = resp.result.expect("result");
        assert_eq!(r["isError"], serde_json::json!(false));
        let payload: Value =
            serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
        assert!(payload.get("address").is_some());
    }

    #[tokio::test]
    async fn mcp_get_session_info_reports_the_active_session() {
        let server = signing_server();
        install_session(&server, SessionScope::nostr_only()).await;
        let resp = server
            .handle_request_async(&call("get_session_info", serde_json::json!({})))
            .await;
        assert!(resp.error.is_none());
        let r = resp.result.expect("result");
        assert_eq!(r["isError"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn mcp_unknown_method_is_rejected() {
        let server = signing_server();
        let resp = server
            .handle_request_async(&rpc_id(7, "does/not/exist", Value::Null))
            .await;
        // The id is preserved even on the error path (JSON-RPC correlation).
        assert_eq!(resp.id, serde_json::json!(7));
        let e = resp.error.expect("unknown method must error");
        assert!(e.message.contains("Unknown method"), "got: {}", e.message);
    }

    #[tokio::test]
    async fn mcp_unknown_tool_returns_a_tool_error() {
        let server = signing_server();
        install_session(&server, SessionScope::nostr_only()).await;
        let resp = server
            .handle_request_async(&call("no_such_tool", serde_json::json!({})))
            .await;
        // Unknown tool is a tool-level error (isError), not a JSON-RPC error.
        let r = resp.result.expect("result");
        assert_eq!(r["isError"], serde_json::json!(true));
    }

    // --- keep-vfx3: end-to-end coverage of the financial-safety guards in the
    // sign_bitcoin_psbt tool arm, plus the event-kind gates in sign_nostr_event.
    // The predicate helpers are unit-tested in scope.rs/session.rs; these drive
    // the actual MCP wiring through handle_request_async. ---

    // A base64 PSBT with one output (`out_sats` to `output_spk`) funded by one
    // input whose witness_utxo is `in_sats`, so analyze_psbt sees a valid tx
    // (inputs >= outputs) with a controllable output amount and address. The
    // output carries no owner tap metadata, so it is treated as a spend, not change.
    fn psbt_base64_single_output(
        output_spk: keep_bitcoin::bitcoin::ScriptBuf,
        out_sats: u64,
        in_sats: u64,
    ) -> String {
        use keep_bitcoin::bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, Psbt,
            ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_sats),
                script_pubkey: output_spk,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("valid unsigned tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(in_sats),
            script_pubkey: ScriptBuf::new(),
        });
        keep_bitcoin::psbt::serialize_psbt_base64(&psbt)
    }

    // The x-only key for a fixed seed. Seed 7 is `signing_server`'s own key, so
    // `xonly_for_seed(7)` marks an output as recognized change (is_change_output
    // matches the signer's key against the output's tap_internal_key).
    fn xonly_for_seed(seed: u8) -> keep_bitcoin::bitcoin::secp256k1::XOnlyPublicKey {
        use keep_bitcoin::bitcoin::secp256k1::{Keypair, Secp256k1};
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[seed; 32]).expect("valid secret");
        keypair.x_only_public_key().0
    }

    // A deterministic testnet p2tr address from a fixed seed (distinct seeds give
    // distinct addresses). Testnet matches the tool's default network so
    // analyze_psbt's `Address::from_script` yields the same string we assert on.
    fn testnet_p2tr_address(seed: u8) -> keep_bitcoin::bitcoin::Address {
        use keep_bitcoin::bitcoin::{key::Secp256k1, Address, Network};
        Address::p2tr(
            &Secp256k1::new(),
            xonly_for_seed(seed),
            None,
            Network::Testnet,
        )
    }

    // A base64 PSBT with two outputs: an external spend (`spend_sats` to
    // `spend_spk`, no tap metadata -> not change) and a change output
    // (`change_sats` to `change_spk`) whose tap_internal_key is set so
    // is_change_output recognizes it as change. Funded by one input of `in_sats`.
    fn psbt_base64_spend_and_change(
        spend_spk: keep_bitcoin::bitcoin::ScriptBuf,
        spend_sats: u64,
        change_spk: keep_bitcoin::bitcoin::ScriptBuf,
        change_sats: u64,
        change_internal_key: keep_bitcoin::bitcoin::secp256k1::XOnlyPublicKey,
        in_sats: u64,
    ) -> String {
        use keep_bitcoin::bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, Psbt,
            ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(spend_sats),
                    script_pubkey: spend_spk,
                },
                TxOut {
                    value: Amount::from_sat(change_sats),
                    script_pubkey: change_spk,
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("valid unsigned tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(in_sats),
            script_pubkey: ScriptBuf::new(),
        });
        psbt.outputs[1].tap_internal_key = Some(change_internal_key);
        keep_bitcoin::psbt::serialize_psbt_base64(&psbt)
    }

    #[tokio::test]
    async fn mcp_sign_bitcoin_psbt_refuses_overspend() {
        // A PSBT whose total output exceeds the session's max_amount_sats must be
        // refused before any signing, through the actual MCP tool arm.
        let server = signing_server();
        install_session(
            &server,
            SessionScope::bitcoin_only().with_max_amount(10_000),
        )
        .await;
        let psbt =
            psbt_base64_single_output(testnet_p2tr_address(2).script_pubkey(), 50_000, 60_000);
        let resp = server
            .handle_request_async(&call(
                "sign_bitcoin_psbt",
                serde_json::json!({"psbt": psbt, "network": "testnet"}),
            ))
            .await;
        let e = resp
            .error
            .unwrap_or_else(|| panic!("overspend must be refused, got {:?}", resp.result));
        assert!(
            e.message.contains("Amount exceeded"),
            "expected an amount-exceeded refusal, got: {}",
            e.message
        );
    }

    #[tokio::test]
    async fn mcp_sign_bitcoin_psbt_counts_recognized_change_toward_the_amount_limit() {
        // The amount guard caps total_output_sats, INCLUDING recognized change, not
        // just the external (non-change) spend. This pins that semantic on purpose:
        // is_change is derived from client-supplied PSBT output metadata
        // (tap_internal_key), so trusting it to shrink the amount check would let a
        // malicious client relabel a large output as change to exceed the cap. Here
        // the external spend (8_000) is under the 10_000 limit but the total incl.
        // change (58_000) is over, so the request must be refused. If the guard were
        // changed to count only non-change spend, this test would fail.
        let server = signing_server();
        install_session(
            &server,
            SessionScope::bitcoin_only().with_max_amount(10_000),
        )
        .await;
        let psbt = psbt_base64_spend_and_change(
            testnet_p2tr_address(2).script_pubkey(),
            8_000,
            testnet_p2tr_address(7).script_pubkey(),
            50_000,
            xonly_for_seed(7),
            60_000,
        );
        let resp = server
            .handle_request_async(&call(
                "sign_bitcoin_psbt",
                serde_json::json!({"psbt": psbt, "network": "testnet"}),
            ))
            .await;
        let e = resp.error.unwrap_or_else(|| {
            panic!(
                "total outputs over the limit (including change) must be refused, got {:?}",
                resp.result
            )
        });
        assert!(
            e.message.contains("Amount exceeded"),
            "expected an amount-exceeded refusal counting change, got: {}",
            e.message
        );
    }

    #[tokio::test]
    async fn mcp_sign_bitcoin_psbt_refuses_non_allowlisted_output() {
        // A non-change output to an address outside the allowlist must be refused
        // through the actual MCP tool arm.
        let server = signing_server();
        let allowed = testnet_p2tr_address(3);
        let disallowed = testnet_p2tr_address(2);
        install_session(
            &server,
            SessionScope::bitcoin_only().with_address_allowlist([allowed.to_string()]),
        )
        .await;
        let psbt = psbt_base64_single_output(disallowed.script_pubkey(), 10_000, 20_000);
        let resp = server
            .handle_request_async(&call(
                "sign_bitcoin_psbt",
                serde_json::json!({"psbt": psbt, "network": "testnet"}),
            ))
            .await;
        let e = resp.error.unwrap_or_else(|| {
            panic!(
                "non-allowlisted output must be refused, got {:?}",
                resp.result
            )
        });
        assert!(
            e.message.contains("Address not allowed")
                && e.message.contains(&disallowed.to_string()),
            "expected an address-not-allowed refusal naming the output, got: {}",
            e.message
        );
    }

    #[tokio::test]
    async fn mcp_sign_bitcoin_psbt_refuses_output_with_undecodable_address_under_allowlist() {
        // Fail closed: a non-change spend output whose scriptPubKey does not decode
        // to an address cannot be confirmed against the allowlist, so it must be
        // refused rather than signed. Previously such an output escaped the check.
        let server = signing_server();
        install_session(
            &server,
            SessionScope::bitcoin_only()
                .with_address_allowlist([testnet_p2tr_address(3).to_string()]),
        )
        .await;
        // A bare OP_RETURN script has no address encoding, so Address::from_script
        // yields None and analyze_psbt records the output's address as None.
        let undecodable = keep_bitcoin::bitcoin::ScriptBuf::from_bytes(vec![0x6a]);
        let psbt = psbt_base64_single_output(undecodable, 10_000, 20_000);
        let resp = server
            .handle_request_async(&call(
                "sign_bitcoin_psbt",
                serde_json::json!({"psbt": psbt, "network": "testnet"}),
            ))
            .await;
        let e = resp.error.unwrap_or_else(|| {
            panic!(
                "undecodable output must be refused under an allowlist, got {:?}",
                resp.result
            )
        });
        assert!(
            e.message.contains("no recognizable address"),
            "expected a fail-closed refusal for the undecodable output, got: {}",
            e.message
        );
    }

    #[tokio::test]
    async fn mcp_sign_nostr_event_rejects_kind_above_u16_max() {
        let server = signing_server();
        install_session(&server, SessionScope::nostr_only()).await;
        let resp = server
            .handle_request_async(&call(
                "sign_nostr_event",
                serde_json::json!({"kind": 70_000, "content": "x", "tags": []}),
            ))
            .await;
        let e = resp
            .error
            .unwrap_or_else(|| panic!("out-of-range kind must be refused, got {:?}", resp.result));
        assert!(
            e.message.contains("exceeds maximum value"),
            "expected an out-of-range kind refusal, got: {}",
            e.message
        );
    }

    #[tokio::test]
    async fn mcp_sign_nostr_event_enforces_the_event_kind_allowlist() {
        // A session restricted to kinds {1,4,7} must refuse to sign kind 5 before
        // any key use, through the MCP tool arm.
        let server = signing_server();
        install_session(
            &server,
            SessionScope::nostr_only().with_event_kinds([1, 4, 7]),
        )
        .await;
        let resp = server
            .handle_request_async(&call(
                "sign_nostr_event",
                serde_json::json!({"kind": 5, "content": "x", "tags": []}),
            ))
            .await;
        let e = resp
            .error
            .unwrap_or_else(|| panic!("disallowed kind must be refused, got {:?}", resp.result));
        assert!(
            e.message.contains("Event kind not allowed"),
            "expected an event-kind refusal, got: {}",
            e.message
        );
    }
}
