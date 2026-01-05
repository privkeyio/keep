use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

use keep_core::error::{KeepError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub id: Uuid,
    pub source_wallet: String,
    pub destination: String,
    pub amount_sats: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TransactionRequest {
    pub fn new(source_wallet: String, destination: String, amount_sats: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            source_wallet,
            destination,
            amount_sats,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalConfig {
    pub quorum: u32,
    pub from_groups: Vec<String>,
    #[serde(default = "default_timeout_hours")]
    pub timeout_hours: u32,
}

fn default_timeout_hours() -> u32 {
    24
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Allow {
        rule_id: String,
        reason: String,
    },
    Deny {
        rule_id: String,
        reason: String,
    },
    RequireApproval {
        rule_id: String,
        approval_config: ApprovalConfig,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTraceEntry {
    pub rule_id: String,
    pub matched: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub decision: PolicyDecision,
    pub policy_id: Uuid,
    pub policy_version: String,
    pub evaluated_at: DateTime<Utc>,
    pub evaluation_time_us: u64,
    pub rules_evaluated: u32,
    pub trace: Vec<RuleTraceEntry>,
}

pub struct WardenClient {
    base_url: String,
    client: Client,
    token: Option<String>,
}

impl WardenClient {
    pub fn new(base_url: &str, token: Option<String>) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| KeepError::Other(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            base_url,
            client,
            token,
        })
    }

    pub async fn evaluate(&self, request: &TransactionRequest) -> Result<EvaluationResult> {
        let url = format!("{}/v1/policies/evaluate", self.base_url);

        let mut req = self.client.post(&url).json(request);
        if let Some(ref token) = self.token {
            req = req.bearer_auth(token);
        }

        let response = req
            .send()
            .await
            .map_err(|e| KeepError::Other(format!("Warden request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(KeepError::Other(format!(
                "Warden returned {}: {}",
                status, body
            )));
        }

        response
            .json()
            .await
            .map_err(|e| KeepError::Other(format!("Failed to parse Warden response: {}", e)))
    }
}

pub enum PolicyCheckResult {
    Allowed,
    Denied {
        rule_id: String,
        reason: String,
    },
    RequiresApproval {
        rule_id: String,
        config: ApprovalConfig,
        /// The transaction ID to poll for approval status
        transaction_id: Uuid,
    },
}

pub fn get_warden_token() -> Option<String> {
    std::env::var("WARDEN_TOKEN").ok()
}

pub async fn check_policy(
    warden_url: &str,
    token: Option<String>,
    source_wallet: &str,
    destination: &str,
    amount_sats: u64,
    metadata: Option<HashMap<String, serde_json::Value>>,
) -> Result<PolicyCheckResult> {
    let client = WardenClient::new(warden_url, token)?;

    let mut request = TransactionRequest::new(
        source_wallet.to_string(),
        destination.to_string(),
        amount_sats,
    );
    let transaction_id = request.id;

    if let Some(meta) = metadata {
        request.metadata = meta;
    }

    let result = client.evaluate(&request).await?;

    match result.decision {
        PolicyDecision::Allow { .. } => Ok(PolicyCheckResult::Allowed),
        PolicyDecision::Deny { rule_id, reason } => {
            Ok(PolicyCheckResult::Denied { rule_id, reason })
        }
        PolicyDecision::RequireApproval {
            rule_id,
            approval_config,
        } => Ok(PolicyCheckResult::RequiresApproval {
            rule_id,
            config: approval_config,
            transaction_id,
        }),
    }
}

pub async fn wait_for_approval(
    warden_url: &str,
    token: Option<String>,
    transaction_id: Uuid,
    timeout_secs: u64,
) -> Result<bool> {
    let client = WardenClient::new(warden_url, token)?;

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() >= timeout {
            return Err(KeepError::Other("Approval timeout exceeded".to_string()));
        }

        let url = format!(
            "{}/v1/transactions/{}/approval-status",
            client.base_url, transaction_id
        );

        let mut req = client.client.get(&url);
        if let Some(ref token) = client.token {
            req = req.bearer_auth(token);
        }

        let response = req
            .send()
            .await
            .map_err(|e| KeepError::Other(format!("Workflow status check failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_string());
            return Err(KeepError::Other(format!(
                "Workflow status check failed: status={} body={}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct WorkflowStatusResponse {
            status: String,
        }

        let response: WorkflowStatusResponse = response
            .json()
            .await
            .map_err(|e| KeepError::Other(format!("Failed to parse status: {}", e)))?;

        match response.status.as_str() {
            "APPROVED" => return Ok(true),
            "REJECTED" => return Ok(false),
            "TIMED_OUT" => {
                return Err(KeepError::Other("Approval workflow timed out".to_string()))
            }
            "CANCELLED" => {
                return Err(KeepError::Other("Approval workflow cancelled".to_string()))
            }
            "PENDING" => {}
            other => {
                return Err(KeepError::Other(format!(
                    "Unknown workflow status: {}",
                    other
                )))
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
