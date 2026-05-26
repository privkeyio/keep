use std::sync::atomic::Ordering;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use keep_core::frost::ShareExport;

use crate::state::AppState;

fn hex8(bytes: &[u8]) -> String {
    bytes[..4.min(bytes.len())]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub async fn health() -> &'static str {
    "ok"
}

pub async fn bunker(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.bunker.clone())
}

#[derive(Serialize)]
pub struct ShareDto {
    name: String,
    group: String,
    identifier: u16,
    threshold: u16,
    total_shares: u16,
    sign_count: u64,
    created_at: i64,
    last_used: Option<i64>,
    did_backup: bool,
}

pub async fn shares(State(state): State<AppState>) -> impl IntoResponse {
    let keep = state.keep.lock().await;
    match keep.frost_list_shares() {
        Ok(shares) => {
            let dto: Vec<ShareDto> = shares
                .into_iter()
                .map(|s| ShareDto {
                    name: s.metadata.name,
                    group: keep_core::keys::bytes_to_npub(&s.metadata.group_pubkey),
                    identifier: s.metadata.identifier,
                    threshold: s.metadata.threshold,
                    total_shares: s.metadata.total_shares,
                    sign_count: s.metadata.sign_count,
                    created_at: s.metadata.created_at,
                    last_used: s.metadata.last_used,
                    did_backup: s.metadata.did_backup,
                })
                .collect();
            Json(dto).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ShareRef {
    pub group: String,
    pub identifier: u16,
}

#[derive(Deserialize)]
pub struct RenameRequest {
    pub group: String,
    pub identifier: u16,
    pub name: String,
}

/// Renames a stored share.
pub async fn rename_share(
    State(state): State<AppState>,
    Json(body): Json<RenameRequest>,
) -> impl IntoResponse {
    let group = match keep_core::keys::npub_to_bytes(&body.group) {
        Ok(g) => g,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let mut keep = state.keep.lock().await;
    match keep.frost_rename_share(&group, body.identifier, &body.name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Exports a stored share, re-encrypted under `passphrase`, as a bech32
/// `kshare1…` string for backup or migration.
pub async fn export_share(
    State(state): State<AppState>,
    Json(body): Json<ExportRequest>,
) -> impl IntoResponse {
    let group = match keep_core::keys::npub_to_bytes(&body.group) {
        Ok(g) => g,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let mut keep = state.keep.lock().await;
    match keep.frost_export_share(&group, body.identifier, &body.passphrase) {
        Ok(export) => match export.to_bech32() {
            Ok(s) => Json(ExportResponse { export: s }).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ExportRequest {
    pub group: String,
    pub identifier: u16,
    pub passphrase: String,
}

#[derive(Serialize)]
pub struct ExportResponse {
    pub export: String,
}

/// Permanently deletes a stored share.
pub async fn delete_share(
    State(state): State<AppState>,
    Json(body): Json<ShareRef>,
) -> impl IntoResponse {
    let group = match keep_core::keys::npub_to_bytes(&body.group) {
        Ok(g) => g,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let mut keep = state.keep.lock().await;
    match keep.frost_delete_share(&group, body.identifier) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize)]
pub struct SigningEntryDto {
    timestamp_ms: u64,
    session: String,
    operation: String,
    participants: Vec<u16>,
    our_index: u16,
}

#[derive(Serialize)]
pub struct SigningLogResponse {
    verified: bool,
    entries: Vec<SigningEntryDto>,
}

/// Returns the FROST node's tamper-evident signing audit log (network mode).
pub async fn signing_log(State(state): State<AppState>) -> impl IntoResponse {
    let Some(node) = state.node.as_ref() else {
        return Json(SigningLogResponse {
            verified: true,
            entries: Vec::new(),
        })
        .into_response();
    };
    let log = node.audit_log();
    let verified = log.verify_all();
    let mut entries: Vec<SigningEntryDto> = log
        .entries()
        .into_iter()
        .map(|e| SigningEntryDto {
            timestamp_ms: e.timestamp_ms,
            session: hex8(&e.session_id),
            operation: format!("{:?}", e.operation),
            participants: e.participant_indices,
            our_index: e.our_index,
        })
        .collect();
    entries.reverse();
    Json(SigningLogResponse { verified, entries }).into_response()
}

#[derive(Serialize)]
pub struct KillswitchStatus {
    enabled: bool,
}

pub async fn killswitch_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(KillswitchStatus {
        enabled: state.signing_enabled.load(Ordering::Relaxed),
    })
}

#[derive(Deserialize)]
pub struct KillswitchRequest {
    pub enabled: bool,
}

/// Toggles co-signing live, with no restart — the policy hook reads this on
/// every round.
pub async fn set_killswitch(
    State(state): State<AppState>,
    Json(body): Json<KillswitchRequest>,
) -> impl IntoResponse {
    state.signing_enabled.store(body.enabled, Ordering::Relaxed);
    tracing::warn!(enabled = body.enabled, "co-signing toggled via kill switch");
    Json(KillswitchStatus {
        enabled: body.enabled,
    })
}

#[derive(Deserialize)]
pub struct ImportRequest {
    pub data: String,
    pub passphrase: String,
    pub name: Option<String>,
}

/// Imports a FROST share export (bech32 `kshare1…` or JSON) into the vault.
///
/// The share is persisted immediately and appears in `GET /api/shares`. The
/// running bunker only loads shares at startup, so signing with a newly
/// imported share requires a service restart.
pub async fn import_share(
    State(state): State<AppState>,
    Json(body): Json<ImportRequest>,
) -> impl IntoResponse {
    let export = match ShareExport::parse(body.data.trim()) {
        Ok(e) => e,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let name = body.name.unwrap_or_else(|| "imported".to_string());
    let mut keep = state.keep.lock().await;
    match keep.frost_import_share(&export, &body.passphrase, &name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ApprovalDecision {
    pub approve: bool,
}

pub async fn resolve_approval(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<ApprovalDecision>,
) -> impl IntoResponse {
    let sender = state.approvals.lock().ok().and_then(|mut m| m.remove(&id));
    match sender {
        Some(tx) => match tx.send(body.approve) {
            Ok(()) => StatusCode::NO_CONTENT,
            Err(_) => StatusCode::GONE,
        },
        None => StatusCode::NOT_FOUND,
    }
}
