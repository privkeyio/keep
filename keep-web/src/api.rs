use std::sync::atomic::Ordering;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use keep_core::error::KeepError;
use keep_core::frost::ShareExport;

use crate::state::AppState;

/// Map a keep-core error to an HTTP status: client errors (bad input, missing
/// share) vs. server-side failures (storage/IO/crypto).
fn err_status(e: &KeepError) -> StatusCode {
    match e {
        KeepError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        KeepError::KeyNotFound(_) | KeepError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn hex8(bytes: &[u8]) -> String {
    bytes[..4.min(bytes.len())]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn parse_group(npub: &str) -> Result<[u8; 32], (StatusCode, &'static str)> {
    keep_core::keys::npub_to_bytes(npub)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid group npub"))
}

pub async fn health() -> &'static str {
    "ok"
}

#[derive(Serialize)]
pub struct WsTicket {
    ticket: String,
}

/// Issues a single-use, short-lived ticket authorizing one WebSocket upgrade.
/// Gated by the bearer middleware; the ticket (not the durable token) is what
/// rides in the WS URL.
pub async fn ws_ticket(State(state): State<AppState>) -> impl IntoResponse {
    let bytes: [u8; 32] = keep_core::crypto::random_bytes();
    let ticket: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    state.ws_tickets.issue(ticket.clone());
    Json(WsTicket { ticket })
}

/// Returns the bunker connection details. The `url` carries the connection
/// `?secret=`, which is sensitive — this endpoint is gated behind bearer auth.
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
        Err(e) => {
            tracing::error!(error = %e, "frost_list_shares failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "failed to list shares").into_response()
        }
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
    let group = match parse_group(&body.group) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let mut keep = state.keep.lock().await;
    match keep.frost_rename_share(&group, body.identifier, &body.name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "frost_rename_share failed");
            (err_status(&e), "failed to rename share").into_response()
        }
    }
}

/// Exports a stored share, re-encrypted under `passphrase`, as a bech32
/// `kshare1…` string for backup or migration.
pub async fn export_share(
    State(state): State<AppState>,
    Json(body): Json<ExportRequest>,
) -> impl IntoResponse {
    let group = match parse_group(&body.group) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let mut keep = state.keep.lock().await;
    match keep.frost_export_share(&group, body.identifier, &body.passphrase) {
        Ok(export) => match export.to_bech32() {
            Ok(s) => Json(ExportResponse { export: s }).into_response(),
            Err(e) => {
                tracing::error!(error = %e, "share export to_bech32 failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to encode export").into_response()
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "frost_export_share failed");
            (err_status(&e), "failed to export share").into_response()
        }
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
    // Refuse to delete the exact share the running co-signer is using: the node
    // holds it in memory and would keep signing with a share that's gone from
    // disk, leaving an inconsistent state. The operator must reconfigure/stop
    // first. Sibling shares in the same group are not blocked.
    if state.bunker.group.as_deref() == Some(body.group.as_str())
        && state.active_identifier == Some(body.identifier)
    {
        return (
            StatusCode::CONFLICT,
            "cannot delete the active co-signer's share; reconfigure or stop the service first",
        )
            .into_response();
    }
    let group = match parse_group(&body.group) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let mut keep = state.keep.lock().await;
    match keep.frost_delete_share(&group, body.identifier) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "frost_delete_share failed");
            (err_status(&e), "failed to delete share").into_response()
        }
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
        enabled: state.signing_enabled.load(Ordering::SeqCst),
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
    state.signing_enabled.store(body.enabled, Ordering::SeqCst);
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
        Err(e) => {
            tracing::debug!(error = %e, "share import parse failed");
            return (StatusCode::BAD_REQUEST, "malformed share data").into_response();
        }
    };
    let name = body.name.unwrap_or_else(|| "imported".to_string());
    let mut keep = state.keep.lock().await;
    match keep.frost_import_share(&export, &body.passphrase, &name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "frost_import_share failed");
            (err_status(&e), "failed to import share").into_response()
        }
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
    let sender = match state.approvals.lock() {
        Ok(mut m) => m.remove(&id),
        // A poisoned mutex is a server-side failure, not a missing approval.
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    match sender {
        Some(tx) => match tx.send(body.approve) {
            Ok(()) => StatusCode::NO_CONTENT,
            Err(_) => StatusCode::GONE,
        },
        None => StatusCode::NOT_FOUND,
    }
}
