use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use keep_core::frost::ShareExport;

use crate::state::AppState;

pub async fn health() -> &'static str {
    "ok"
}

pub async fn bunker(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.bunker.clone())
}

#[derive(Serialize)]
pub struct ShareDto {
    name: String,
    identifier: u16,
    threshold: u16,
    total_shares: u16,
    sign_count: u64,
}

pub async fn shares(State(state): State<AppState>) -> impl IntoResponse {
    let keep = state.keep.lock().await;
    match keep.frost_list_shares() {
        Ok(shares) => {
            let dto: Vec<ShareDto> = shares
                .into_iter()
                .map(|s| ShareDto {
                    name: s.metadata.name,
                    identifier: s.metadata.identifier,
                    threshold: s.metadata.threshold,
                    total_shares: s.metadata.total_shares,
                    sign_count: s.metadata.sign_count,
                })
                .collect();
            Json(dto).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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
