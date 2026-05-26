use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;

/// Shared bearer token gating every `/api/*` route and the WS upgrade.
///
/// The token is read from `KEEP_WEB_AUTH_TOKEN`; if unset, a random one is
/// generated at startup and logged once so the operator can retrieve it. The
/// daemon is never run fully open (fail-closed).
#[derive(Clone)]
pub struct AuthToken(Arc<String>);

impl AuthToken {
    /// Resolve the auth token from the environment, generating and logging a
    /// random one if none is configured.
    pub fn from_env() -> Self {
        match std::env::var("KEEP_WEB_AUTH_TOKEN") {
            Ok(t) if !t.trim().is_empty() => {
                tracing::info!("KEEP_WEB_AUTH_TOKEN set; bearer auth required on all endpoints");
                Self(Arc::new(t))
            }
            _ => {
                let bytes: [u8; 32] = keep_core::crypto::random_bytes();
                let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                tracing::warn!(
                    token = %token,
                    "KEEP_WEB_AUTH_TOKEN not set; generated a random auth token (set the env var to pin it)"
                );
                Self(Arc::new(token))
            }
        }
    }

    fn matches(&self, candidate: &str) -> bool {
        candidate
            .as_bytes()
            .ct_eq(self.0.as_bytes())
            .unwrap_u8()
            == 1
    }
}

/// Middleware gating all routes: requires `Authorization: Bearer <token>` or,
/// for the WS upgrade (browsers cannot set headers on `WebSocket`), an
/// `access_token=<token>` query parameter. Comparison is constant-time.
pub async fn require_auth(
    State(token): State<AuthToken>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let presented = bearer_from_header(&request).or_else(|| token_from_query(&request));
    match presented {
        Some(t) if token.matches(&t) => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn bearer_from_header(request: &Request) -> Option<String> {
    let value = request.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

fn token_from_query(request: &Request) -> Option<String> {
    let query = request.uri().query()?;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == "access_token" {
            Some(v.to_string())
        } else {
            None
        }
    })
}
