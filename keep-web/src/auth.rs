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
    /// Resolve the auth token from an optionally-configured value, generating
    /// and logging a random one if none was supplied (fail-closed: never open).
    pub fn resolve(configured: Option<String>) -> Self {
        match configured {
            Some(t) if !t.trim().is_empty() => {
                tracing::info!("auth token configured; bearer auth required on all endpoints");
                Self(Arc::new(t.trim().to_string()))
            }
            _ => {
                let bytes: [u8; 32] = keep_core::crypto::random_bytes();
                let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                tracing::warn!(
                    token = %token,
                    "no auth token configured; generated a random one (set KEEP_WEB_AUTH_TOKEN[_FILE] to pin it)"
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

/// Middleware gating the API routes: requires `Authorization: Bearer <token>`,
/// compared in constant time. The WS upgrade is handled separately via
/// single-use tickets (see `state::TicketStore`) rather than this middleware,
/// so the durable token never rides in a URL.
pub async fn require_auth(
    State(token): State<AuthToken>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match bearer_from_header(&request) {
        Some(t) if token.matches(&t) => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn bearer_from_header(request: &Request) -> Option<String> {
    let value = request.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn token(t: &str) -> AuthToken {
        AuthToken(Arc::new(t.to_string()))
    }

    fn req(builder: axum::http::request::Builder) -> Request {
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn resolve_uses_configured_or_generates() {
        let configured = AuthToken::resolve(Some("  pinned  ".into()));
        assert!(configured.matches("pinned"));

        let a = AuthToken::resolve(None);
        let b = AuthToken::resolve(Some("".into()));
        // Generated tokens are random and non-empty.
        assert!(!a.matches(""));
        assert!(!a.matches(&b.0));
    }

    #[test]
    fn matches_is_exact() {
        let t = token("s3cret");
        assert!(t.matches("s3cret"));
        assert!(!t.matches("s3cre"));
        assert!(!t.matches("s3crett"));
        assert!(!t.matches(""));
        assert!(!t.matches("wrong"));
    }

    #[test]
    fn bearer_header_parsing() {
        let pull = |b: axum::http::request::Builder| bearer_from_header(&req(b));
        assert_eq!(
            pull(Request::builder().header(header::AUTHORIZATION, "Bearer abc")),
            Some("abc".into())
        );
        assert_eq!(
            pull(Request::builder().header(header::AUTHORIZATION, "bearer abc")),
            Some("abc".into())
        );
        assert_eq!(
            pull(Request::builder().header(header::AUTHORIZATION, "Bearer ")),
            None
        );
        assert_eq!(
            pull(Request::builder().header(header::AUTHORIZATION, "Basic abc")),
            None
        );
        assert_eq!(pull(Request::builder()), None);
    }

    fn app() -> Router {
        Router::new()
            .route("/api/x", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                token("s3cret"),
                require_auth,
            ))
    }

    async fn status(builder: axum::http::request::Builder) -> StatusCode {
        app().oneshot(req(builder)).await.unwrap().status()
    }

    #[tokio::test]
    async fn middleware_gates_requests() {
        assert_eq!(
            status(Request::builder().uri("/api/x")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(
                Request::builder()
                    .uri("/api/x")
                    .header(header::AUTHORIZATION, "Bearer wrong")
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(
                Request::builder()
                    .uri("/api/x")
                    .header(header::AUTHORIZATION, "Bearer s3cret")
            )
            .await,
            StatusCode::OK
        );
        // The WS query-param path is gone; a token in the URL is not accepted.
        assert_eq!(
            status(Request::builder().uri("/api/x?access_token=s3cret")).await,
            StatusCode::UNAUTHORIZED
        );
    }
}
