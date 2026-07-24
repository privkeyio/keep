use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;

/// Shared bearer token gating every `/api/*` route and the WS upgrade.
///
/// The token comes from `KEEP_WEB_AUTH_TOKEN[_FILE]`, or from the `auth_token`
/// file persisted in the vault directory when neither is set. The value is
/// never logged: it authorizes share export, so emitting it would put a
/// credential equivalent to the share into the journal, which the `adm` group
/// can read and log shippers forward off-box. The daemon is never run fully
/// open (fail-closed).
#[derive(Clone)]
pub struct AuthToken(Arc<String>);

impl AuthToken {
    /// Build from a resolved token. Callers supply either the configured value
    /// or the persisted one; an all-whitespace value is rejected by the caller
    /// rather than silently accepted here.
    pub fn new(token: impl Into<String>) -> Self {
        Self(Arc::new(token.into().trim().to_string()))
    }

    fn matches(&self, candidate: &str) -> bool {
        candidate.as_bytes().ct_eq(self.0.as_bytes()).unwrap_u8() == 1
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
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
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
    fn new_trims_surrounding_whitespace() {
        // Secrets read from a file arrive with a trailing newline.
        let t = AuthToken::new("  pinned  \n");
        assert!(t.matches("pinned"));
        assert!(!t.matches("  pinned  "));
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
        Router::new().route("/api/x", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(token("s3cret"), require_auth),
        )
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
