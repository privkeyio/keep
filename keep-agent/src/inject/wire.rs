// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The one-line exchange between the gateway and an inject worker: the
//! request with its secret added, and the response or why there is none.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The largest request line the gateway sends a worker.
pub const MAX_REQUEST_LINE: usize = 512 * 1024;
/// The largest answer line a worker sends back: the response body read past
/// the cut, base64-encoded, and the headers.
pub const MAX_ANSWER_LINE: usize = 1024 * 1024;
/// The most response body an agent is given.
pub const MAX_RESPONSE_BODY: usize = 256 * 1024;
/// The response headers passed back, lowercase. `Set-Cookie` is never one:
/// a session it sets is a credential the agent was not granted.
pub const RETURNED_HEADERS: [&str; 4] = [
    "content-type",
    "content-encoding",
    "location",
    "retry-after",
];
/// The longest value of a returned header.
pub const MAX_HEADER_VALUE: usize = 8 * 1024;

/// A request for a worker to send. `headers` already holds the injected
/// header and `Accept-Encoding: identity`; `secret_b64` is the secret alone,
/// for the worker's own scan of the response.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<[String; 2]>,
    pub body_b64: String,
    pub secret_b64: String,
}

/// What a worker read: the status, the returned headers, and the body up to
/// [`MAX_RESPONSE_BODY`] plus the read past it the scan needs, with `more`
/// set when the body went on further.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponse {
    pub status: u16,
    pub headers: Vec<[String; 2]>,
    pub body_b64: String,
    pub more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerFailure {
    pub error: Cause,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkerAnswer {
    Response(WorkerResponse),
    Failed(WorkerFailure),
}

/// Why a request got no response, each one fixed message an agent is told,
/// never the underlying error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// No worker could be reached.
    Unavailable,
    /// Too many requests in flight.
    Busy,
    Dns,
    /// The host resolved to an address that is not globally reachable.
    AddressRefused,
    Connect,
    Tls,
    Timeout,
    /// The response was compressed or otherwise encoded.
    EncodedResponse,
    /// The response held the secret.
    SecretInResponse,
    Http,
    /// A freeze, revoke or disconnect withdrew the request.
    Canceled,
}

impl Cause {
    pub fn message(self) -> &'static str {
        match self {
            Cause::Unavailable => "unavailable",
            Cause::Busy => "busy",
            Cause::Dns => "dns",
            Cause::AddressRefused => "address refused",
            Cause::Connect => "connect",
            Cause::Tls => "tls",
            Cause::Timeout => "timeout",
            Cause::EncodedResponse => "encoded response",
            Cause::SecretInResponse => "secret in response",
            Cause::Http => "http",
            Cause::Canceled => "canceled",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_parse_as_one_shape_or_the_other() {
        let ok = r#"{"status":200,"headers":[["content-type","text/plain"]],"body_b64":"aGk=","more":false}"#;
        assert!(matches!(
            serde_json::from_str::<WorkerAnswer>(ok).unwrap(),
            WorkerAnswer::Response(WorkerResponse { status: 200, .. })
        ));
        let failed = r#"{"error":"secret_in_response"}"#;
        assert_eq!(
            serde_json::from_str::<WorkerAnswer>(failed).unwrap(),
            WorkerAnswer::Failed(WorkerFailure {
                error: Cause::SecretInResponse
            })
        );
        for bad in [
            r#"{"error":"something else"}"#,
            r#"{"error":"dns","extra":1}"#,
            r#"{"status":200,"headers":[],"body_b64":"","more":false,"error":"dns"}"#,
            r#"{"status":200}"#,
        ] {
            assert!(serde_json::from_str::<WorkerAnswer>(bad).is_err(), "{bad}");
        }
    }
}
