// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The inject worker: one process per request, started by systemd for one
//! connection from the gateway. It resolves the host, refuses any address
//! that is not globally reachable, connects only to the addresses it checked,
//! verifies the server against fixed roots, sends the request, reads a
//! bounded response and refuses one that carries the secret. It never holds
//! the vault, and its memory, buffers HTTP and TLS libraries free unwiped
//! among it, ends with the process.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use url::{Host, Url};
use zeroize::Zeroizing;

use super::scan::{longest_form, Scanner};
use super::wire::{
    Cause, WorkerAnswer, WorkerFailure, WorkerRequest, WorkerResponse, MAX_HEADER_VALUE,
    MAX_REQUEST_LINE, MAX_RESPONSE_BODY, RETURNED_HEADERS,
};
use crate::error::{AgentError, Result};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The most a worker runs, past every timeout above.
pub const WORKER_TIMEOUT: Duration = Duration::from_secs(35);

type LookupFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

/// Resolves a host and port to the addresses to check and connect to.
pub type Lookup = Arc<dyn Fn(String, u16) -> LookupFuture + Send + Sync>;

/// What a request is sent with: the TLS settings and roots, the resolver,
/// and which resolved addresses may be connected to.
pub struct Env {
    pub tls: rustls::ClientConfig,
    pub lookup: Lookup,
    pub allow: fn(IpAddr) -> bool,
}

impl Env {
    /// The system resolver (with the name made absolute, so no search domain
    /// applies), the fixed roots, and only globally reachable addresses.
    pub fn system() -> Self {
        Self {
            tls: client_config(roots()),
            lookup: Arc::new(|host, port| {
                Box::pin(async move {
                    Ok(tokio::net::lookup_host(format!("{host}.:{port}"))
                        .await?
                        .collect())
                })
            }),
            allow: super::addr::is_global,
        }
    }
}

/// TLS 1.2 or 1.3 with the ring provider, verifying against `roots` only,
/// with no early data.
pub fn client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.enable_early_data = false;
    config
}

/// The roots a release trusts: exactly the bundled webpki roots, so the
/// trust set is fixed and out of reach of anything that can write
/// `/etc/ssl`. An e2e build (`--cfg keep_e2e_roots`) adds one test root.
pub fn roots() -> rustls::RootCertStore {
    #[allow(unused_mut)]
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    #[cfg(keep_e2e_roots)]
    {
        #[used]
        static MARKER: [u8; 20] = *b"keep-e2e-roots-build";
        let der = include_bytes!(env!("KEEP_E2E_CA_DER"));
        roots
            .add(rustls::pki_types::CertificateDer::from(&der[..]))
            .expect("the e2e test root parses");
    }
    roots
}

/// Answers for the one host it was given and refuses every other name, so a
/// connection can only go to the addresses that were checked (reqwest's own
/// overrides fall back to a live lookup for other names).
struct Pinned {
    host: String,
    addrs: Vec<SocketAddr>,
}

impl reqwest::dns::Resolve for Pinned {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let found = (name.as_str() == self.host).then(|| self.addrs.clone());
        Box::pin(async move {
            match found {
                Some(addrs) => Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs),
                None => Err("a name other than the request's host".into()),
            }
        })
    }
}

/// Send `request` and read its response, or say why not.
pub async fn perform(request: &WorkerRequest, env: &Env) -> WorkerAnswer {
    match send(request, env).await {
        Ok(response) => WorkerAnswer::Response(response),
        Err(error) => WorkerAnswer::Failed(WorkerFailure { error }),
    }
}

async fn send(request: &WorkerRequest, env: &Env) -> std::result::Result<WorkerResponse, Cause> {
    let secret = Zeroizing::new(B64.decode(&request.secret_b64).map_err(|_| Cause::Http)?);
    let body = Zeroizing::new(B64.decode(&request.body_b64).map_err(|_| Cause::Http)?);
    let url = Url::parse(&request.url).map_err(|_| Cause::Http)?;
    let host = match (url.scheme(), url.host()) {
        ("https", Some(Host::Domain(host))) => host.to_string(),
        _ => return Err(Cause::Http),
    };
    let port = url.port().unwrap_or(443);
    let addrs = tokio::time::timeout(LOOKUP_TIMEOUT, (env.lookup)(host.clone(), port))
        .await
        .map_err(|_| Cause::Dns)?
        .map_err(|_| Cause::Dns)?;
    if addrs.is_empty() {
        return Err(Cause::Dns);
    }
    // Any address that is not allowed refuses the whole lookup, rather than
    // picking another: an answer mixing in an internal address is hostile.
    if addrs.iter().any(|a| !(env.allow)(a.ip())) {
        return Err(Cause::AddressRefused);
    }
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(env.tls.clone())
        .dns_resolver(Arc::new(Pinned { host, addrs }))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .http1_only()
        .https_only(true)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|_| Cause::Http)?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|_| Cause::Http)?;
    let mut headers = reqwest::header::HeaderMap::new();
    for [name, value] in &request.headers {
        let name =
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| Cause::Http)?;
        let mut value =
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()).map_err(|_| Cause::Http)?;
        value.set_sensitive(true);
        headers.append(name, value);
    }
    let mut response = client
        .request(method, url)
        .headers(headers)
        .body(body.to_vec())
        .send()
        .await
        .map_err(classify)?;
    let status = response.status().as_u16();
    let returned: Vec<[String; 2]> = RETURNED_HEADERS
        .iter()
        .filter_map(|name| {
            let value = response.headers().get(*name)?;
            let bytes = value.as_bytes();
            (bytes.len() <= MAX_HEADER_VALUE && super::rule::is_header_value(bytes)).then(|| {
                [
                    name.to_string(),
                    String::from_utf8_lossy(bytes).into_owned(),
                ]
            })
        })
        .collect();
    // An echo counts whatever else is wrong with the response, so it is
    // looked for first, and in what was read before any failure.
    let scanner = Scanner::new(&secret);
    if returned.iter().any(|[_, v]| scanner.found_in(v.as_bytes())) {
        return Err(Cause::SecretInResponse);
    }
    // Every value counts, not only the first: a body under any encoding but
    // identity, or a transfer coding but chunked, is bytes the scan cannot
    // read.
    let headers = response.headers();
    if headers
        .get_all(reqwest::header::CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
        || headers
            .get_all(reqwest::header::TRANSFER_ENCODING)
            .iter()
            .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"chunked"))
    {
        return Err(Cause::EncodedResponse);
    }
    let limit = MAX_RESPONSE_BODY + longest_form(secret.len());
    let mut read = Zeroizing::new(Vec::with_capacity(limit));
    let failed = |error, read: &[u8]| {
        if scanner.found_in(read) {
            Cause::SecretInResponse
        } else {
            classify(error)
        }
    };
    let mut more = false;
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(e) => return Err(failed(e, &read)),
        };
        let room = limit - read.len();
        if chunk.len() > room {
            read.extend_from_slice(&chunk[..room]);
            more = true;
            break;
        }
        read.extend_from_slice(&chunk);
        if read.len() == limit {
            more = match response.chunk().await {
                Ok(next) => next.is_some_and(|c| !c.is_empty()),
                Err(e) => return Err(failed(e, &read)),
            };
            break;
        }
    }
    if scanner.found_in(&read) {
        return Err(Cause::SecretInResponse);
    }
    Ok(WorkerResponse {
        status,
        headers: returned,
        body_b64: B64.encode(&*read),
        more,
    })
}

/// A transport error's cause: a TLS failure anywhere in its chain, a
/// timeout, a failure to connect, or anything else.
fn classify(error: reqwest::Error) -> Cause {
    if error.is_timeout() {
        return Cause::Timeout;
    }
    // An `io::Error` hides what it wraps from `source()`, and TLS errors
    // arrive wrapped in more than one, so step into each one's inner error.
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(e) = next {
        if e.downcast_ref::<rustls::Error>().is_some() {
            return Cause::Tls;
        }
        next = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    if error.is_connect() {
        Cause::Connect
    } else {
        Cause::Http
    }
}

/// The worker process: read one request from standard input (the gateway's
/// connection, passed by systemd), send it, write the answer to standard
/// output. It stops at once if the gateway closes the connection first.
pub async fn run() -> Result<()> {
    if rustix::process::geteuid().is_root() {
        return Err(AgentError::Other(
            "the inject worker never runs as root".into(),
        ));
    }
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| AgentError::Other(format!("PR_SET_DUMPABLE: {e}")))?;
    let mut input = tokio::io::BufReader::new(tokio::io::stdin());
    // Sized for the longest line, so it never grows and leaves a copy of
    // the secret behind.
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_LINE + 1));
    (&mut input)
        .take(MAX_REQUEST_LINE as u64 + 1)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|e| AgentError::Other(format!("reading the request: {e}")))?;
    if line.last() != Some(&b'\n') {
        return Err(AgentError::Other(
            "the request line is incomplete or too long".into(),
        ));
    }
    let request: WorkerRequest = serde_json::from_slice(&line)
        .map_err(|_| AgentError::Other("the request does not parse".into()))?;
    let env = Env::system();
    let answer = tokio::select! {
        answer = perform(&request, &env) => answer,
        _ = closed(&mut input) => return Ok(()),
        () = tokio::time::sleep(WORKER_TIMEOUT) => WorkerAnswer::Failed(WorkerFailure { error: Cause::Timeout }),
    };
    drop(request);
    let mut out =
        serde_json::to_vec(&answer).map_err(|e| AgentError::Serialization(e.to_string()))?;
    out.push(b'\n');
    let mut stdout = tokio::io::stdout();
    stdout
        .write_all(&out)
        .await
        .and(stdout.flush().await)
        .map_err(|e| AgentError::Other(format!("writing the answer: {e}")))
}

/// Resolves once the gateway closes its side of the connection.
async fn closed<R: tokio::io::AsyncRead + Unpin>(input: &mut R) {
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests;
