// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::sync::Mutex;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const SECRET: &[u8] = b"tk_test_0123456789abcdef";
const HOST: &str = "echo.keep.test";

/// What the test server answers with.
#[derive(Clone)]
enum Reply {
    /// The request's head echoed back in the body, with `Set-Cookie`.
    Echo,
    /// A body that holds the secret starting at this offset.
    SecretAt(usize),
    /// A body of this many bytes, none of them the secret.
    Long(usize),
    /// A gzip-encoded body.
    Gzip,
    /// `Content-Encoding: identity`, then `gzip`.
    IdentityThenGzip,
    /// A body under the gzip transfer coding.
    TransferGzip,
    /// A redirect.
    Redirect,
}

struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

fn test_root() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(include_bytes!("../testdata/ca.pem")).unwrap())
        .unwrap();
    roots
}

async fn serve(reply: Reply) -> Server {
    let certs =
        vec![CertificateDer::from_pem_slice(include_bytes!("../testdata/leaf.pem")).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("../testdata/leaf.key")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                continue;
            };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if tls.read(&mut byte).await.unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            seen.lock().unwrap().push(head.clone());
            if matches!(reply, Reply::TransferGzip) {
                let chunk = [0x1f, 0x8b, 0, 0];
                let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n";
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await;
                let _ = tls.write_all(&chunk).await;
                let _ = tls.write_all(b"\r\n0\r\n\r\n").await;
                let _ = tls.shutdown().await;
                continue;
            }
            let (extra, body): (&str, Vec<u8>) = match &reply {
                Reply::Echo => (
                    "Set-Cookie: session=abc\r\nContent-Type: text/plain\r\n",
                    head.into_bytes(),
                ),
                Reply::SecretAt(at) => {
                    let mut body = vec![b'x'; *at];
                    body.extend_from_slice(SECRET);
                    body.extend_from_slice(&[b'y'; 64]);
                    ("", body)
                }
                Reply::Long(n) => ("", vec![b'z'; *n]),
                Reply::Gzip => ("Content-Encoding: gzip\r\n", vec![0x1f, 0x8b, 0, 0]),
                Reply::TransferGzip => unreachable!("answered above"),
                Reply::IdentityThenGzip => (
                    "Content-Encoding: identity\r\nContent-Encoding: gzip\r\n",
                    vec![0x1f, 0x8b, 0, 0],
                ),
                Reply::Redirect => ("Location: https://elsewhere.example/x\r\n", Vec::new()),
            };
            let status = if matches!(reply, Reply::Redirect) {
                "302 Found"
            } else {
                "200 OK"
            };
            let response = format!(
                "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = tls.write_all(response.as_bytes()).await;
            let _ = tls.write_all(&body).await;
            let _ = tls.shutdown().await;
        }
    });
    Server { port, requests }
}

fn env(port: u16, roots: rustls::RootCertStore, allow: fn(IpAddr) -> bool) -> Env {
    Env {
        tls: client_config(roots),
        lookup: Arc::new(move |host, _| {
            Box::pin(async move {
                assert_eq!(host, HOST);
                Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
            })
        }),
        allow,
    }
}

fn request(port: u16) -> WorkerRequest {
    let secret = std::str::from_utf8(SECRET).unwrap();
    WorkerRequest {
        method: "POST".into(),
        url: format!("https://{HOST}:{port}/v1/items"),
        headers: vec![
            ["authorization".into(), format!("Bearer {secret}")],
            ["accept-encoding".into(), "identity".into()],
            ["content-type".into(), "application/json".into()],
        ],
        body_b64: B64.encode(b"{}"),
        secret_b64: B64.encode(SECRET),
    }
}

fn any(_: IpAddr) -> bool {
    true
}

fn failed(answer: WorkerAnswer) -> Cause {
    match answer {
        WorkerAnswer::Failed(WorkerFailure { error }) => error,
        other => panic!("expected a failure, got {other:?}"),
    }
}

fn response(answer: WorkerAnswer) -> WorkerResponse {
    match answer {
        WorkerAnswer::Response(r) => r,
        other => panic!("expected a response, got {other:?}"),
    }
}

#[tokio::test]
async fn a_request_goes_out_with_its_secret_and_an_echo_of_it_is_refused() {
    let server = serve(Reply::Echo).await;
    let answer = perform(&request(server.port), &env(server.port, test_root(), any)).await;
    assert_eq!(failed(answer), Cause::SecretInResponse);
    let seen = server.requests.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let head = seen[0].to_ascii_lowercase();
    assert!(head.starts_with("post /v1/items http/1.1\r\n"), "{head}");
    assert_eq!(head.matches("authorization: bearer tk_test_").count(), 1);
    assert!(head.contains("accept-encoding: identity"));
    assert!(head.contains(&format!("host: {HOST}:{}", server.port)));
    assert!(!head.contains("proxy"));
}

#[tokio::test]
async fn a_response_without_the_secret_comes_back_with_only_the_returned_headers() {
    let server = serve(Reply::Echo).await;
    let mut req = request(server.port);
    req.secret_b64 = B64.encode(b"a-secret-not-in-the-request");
    let r = response(perform(&req, &env(server.port, test_root(), any)).await);
    assert_eq!(r.status, 200);
    assert_eq!(
        r.headers,
        [["content-type".to_string(), "text/plain".to_string()]]
    );
    assert!(!r.more);
    let body = B64.decode(&r.body_b64).unwrap();
    assert!(body.starts_with(b"POST /v1/items"));
}

#[tokio::test]
async fn a_compressed_response_is_refused() {
    for reply in [Reply::Gzip, Reply::IdentityThenGzip, Reply::TransferGzip] {
        let server = serve(reply).await;
        let answer = perform(&request(server.port), &env(server.port, test_root(), any)).await;
        assert_eq!(failed(answer), Cause::EncodedResponse);
    }
}

#[tokio::test]
async fn a_redirect_is_returned_not_followed() {
    let server = serve(Reply::Redirect).await;
    let r = response(perform(&request(server.port), &env(server.port, test_root(), any)).await);
    assert_eq!(r.status, 302);
    assert_eq!(
        r.headers,
        [[
            "location".to_string(),
            "https://elsewhere.example/x".to_string()
        ]]
    );
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_long_body_is_read_past_the_cut_and_marked() {
    let limit = MAX_RESPONSE_BODY + longest_form(SECRET.len());
    let server = serve(Reply::Long(limit + 10_000)).await;
    let r = response(perform(&request(server.port), &env(server.port, test_root(), any)).await);
    assert!(r.more);
    assert_eq!(B64.decode(&r.body_b64).unwrap().len(), limit);
    let server = serve(Reply::Long(limit)).await;
    let r = response(perform(&request(server.port), &env(server.port, test_root(), any)).await);
    assert!(!r.more, "a body that ends at the limit has no more");
}

/// A secret placed so a cut at the agent's limit would split it is still
/// found, since the worker reads past the cut.
#[tokio::test]
async fn a_secret_straddling_the_cut_is_found() {
    for at in [
        MAX_RESPONSE_BODY - 5,
        MAX_RESPONSE_BODY,
        MAX_RESPONSE_BODY + 100,
    ] {
        let server = serve(Reply::SecretAt(at)).await;
        let answer = perform(&request(server.port), &env(server.port, test_root(), any)).await;
        assert_eq!(failed(answer), Cause::SecretInResponse, "at {at}");
    }
}

#[tokio::test]
async fn an_address_that_is_not_globally_reachable_is_never_connected_to() {
    let server = serve(Reply::Echo).await;
    let answer = perform(
        &request(server.port),
        &env(server.port, test_root(), super::super::addr::is_global),
    )
    .await;
    assert_eq!(failed(answer), Cause::AddressRefused);
    assert!(server.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_server_the_release_roots_do_not_vouch_for_fails_tls() {
    let server = serve(Reply::Echo).await;
    let answer = perform(&request(server.port), &env(server.port, roots(), any)).await;
    assert_eq!(failed(answer), Cause::Tls);
    assert!(server.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_lookup_that_fails_or_finds_nothing_is_a_dns_failure() {
    let mut e = env(1, test_root(), any);
    e.lookup = Arc::new(|_, _| Box::pin(async { Ok(Vec::new()) }));
    assert_eq!(failed(perform(&request(1), &e).await), Cause::Dns);
    e.lookup = Arc::new(|_, _| Box::pin(async { Err(std::io::Error::other("no such host")) }));
    assert_eq!(failed(perform(&request(1), &e).await), Cause::Dns);
}

#[tokio::test]
async fn the_pinned_resolver_answers_only_for_its_host() {
    use reqwest::dns::Resolve;
    let pinned = Pinned {
        host: HOST.into(),
        addrs: vec![SocketAddr::from(([1, 1, 1, 1], 443))],
    };
    let ok = pinned.resolve(HOST.parse().unwrap()).await.unwrap();
    assert_eq!(
        ok.collect::<Vec<_>>(),
        [SocketAddr::from(([1, 1, 1, 1], 443))]
    );
    assert!(pinned
        .resolve("other.example".parse().unwrap())
        .await
        .is_err());
}

#[test]
fn the_release_roots_are_exactly_the_bundled_ones() {
    assert_eq!(roots().roots, webpki_roots::TLS_SERVER_ROOTS.to_vec());
}

#[tokio::test]
async fn a_malformed_request_is_refused_before_any_lookup() {
    let mut e = env(1, test_root(), any);
    e.lookup = Arc::new(|_, _| panic!("no lookup for a malformed request"));
    for change in [
        |r: &mut WorkerRequest| r.url = "http://echo.keep.test/v1".into(),
        |r: &mut WorkerRequest| r.url = "https://127.0.0.1/v1".into(),
        |r: &mut WorkerRequest| r.secret_b64 = "!".into(),
        |r: &mut WorkerRequest| r.body_b64 = "!".into(),
    ] {
        let mut req = request(1);
        change(&mut req);
        assert_eq!(failed(perform(&req, &e).await), Cause::Http);
    }
}
