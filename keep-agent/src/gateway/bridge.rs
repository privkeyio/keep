// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! `keep agent connect`: the bridge between an MCP client speaking JSON-RPC
//! on stdio and the gateway's agent socket. It wraps each request in the
//! envelope the gateway reads, `{"token": ..., "message": ...}`, and passes
//! each answer back.
//!
//! The token comes from a file only its owner can read, never from an
//! argument or the environment, which agent configurations commit and leak.
//! It is sent only to a socket the gateway's user serves, checked on every
//! connection, and every buffer holding it is wiped when dropped.
//!
//! Requests go one at a time, each answered before the next is sent, so every
//! answer belongs to the request before it. Notifications are dropped here:
//! the gateway acts on none, and they would only count against the agent's
//! limits.
//!
//! When the gateway closes the connection (it was idle, the token was
//! refused three times in a row, or the gateway restarted), the bridge keeps
//! running and connects again for the next request, so the client's session
//! survives; it also starts when the gateway is not running yet. A request is
//! sent again only when the gateway cannot have read it: its line was not
//! sent whole, or the gateway closed the connection with it unread. Once the
//! gateway may have read a request, losing the connection before its answer
//! is an error for the client, never a retry: the gateway may already have
//! signed and recorded it.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::daemon::server::{self, ConnectError, MAX_LINE};
use super::daemon::state::REFUSED_CODE;
use crate::error::{AgentError, Result};

/// The request was not sent, or the gateway closed the connection without
/// reading it.
pub const UNREACHABLE: i64 = -32010;

/// The request was sent and no answer came, so the gateway may have carried
/// it out.
pub const LOST: i64 = -32011;

const NOT_SENT: &str = "the gateway cannot be reached; the request was not sent";
const MAYBE_DONE: &str = "no answer came from the gateway; the request may have been carried \
                          out, so it was not sent again";
const TOO_LARGE: &str = "request too large for the gateway";

/// The longest answer read from the gateway: far more than a signed PSBT of
/// the largest request the gateway reads.
pub const MAX_ANSWER: usize = 64 * 1024 * 1024;

/// The largest token file read. A token is 73 bytes.
const MAX_TOKEN_FILE: usize = 256;

/// Variables that hold vault secrets. An agent can read its own environment,
/// so a bridge started with any of them set has handed the agent what the
/// gateway exists to keep from it.
pub const VAULT_SECRET_VARS: [&str; 7] = [
    "KEEP_PASSWORD",
    "KEEP_NEW_PASSWORD",
    "KEEP_HIDDEN_PASSWORD",
    "KEEP_DURESS_PASSWORD",
    "KEEP_NSEC",
    "KEEP_STORAGE_KEY",
    "KEEP_WEB_AUTH_TOKEN",
];

/// The first vault secret variable `is_set` reports, if any.
pub fn vault_secret_var(is_set: impl Fn(&str) -> bool) -> Option<&'static str> {
    VAULT_SECRET_VARS.into_iter().find(|v| is_set(v))
}

/// An agent token, wiped when dropped and never printed.
pub struct Token(Zeroizing<String>);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// Read the token from `path`, which must be a regular file owned by
    /// `owner` and closed to everyone else. The checks are made on the file
    /// opened, so it cannot be swapped between check and read.
    pub fn read(path: &Path, owner: u32) -> Result<Self> {
        // A token given in place of the path is not repeated in errors.
        let shown = if path
            .to_string_lossy()
            .contains(keep_core::agent::TOKEN_PREFIX)
        {
            "(not shown: the path looks like a token; pass the path of the file holding it)"
                .to_string()
        } else {
            path.display().to_string()
        };
        let fail = |m: String| AgentError::Other(format!("token file {shown}: {m}"));
        // Non-blocking, so a FIFO put in its place cannot hang the open.
        let flags = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags.bits() as i32)
            .open(path)
            .map_err(|e| fail(e.to_string()))?;
        let meta = file.metadata().map_err(|e| fail(e.to_string()))?;
        if !meta.file_type().is_file() {
            return Err(fail("is not a regular file".into()));
        }
        if meta.uid() != owner {
            return Err(fail(format!(
                "is owned by uid {}, not uid {owner}, which runs the bridge",
                meta.uid()
            )));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(fail(format!(
                "has mode {:o}; it must be readable by its owner alone (chmod 600)",
                meta.mode() & 0o7777
            )));
        }
        let mut buf = Zeroizing::new([0u8; MAX_TOKEN_FILE + 1]);
        let mut len = 0;
        loop {
            match file.read(&mut buf[len..]) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(fail(e.to_string())),
            }
        }
        let token = std::str::from_utf8(&buf[..len])
            .ok()
            .filter(|_| len <= MAX_TOKEN_FILE)
            .map(str::trim)
            .filter(|t| keep_core::agent::well_formed_token(t))
            .ok_or_else(|| {
                fail(format!(
                    "does not hold an agent token ({}, then 64 lowercase hex digits)",
                    keep_core::agent::TOKEN_PREFIX
                ))
            })?;
        Ok(Self(Zeroizing::new(token.to_string())))
    }

    /// The request line for `message`: the envelope and its newline, built
    /// in one buffer of its final size, so no copy of the token is left
    /// behind unwiped.
    fn envelope(&self, message: &[u8]) -> Zeroizing<Vec<u8>> {
        const HEAD: &[u8] = b"{\"token\":\"";
        const MIDDLE: &[u8] = b"\",\"message\":";
        const TAIL: &[u8] = b"}\n";
        let size = HEAD.len() + self.0.len() + MIDDLE.len() + message.len() + TAIL.len();
        let mut line = Zeroizing::new(Vec::with_capacity(size));
        line.extend_from_slice(HEAD);
        line.extend_from_slice(self.0.as_bytes());
        line.extend_from_slice(MIDDLE);
        line.extend_from_slice(message);
        line.extend_from_slice(TAIL);
        line
    }
}

/// When the bridge stops using a connection the gateway is about to close,
/// and how long it waits on one.
#[derive(Debug, Clone)]
pub struct Timing {
    /// How long a connection no token was accepted on is used: under the
    /// gateway's pre-auth deadline.
    pub fresh_for: Duration,
    /// How long a connection a token was accepted on may sit idle and still
    /// be used: under the gateway's idle timeout.
    pub idle_for: Duration,
    /// Refused requests in a row after which the gateway closes the
    /// connection.
    pub refusals_in_a_row: u32,
    /// How long the gateway may take to accept a connection.
    pub connect_timeout: Duration,
    /// How long an answer may take.
    pub answer_timeout: Duration,
    /// How long sending a request may take.
    pub write_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        let gateway = server::Limits::default();
        Self {
            fresh_for: gateway.pre_auth.saturating_sub(Duration::from_secs(1)),
            idle_for: gateway.idle.saturating_sub(Duration::from_secs(10)),
            refusals_in_a_row: gateway.refusals_in_a_row,
            connect_timeout: Duration::from_secs(10),
            answer_timeout: Duration::from_secs(150),
            write_timeout: Duration::from_secs(30),
        }
    }
}

/// One connection to the gateway.
struct Conn {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    opened: Instant,
    last_answer: Instant,
    /// Whether a token was accepted on it.
    accepted: bool,
    /// Refused requests since the last accepted one.
    refusals: u32,
}

impl Conn {
    fn open(
        socket: &Path,
        gateway_uid: u32,
        timing: &Timing,
    ) -> std::result::Result<Self, ConnectError> {
        let stream = server::connect_verified(socket, gateway_uid, timing.connect_timeout)?;
        let io = |e: std::io::Error| ConnectError::Rejected(format!("{}: {e}", socket.display()));
        stream
            .set_read_timeout(Some(timing.answer_timeout))
            .map_err(io)?;
        stream
            .set_write_timeout(Some(timing.write_timeout))
            .map_err(io)?;
        let reader = BufReader::with_capacity(64 * 1024, stream.try_clone().map_err(io)?);
        let now = Instant::now();
        Ok(Self {
            stream,
            reader,
            opened: now,
            last_answer: now,
            accepted: false,
            refusals: 0,
        })
    }

    /// Whether the gateway will still read a request sent now: it has not
    /// closed the connection and is not about to.
    fn usable(&self, timing: &Timing) -> bool {
        let fresh = if self.accepted {
            self.last_answer.elapsed() < timing.idle_for
        } else {
            self.opened.elapsed() < timing.fresh_for
        };
        fresh
            && self.refusals < timing.refusals_in_a_row
            && self.reader.buffer().is_empty()
            && self.open_and_quiet()
    }

    /// The gateway sends nothing unasked, so anything waiting to be read is
    /// either the end of the connection or a fault.
    fn open_and_quiet(&self) -> bool {
        let mut byte = [0u8; 1];
        let flags = rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT;
        matches!(
            rustix::net::recv(&self.stream, &mut byte[..], flags),
            Err(rustix::io::Errno::AGAIN)
        )
    }

    /// Send a whole request line. An error means its newline was not sent,
    /// so the gateway never reads the request.
    fn send(&mut self, line: &[u8]) -> std::io::Result<()> {
        (&self.stream).write_all(line)?;
        (&self.stream).flush()
    }

    /// The next answer line, without its newline.
    fn answer(&mut self) -> std::io::Result<Vec<u8>> {
        let mut line = Vec::new();
        (&mut self.reader)
            .take(MAX_ANSWER as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if line.last() == Some(&b'\n') {
            line.pop();
            return Ok(line);
        }
        Err(if line.len() > MAX_ANSWER {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "answer too long")
        } else {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the gateway closed the connection",
            )
        })
    }
}

/// A message from the client, sorted by what the bridge does with it.
#[derive(Debug, PartialEq)]
enum Incoming {
    /// Nothing to send or answer.
    Drop,
    /// Answered by the bridge.
    Answer(Value),
    /// A request for the gateway.
    Forward { id: Value, message: Vec<u8> },
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn classify(line: &[u8]) -> Incoming {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Incoming::Drop;
    }
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return Incoming::Answer(rpc_error(Value::Null, -32700, "parse error"));
    };
    let Some(object) = value.as_object() else {
        return Incoming::Answer(rpc_error(
            Value::Null,
            -32600,
            "invalid request: one JSON-RPC message per line, and no batches",
        ));
    };
    let id = object.get("id").cloned();
    let has_method = object.get("method").is_some_and(Value::is_string);
    match (id, has_method) {
        (Some(id), true) => match serde_json::to_vec(&value) {
            Ok(message) => Incoming::Forward { id, message },
            Err(_) => Incoming::Answer(rpc_error(id, -32600, "invalid request")),
        },
        // A notification: the gateway acts on none.
        (None, true) => Incoming::Drop,
        // A response: the gateway asks the client nothing.
        (_, false) if object.contains_key("result") || object.contains_key("error") => {
            Incoming::Drop
        }
        (id, false) => Incoming::Answer(rpc_error(
            id.unwrap_or(Value::Null),
            -32600,
            "invalid request",
        )),
    }
}

/// A line from the client.
#[derive(Debug, PartialEq)]
enum Line {
    Text(Vec<u8>),
    /// Longer than the limit: read through and discarded.
    TooLong,
}

/// The next line from the client of at most `max` bytes, or `None` at the
/// end of input.
fn read_line(input: &mut impl BufRead, max: usize) -> std::io::Result<Option<Line>> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buf = match input.fill_buf() {
            Ok(buf) => buf,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            return Ok(match (too_long, line.is_empty()) {
                (true, _) => Some(Line::TooLong),
                (false, true) => None,
                (false, false) => Some(Line::Text(line)),
            });
        }
        let (chunk, used, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(at) => (&buf[..at], at + 1, true),
            None => (buf, buf.len(), false),
        };
        if !too_long {
            if line.len() + chunk.len() > max {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        input.consume(used);
        if done {
            if too_long {
                return Ok(Some(Line::TooLong));
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(Line::Text(line)));
        }
    }
}

/// Why a request got no answer.
enum Failure {
    /// No connection could be made, so nothing was sent.
    NoConnection(String),
    /// The gateway cannot have read the request.
    Unread(String),
    /// The gateway may have read the request.
    Lost(String),
}

/// The bridge: one token, one gateway, at most one connection at a time.
pub struct Bridge {
    socket: PathBuf,
    gateway_uid: u32,
    token: Token,
    timing: Timing,
    conn: Option<Conn>,
}

impl Bridge {
    /// Connect to the gateway at `socket`, which must be served by
    /// `gateway_uid` from a directory only that uid can write, or fail if
    /// anything there is not the gateway's. A gateway that is not running
    /// yet is connected to when the first request comes. Nothing is sent
    /// until then.
    pub fn connect(socket: &Path, gateway_uid: u32, token: Token, timing: Timing) -> Result<Self> {
        let conn = match Conn::open(socket, gateway_uid, &timing) {
            Ok(conn) => Some(conn),
            Err(ConnectError::Absent(why)) => {
                tracing::debug!(%why, "the gateway is not running yet");
                None
            }
            Err(e @ ConnectError::Rejected(_)) => return Err(e.into()),
        };
        Ok(Self {
            socket: socket.to_path_buf(),
            gateway_uid,
            token,
            timing,
            conn,
        })
    }

    /// Whether a connection to the gateway is open.
    pub fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    /// Bridge `input` to the gateway and its answers to `output` until
    /// `input` ends.
    pub fn serve(&mut self, mut input: impl BufRead, mut output: impl Write) -> Result<()> {
        let io = |e: std::io::Error| AgentError::Other(format!("stdio: {e}"));
        loop {
            let incoming = match read_line(&mut input, MAX_LINE).map_err(io)? {
                None => return Ok(()),
                Some(Line::Text(line)) => classify(&line),
                Some(Line::TooLong) => Incoming::Answer(rpc_error(Value::Null, -32600, TOO_LARGE)),
            };
            let answer = match incoming {
                Incoming::Drop => continue,
                Incoming::Answer(answer) => answer,
                Incoming::Forward { id, message } => self.forward(id, &message),
            };
            let mut line = serde_json::to_vec(&answer)
                .map_err(|e| AgentError::Serialization(e.to_string()))?;
            line.push(b'\n');
            output.write_all(&line).map_err(io)?;
            output.flush().map_err(io)?;
        }
    }

    /// Send one request and return the gateway's answer, or an error for the
    /// client that says whether the request may have been carried out.
    fn forward(&mut self, id: Value, message: &[u8]) -> Value {
        let line = self.token.envelope(message);
        if line.len() - 1 > MAX_LINE {
            return rpc_error(id, -32600, TOO_LARGE);
        }
        let mut outcome = self.attempt(&line, &id);
        // A request the gateway cannot have read goes once more, on a new
        // connection.
        if let Err(Failure::Unread(why)) = &outcome {
            tracing::debug!(%why, "the request was not read; sending it again");
            outcome = self.attempt(&line, &id);
        }
        match outcome {
            Ok(answer) => answer,
            Err(Failure::NoConnection(why) | Failure::Unread(why)) => {
                tracing::error!(%why, "the request was not sent to the gateway");
                rpc_error(id, UNREACHABLE, NOT_SENT)
            }
            Err(Failure::Lost(why)) => {
                tracing::error!(%why, "no answer from the gateway");
                rpc_error(id, LOST, MAYBE_DONE)
            }
        }
    }

    /// Send a request line on a connection the gateway will read it from,
    /// and take its answer.
    fn attempt(&mut self, line: &[u8], id: &Value) -> std::result::Result<Value, Failure> {
        let conn = match self.conn.take() {
            Some(conn) if conn.usable(&self.timing) => conn,
            _ => Conn::open(&self.socket, self.gateway_uid, &self.timing)
                .map_err(|e| Failure::NoConnection(e.to_string()))?,
        };
        let conn = self.conn.insert(conn);
        let outcome = match conn.send(line) {
            Err(e) => Err(Failure::Unread(e.to_string())),
            // Sent: from here the gateway may have acted on it.
            Ok(()) => match conn.answer() {
                Ok(answer) => take_answer(conn, &answer, id).map_err(Failure::Lost),
                // The gateway closed the connection with the request still
                // unread in it.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    Err(Failure::Unread(e.to_string()))
                }
                Err(e) => Err(Failure::Lost(e.to_string())),
            },
        };
        if outcome.is_err() {
            self.conn = None;
        }
        outcome
    }
}

/// Check that an answer is for the request sent, and note what it says about
/// the connection. The gateway answers a refusal it makes before reading the
/// request with a null id, which is given the request's id here: only one
/// request is ever waiting.
fn take_answer(conn: &mut Conn, answer: &[u8], id: &Value) -> std::result::Result<Value, String> {
    let mut answer: Value =
        serde_json::from_slice(answer).map_err(|e| format!("unexpected answer: {e}"))?;
    let object = answer
        .as_object_mut()
        .ok_or("unexpected answer: not an object")?;
    match object.get("id") {
        Some(Value::Null) => {
            object.insert("id".into(), id.clone());
        }
        Some(got) if got == id => {}
        _ => return Err("unexpected answer: not for the request sent".into()),
    }
    let refused = object
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
        == Some(REFUSED_CODE);
    conn.last_answer = Instant::now();
    if refused {
        conn.refusals += 1;
    } else {
        conn.accepted = true;
        conn.refusals = 0;
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::testing::me;
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const TOKEN: &str = "keep_agt_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn token_file(dir: &Path, contents: &str, mode: u32) -> PathBuf {
        let path = dir.join(format!("token-{mode:o}-{}", contents.len()));
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn read_err(path: &Path, owner: u32) -> String {
        Token::read(path, owner).unwrap_err().to_string()
    }

    #[test]
    fn the_token_is_read_only_from_a_file_its_owner_alone_can_read() {
        let dir = tempfile::tempdir().unwrap();
        for contents in [
            TOKEN.to_string(),
            format!("{TOKEN}\n"),
            format!(" {TOKEN}\r\n"),
        ] {
            let token = Token::read(&token_file(dir.path(), &contents, 0o600), me()).unwrap();
            assert_eq!(token.0.as_str(), TOKEN);
        }
        let token = Token::read(&token_file(dir.path(), TOKEN, 0o400), me()).unwrap();
        assert_eq!(format!("{token:?}"), "Token(..)", "never printed");

        for mode in [0o640, 0o604, 0o660, 0o644, 0o610] {
            let err = read_err(&token_file(dir.path(), TOKEN, mode), me());
            assert!(
                err.contains("readable by its owner alone"),
                "{mode:o}: {err}"
            );
            assert!(!err.contains(TOKEN));
        }
        let err = read_err(&token_file(dir.path(), TOKEN, 0o600), me() + 1);
        assert!(err.contains("is owned by uid"), "{err}");
        assert!(read_err(&dir.path().join("missing"), me()).contains("missing"));
        // The token itself given as the path is not repeated.
        let err = read_err(Path::new(TOKEN), me());
        assert!(err.contains("not shown"), "{err}");
        assert!(!err.contains("0123456789abcdef"), "{err}");
        assert!(read_err(dir.path(), me()).contains("not a regular file"));

        // A FIFO is refused without waiting for a writer.
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(read_err(&fifo, me()).contains("not a regular file"));

        for bad in [
            "",
            "keep_agt_",
            &TOKEN.to_uppercase(),
            &TOKEN[..TOKEN.len() - 1],
            &format!("{TOKEN}0"),
            &format!("{TOKEN}\n{TOKEN}"),
            &format!("{TOKEN}{}", " ".repeat(MAX_TOKEN_FILE)),
        ] {
            let err = read_err(&token_file(dir.path(), bad, 0o600), me());
            assert!(
                err.contains("does not hold an agent token"),
                "{bad:?}: {err}"
            );
            assert!(!err.contains("0123456789abcdef"), "{err}");
        }
    }

    #[test]
    fn a_vault_secret_in_the_environment_is_found_by_name() {
        assert_eq!(vault_secret_var(|_| false), None);
        for var in VAULT_SECRET_VARS {
            assert_eq!(vault_secret_var(|v| v == var), Some(var));
        }
    }

    #[test]
    fn the_envelope_is_the_gateway_format() {
        let token = Token(Zeroizing::new(TOKEN.into()));
        let message = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let line = token.envelope(message);
        assert_eq!(line.capacity(), line.len(), "built at its final size");
        assert_eq!(line.last(), Some(&b'\n'));
        let parsed: Value = serde_json::from_slice(&line[..line.len() - 1]).unwrap();
        assert_eq!(
            parsed,
            json!({ "token": TOKEN, "message": { "jsonrpc": "2.0", "id": 1, "method": "ping" } })
        );
    }

    #[test]
    fn client_messages_are_classified_as_requests_notifications_and_errors() {
        let forward = |line: &str| match classify(line.as_bytes()) {
            Incoming::Forward { id, message } => {
                (id, serde_json::from_slice::<Value>(&message).unwrap())
            }
            other => panic!("{line}: {other:?}"),
        };
        let (id, message) = forward(r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#);
        assert_eq!(id, json!("a"));
        assert_eq!(message["method"], json!("tools/list"));
        assert_eq!(forward(r#"{"id":null,"method":"x"}"#).0, Value::Null);

        for drop in [
            "",
            "  \t",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":3,"error":{"code":1,"message":"x"}}"#,
        ] {
            assert_eq!(classify(drop.as_bytes()), Incoming::Drop, "{drop}");
        }
        let answer = |line: &str| match classify(line.as_bytes()) {
            Incoming::Answer(a) => (a["id"].clone(), a["error"]["code"].as_i64().unwrap()),
            other => panic!("{line}: {other:?}"),
        };
        assert_eq!(answer("{nope"), (Value::Null, -32700));
        assert_eq!(
            answer(r#"[{"id":1,"method":"ping"}]"#),
            (Value::Null, -32600)
        );
        assert_eq!(answer("7"), (Value::Null, -32600));
        assert_eq!(answer(r#"{"id":4,"method":5}"#), (json!(4), -32600));
        assert_eq!(answer(r#"{"id":4}"#), (json!(4), -32600));
    }

    #[test]
    fn client_lines_are_split_and_a_long_one_is_skipped_whole() {
        let mut input =
            std::io::Cursor::new([b"a\r\n".as_slice(), &[b'x'; 40], b"\nb\nlast"].concat());
        let mut next = || read_line(&mut input, 10).unwrap();
        assert_eq!(next(), Some(Line::Text(b"a".to_vec())));
        assert_eq!(next(), Some(Line::TooLong));
        assert_eq!(next(), Some(Line::Text(b"b".to_vec())));
        assert_eq!(next(), Some(Line::Text(b"last".to_vec())));
        assert_eq!(next(), None);
        let mut long_at_end = std::io::Cursor::new(vec![b'y'; 11]);
        assert_eq!(
            read_line(&mut long_at_end, 10).unwrap(),
            Some(Line::TooLong)
        );
        assert_eq!(read_line(&mut long_at_end, 10).unwrap(), None);
    }
}

/// A client on the bridge's stdio, and stand-in gateways that do what the
/// real one does at its edges.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::{Arc, Mutex};

    pub(crate) fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    pub(crate) fn token(text: &str) -> Token {
        Token(Zeroizing::new(text.into()))
    }

    /// An MCP client talking to a bridge running on its own thread.
    pub(crate) struct Client {
        to: UnixStream,
        from: BufReader<UnixStream>,
        bridge: std::thread::JoinHandle<Result<()>>,
    }

    impl Client {
        pub(crate) fn start(mut bridge: Bridge) -> Self {
            let (to, input) = UnixStream::pair().unwrap();
            let (output, from) = UnixStream::pair().unwrap();
            from.set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            let bridge = std::thread::spawn(move || bridge.serve(BufReader::new(input), output));
            Self {
                to,
                from: BufReader::new(from),
                bridge,
            }
        }

        pub(crate) fn send(&mut self, line: &str) {
            self.to.write_all(format!("{line}\n").as_bytes()).unwrap();
        }

        pub(crate) fn recv(&mut self) -> Value {
            let mut line = String::new();
            self.from.read_line(&mut line).expect("an answer in time");
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
        }

        pub(crate) fn ask(&mut self, line: &str) -> Value {
            self.send(line);
            self.recv()
        }

        pub(crate) fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
            let message = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
            let answer = self.ask(&message.to_string());
            assert_eq!(answer["id"], json!(id), "{answer}");
            answer
        }

        /// End the client's input and wait for the bridge to stop.
        pub(crate) fn finish(self) -> Result<()> {
            drop(self.to);
            self.bridge.join().unwrap()
        }
    }

    /// One connection to a stand-in gateway.
    pub(crate) struct Peer {
        pub(crate) index: usize,
        reader: BufReader<UnixStream>,
        writer: UnixStream,
        log: Arc<Mutex<Vec<(usize, Value)>>>,
    }

    impl Peer {
        /// The next envelope, recorded, or `None` once the bridge closed.
        pub(crate) fn next(&mut self) -> Option<Value> {
            let mut line = String::new();
            if self.reader.read_line(&mut line).ok()? == 0 || !line.ends_with('\n') {
                return None;
            }
            let envelope: Value = serde_json::from_str(&line).unwrap();
            self.log
                .lock()
                .unwrap()
                .push((self.index, envelope.clone()));
            Some(envelope)
        }

        pub(crate) fn reply(&mut self, answer: &Value) {
            self.writer
                .write_all(format!("{answer}\n").as_bytes())
                .unwrap();
        }

        pub(crate) fn write_raw(&mut self, bytes: &[u8]) {
            self.writer.write_all(bytes).unwrap();
        }

        /// Answer the envelope's request with an empty result.
        pub(crate) fn ok(&mut self, envelope: &Value) {
            let id = envelope["message"]["id"].clone();
            self.reply(&json!({ "jsonrpc": "2.0", "id": id, "result": {} }));
        }

        /// Serve every request with an empty result until the bridge closes.
        pub(crate) fn serve(mut self) {
            while let Some(envelope) = self.next() {
                self.ok(&envelope);
            }
        }

        /// Everything left on the connection once the bridge closes it.
        pub(crate) fn rest(mut self) -> Vec<u8> {
            let mut rest = Vec::new();
            let _ = self.reader.read_to_end(&mut rest);
            rest
        }
    }

    /// A stand-in gateway in a directory only this uid can write, handing
    /// each connection to `handler` on a thread of its own.
    pub(crate) struct Fake {
        dir: tempfile::TempDir,
        pub(crate) path: PathBuf,
        log: Arc<Mutex<Vec<(usize, Value)>>>,
    }

    impl Fake {
        /// A directory for a gateway that is not listening yet.
        pub(crate) fn empty() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("agent.sock");
            Self {
                dir,
                path,
                log: Arc::default(),
            }
        }

        pub(crate) fn start(handler: impl Fn(Peer) + Send + Sync + 'static) -> Self {
            let fake = Self::empty();
            fake.listen(handler);
            fake
        }

        /// Serve on the same path again, with a new handler.
        pub(crate) fn listen(&self, handler: impl Fn(Peer) + Send + Sync + 'static) {
            let listener = std::os::unix::net::UnixListener::bind(&self.path).unwrap();
            let log = self.log.clone();
            let handler = Arc::new(handler);
            std::thread::spawn(move || {
                for (index, stream) in listener.incoming().enumerate() {
                    let Ok(stream) = stream else { return };
                    let peer = Peer {
                        index,
                        reader: BufReader::new(stream.try_clone().unwrap()),
                        writer: stream,
                        log: log.clone(),
                    };
                    let handler = handler.clone();
                    std::thread::spawn(move || handler(peer));
                }
            });
        }

        /// Stop serving: the socket is gone.
        pub(crate) fn remove(&self) {
            std::fs::remove_file(&self.path).unwrap();
        }

        pub(crate) fn dir(&self) -> &Path {
            self.dir.path()
        }

        /// The envelopes received, with the connection each came on.
        pub(crate) fn log(&self) -> Vec<(usize, Value)> {
            self.log.lock().unwrap().clone()
        }

        /// The ids of the requests received, by connection.
        pub(crate) fn ids(&self) -> Vec<(usize, Value)> {
            self.log()
                .into_iter()
                .map(|(i, e)| (i, e["message"]["id"].clone()))
                .collect()
        }
    }

    /// Long enough that only the check a test exercises moves the bridge to
    /// a new connection.
    pub(crate) fn patient() -> Timing {
        Timing {
            fresh_for: Duration::from_secs(60),
            idle_for: Duration::from_secs(60),
            refusals_in_a_row: 3,
            connect_timeout: Duration::from_secs(10),
            answer_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
        }
    }
}

#[cfg(test)]
mod socket_tests {
    use super::testing::*;
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    const TOKEN: &str = "keep_agt_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn bridge(fake: &Fake, timing: Timing) -> Bridge {
        Bridge::connect(&fake.path, me(), token(TOKEN), timing).unwrap()
    }

    fn code(answer: &Value) -> Option<i64> {
        answer["error"]["code"].as_i64()
    }

    #[test]
    fn requests_go_in_the_envelope_and_notifications_and_errors_stay_here() {
        let fake = Fake::start(Peer::serve);
        let mut client = Client::start(bridge(&fake, patient()));
        assert_eq!(client.call(1, "initialize", json!({}))["result"], json!({}));
        client.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        client.send("");
        assert_eq!(code(&client.ask("{nope")), Some(-32700));
        assert_eq!(client.call(2, "tools/list", json!({}))["result"], json!({}));
        client.finish().unwrap();
        let log = fake.log();
        assert_eq!(
            log.len(),
            2,
            "only the requests reached the gateway: {log:?}"
        );
        for (_, envelope) in &log {
            assert_eq!(envelope["token"], json!(TOKEN));
            assert_eq!(envelope.as_object().unwrap().len(), 2);
        }
        assert_eq!(log[1].1["message"]["method"], json!("tools/list"));
    }

    /// A request the gateway read and never answered is reported, never sent
    /// again: it may have been signed.
    #[test]
    fn a_request_whose_answer_was_lost_is_never_sent_again() {
        let fake = Fake::start(|mut peer| {
            if peer.index == 0 {
                // Read the request, then close as a stopping gateway would.
                peer.next();
            } else {
                peer.serve();
            }
        });
        let mut client = Client::start(bridge(&fake, patient()));
        let lost = client.call(1, "tools/call", json!({ "name": "sign_nostr_event" }));
        assert_eq!(code(&lost), Some(LOST), "{lost}");
        assert!(lost["error"]["message"]
            .as_str()
            .unwrap()
            .contains("may have been carried out"));
        assert_eq!(client.call(2, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(0, json!(1)), (1, json!(2))]);
    }

    #[test]
    fn a_refusal_before_the_request_was_read_gets_the_requests_id() {
        let fake = Fake::start(|mut peer| {
            if peer.index != 0 {
                return peer.serve();
            }
            peer.next();
            peer.reply(&json!({ "jsonrpc": "2.0", "id": null,
                "error": { "code": REFUSED_CODE, "message": "request refused" } }));
            // An answer for another request: the connection is not trusted
            // further.
            peer.next();
            peer.reply(&json!({ "jsonrpc": "2.0", "id": 99, "result": {} }));
            peer.next();
        });
        let mut client = Client::start(bridge(&fake, patient()));
        let refused = client.call(1, "ping", json!({}));
        assert_eq!(code(&refused), Some(REFUSED_CODE));
        assert_eq!(code(&client.call(2, "ping", json!({}))), Some(LOST));
        assert_eq!(client.call(3, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(0, json!(1)), (0, json!(2)), (1, json!(3))]);
    }

    /// The token goes only to a socket in a directory the gateway's user
    /// owns and no one else can write, served by that user.
    #[test]
    fn the_token_is_never_sent_to_a_socket_the_gateway_user_does_not_hold() {
        let fake = Fake::start(Peer::serve);
        let err = Bridge::connect(&fake.path, me() + 1, token(TOKEN), patient())
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("is owned by uid"), "{err}");

        // A directory others could write, found on reconnecting.
        let (closed, wait_closed) = mpsc::channel();
        let fake = Fake::start(move |mut peer| {
            if peer.index != 0 {
                return peer.serve();
            }
            let envelope = peer.next().unwrap();
            peer.ok(&envelope);
            drop(peer);
            closed.send(()).unwrap();
        });
        let mut client = Client::start(bridge(&fake, patient()));
        assert_eq!(client.call(1, "ping", json!({}))["result"], json!({}));
        wait_closed.recv_timeout(Duration::from_secs(10)).unwrap();
        std::fs::set_permissions(fake.dir(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let answer = client.call(2, "ping", json!({}));
        assert_eq!(code(&answer), Some(UNREACHABLE), "{answer}");
        std::fs::set_permissions(fake.dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(client.call(3, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(0, json!(1)), (1, json!(3))]);

        if me() == 0 {
            // The directory is the gateway user's, but root serves the
            // socket in it: an impostor, and nothing is sent.
            let fake = Fake::start(Peer::serve);
            std::os::unix::fs::chown(fake.dir(), Some(4_321), None).unwrap();
            let err = Bridge::connect(&fake.path, 4_321, token(TOKEN), patient())
                .err()
                .unwrap()
                .to_string();
            assert!(err.contains("served by uid 0"), "{err}");
            std::thread::sleep(Duration::from_millis(100));
            assert!(fake.log().is_empty());
        }
    }

    #[test]
    fn a_stopped_gateway_is_reported_and_a_restarted_one_used_again() {
        // The gateway answers one request and stops.
        let (closed, wait_closed) = mpsc::channel();
        let fake = Fake::start(move |mut peer| {
            if let Some(envelope) = peer.next() {
                peer.ok(&envelope);
            }
            drop(peer);
            closed.send(()).unwrap();
        });
        let mut client = Client::start(bridge(&fake, patient()));
        assert_eq!(client.call(1, "ping", json!({}))["result"], json!({}));
        wait_closed.recv_timeout(Duration::from_secs(10)).unwrap();
        fake.remove();
        let answer = client.call(2, "ping", json!({}));
        assert_eq!(code(&answer), Some(UNREACHABLE), "{answer}");
        fake.listen(Peer::serve);
        assert_eq!(client.call(3, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        // Request 2 was never sent; the restarted gateway counts from 0.
        assert_eq!(fake.ids(), [(0, json!(1)), (0, json!(3))]);
    }

    /// A gateway that reads the next request on `index`'s connection and
    /// closes without answering, as the real one does when that request
    /// arrives just as it closes the connection. Every other connection is
    /// served.
    fn closes_on_the_next_request(index: usize, answered_first: usize) -> impl Fn(Peer) {
        move |mut peer: Peer| {
            if peer.index != index {
                return peer.serve();
            }
            for _ in 0..answered_first {
                let Some(envelope) = peer.next() else { return };
                peer.reply(&json!({ "jsonrpc": "2.0", "id": envelope["message"]["id"],
                    "error": { "code": REFUSED_CODE, "message": "request refused" } }));
            }
            peer.next();
        }
    }

    /// The gateway closes a connection after three refusals in a row, so
    /// the bridge does not send a fourth on it.
    #[test]
    fn after_the_refusals_that_close_a_connection_the_next_request_uses_a_new_one() {
        let fake = Fake::start(closes_on_the_next_request(0, 3));
        let mut client = Client::start(bridge(&fake, patient()));
        for id in 1..=3 {
            assert_eq!(
                code(&client.call(id, "ping", json!({}))),
                Some(REFUSED_CODE)
            );
        }
        assert_eq!(client.call(4, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        let ids = fake.ids();
        assert_eq!(ids.last(), Some(&(1, json!(4))), "{ids:?}");
    }

    /// A connection no token was accepted on yet is closed at the gateway's
    /// pre-auth deadline; one in use, after it has been idle too long.
    #[test]
    fn a_connection_about_to_time_out_is_replaced_before_sending() {
        let fake = Fake::start(closes_on_the_next_request(0, 0));
        let timing = Timing {
            fresh_for: Duration::from_millis(200),
            ..patient()
        };
        let mut client = Client::start(bridge(&fake, timing));
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(client.call(1, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(1, json!(1))]);

        // Accepted on its first request, then idle.
        let fake = Fake::start(|mut peer| {
            if peer.index != 0 {
                return peer.serve();
            }
            let envelope = peer.next().unwrap();
            peer.ok(&envelope);
            peer.next();
        });
        let timing = Timing {
            idle_for: Duration::from_millis(200),
            ..patient()
        };
        let mut client = Client::start(bridge(&fake, timing));
        assert_eq!(client.call(1, "ping", json!({}))["result"], json!({}));
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(client.call(2, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(0, json!(1)), (1, json!(2))]);
    }

    /// The gateway sends nothing unasked: a connection with something
    /// waiting on it is not used, so no answer is taken for the wrong
    /// request.
    #[test]
    fn a_connection_with_unasked_data_on_it_is_not_used() {
        for delay in [None, Some(Duration::from_millis(100))] {
            let (written, wait_written) = mpsc::channel();
            let fake = Fake::start(move |mut peer| {
                if peer.index != 0 {
                    return peer.serve();
                }
                let envelope = peer.next().unwrap();
                let id = &envelope["message"]["id"];
                let answer = json!({ "jsonrpc": "2.0", "id": id, "result": {} });
                match delay {
                    // In the same write as the answer, so it is read with it.
                    None => peer.write_raw(format!("{answer}\n{answer}\n").as_bytes()),
                    Some(delay) => {
                        peer.reply(&answer);
                        std::thread::sleep(delay);
                        peer.reply(&answer);
                    }
                }
                written.send(()).unwrap();
                peer.serve();
            });
            let mut client = Client::start(bridge(&fake, patient()));
            assert_eq!(client.call(1, "ping", json!({}))["result"], json!({}));
            wait_written.recv_timeout(Duration::from_secs(10)).unwrap();
            let answer = client.call(2, "ping", json!({}));
            assert_eq!(answer["result"], json!({}), "{delay:?}: {answer}");
            client.finish().unwrap();
            assert_eq!(fake.ids(), [(0, json!(1)), (1, json!(2))], "{delay:?}");
        }
    }

    /// A request that could not be sent whole was never read, so it goes
    /// once more on a new connection.
    #[test]
    fn a_request_not_sent_whole_is_sent_again_on_a_new_connection() {
        let stuck_got = Arc::new(Mutex::new(None::<Vec<u8>>));
        let done = Arc::new(AtomicBool::new(false));
        let (got, finished) = (stuck_got.clone(), done.clone());
        let fake = Fake::start(move |peer| {
            if peer.index != 0 {
                return peer.serve();
            }
            // Never reads until the bridge has given up on the connection.
            while !finished.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
            *got.lock().unwrap() = Some(peer.rest());
        });
        let big = "a".repeat(MAX_LINE - 1024);
        // The request must not fit the socket's send buffer whole.
        let send_buffer = std::fs::read_to_string("/proc/sys/net/core/wmem_default")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if send_buffer >= big.len() / 2 {
            eprintln!("skipped: a {send_buffer} byte send buffer holds the whole request");
            return;
        }
        // Long enough for the new connection's send under load; the stuck
        // one only waits it out.
        let timing = Timing {
            write_timeout: Duration::from_secs(2),
            ..patient()
        };
        let mut client = Client::start(bridge(&fake, timing));
        let answer = client.call(1, "tools/call", json!({ "padding": big }));
        let shown: String = answer.to_string().chars().take(200).collect();
        assert_eq!(answer["result"], json!({}), "{shown}");
        done.store(true, Ordering::SeqCst);
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(1, json!(1))]);
        let mut stuck = None;
        for _ in 0..250 {
            stuck = stuck_got.lock().unwrap().take();
            if stuck.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let stuck = stuck.expect("the stuck connection was closed");
        assert!(!stuck.is_empty(), "part of the request was sent");
        assert!(!stuck.contains(&b'\n'), "but never a whole line");
    }

    #[test]
    fn requests_too_large_for_the_gateway_are_answered_here() {
        let fake = Fake::start(Peer::serve);
        let mut client = Client::start(bridge(&fake, patient()));
        let big = "a".repeat(MAX_LINE);
        let message = json!({ "jsonrpc": "2.0", "id": 1, "method": "x", "params": { "p": big } });
        assert_eq!(code(&client.ask(&message.to_string())), Some(-32600));
        // Small enough to read, too large once in the envelope.
        let fits = "a".repeat(MAX_LINE - 60);
        let message = json!({ "jsonrpc": "2.0", "id": 2, "method": "x", "params": fits });
        let line = message.to_string();
        assert!(line.len() <= MAX_LINE);
        let answer = client.ask(&line);
        assert_eq!(
            (answer["id"].clone(), code(&answer)),
            (json!(2), Some(-32600))
        );
        assert_eq!(client.call(3, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(0, json!(3))]);
    }

    /// The gateway closed the connection with the request unread in it, as
    /// it does to a uid holding too many connections: never read, so it goes
    /// once more, and is reported as not sent if that fails too.
    #[test]
    fn a_request_closed_unread_is_sent_again_and_never_reported_as_lost() {
        fn close_unread(peer: Peer) {
            // Let the request arrive, then close without reading it.
            std::thread::sleep(Duration::from_millis(200));
            drop(peer);
        }
        let fake = Fake::start(|peer| {
            if peer.index == 0 {
                close_unread(peer);
            } else {
                peer.serve();
            }
        });
        let mut client = Client::start(bridge(&fake, patient()));
        assert_eq!(client.call(1, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(1, json!(1))]);

        let fake = Fake::start(close_unread);
        let mut client = Client::start(bridge(&fake, patient()));
        let answer = client.call(1, "ping", json!({}));
        assert_eq!(code(&answer), Some(UNREACHABLE), "{answer}");
        client.finish().unwrap();
        assert!(fake.log().is_empty());
    }

    /// A gateway that is not running yet when the bridge starts is used
    /// once it is.
    #[test]
    fn the_bridge_starts_before_the_gateway() {
        let fake = Fake::empty();
        let bridge = Bridge::connect(&fake.path, me(), token(TOKEN), patient()).unwrap();
        assert!(!bridge.is_connected());
        let mut client = Client::start(bridge);
        let answer = client.call(1, "ping", json!({}));
        assert_eq!(code(&answer), Some(UNREACHABLE), "{answer}");
        fake.listen(Peer::serve);
        assert_eq!(client.call(2, "ping", json!({}))["result"], json!({}));
        client.finish().unwrap();
        assert_eq!(fake.ids(), [(0, json!(2))]);
    }
}
