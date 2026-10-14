// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Secret grants and the checks an HTTP request must pass before a secret is
//! added to it: the rule's exact host, port, method and path prefix, a URL
//! already in the parser's normal form, and only the headers agents may set.

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::error::{AgentError, Result};

use keep_approval::change::{format_ok, header_name_ok, path_prefix_ok, rule_host_ok};
pub use keep_approval::change::{MAX_RULES, MAX_SECRETS};

/// The most agent headers one request may carry, and their total size.
pub const MAX_AGENT_HEADERS: usize = 16;
pub const MAX_AGENT_HEADER_BYTES: usize = 8 * 1024;
/// The largest request body an agent may send.
pub const MAX_BODY: usize = 256 * 1024;
/// The sizes of secret value that may be injected.
pub const MIN_INJECTED: usize = 12;
pub const MAX_INJECTED: usize = 2 * 1024;

const MAX_RULE_AGENT_HEADERS: usize = keep_approval::change::MAX_AGENT_HEADERS;

/// The kinds of secret an HTTP rule may send. A note is free text, never a
/// credential to put in a header.
pub const HTTP_KINDS: [keep_core::secret::SecretKind; 3] = [
    keep_core::secret::SecretKind::ApiToken,
    keep_core::secret::SecretKind::Password,
    keep_core::secret::SecretKind::Generic,
];

/// Headers every rule lets the agent set.
const AGENT_HEADERS: &[&str] = &[
    "accept",
    "content-type",
    "user-agent",
    "if-none-match",
    "if-match",
    "if-modified-since",
    "if-unmodified-since",
];

/// Header names no rule may let the agent set, nor inject a secret into: they
/// change how the request is routed or framed, or how the response is
/// encoded, so a server could act on another method or path than the rule's,
/// or send back a form of the secret the scan cannot read.
fn forbidden_header(lower: &str) -> bool {
    const NAMES: &[&str] = &[
        "host",
        "accept-encoding",
        "content-encoding",
        "content-length",
        "transfer-encoding",
        "te",
        "trailer",
        "connection",
        "keep-alive",
        "upgrade",
        "expect",
        "range",
        "if-range",
        "forwarded",
        "via",
        "cookie",
        "x-host",
        "x-http-host-override",
        "x-middleware-subrequest",
    ];
    const PREFIXES: &[&str] = &[
        "proxy-",
        "x-forwarded-",
        "x-original-",
        "x-rewrite-",
        "x-envoy-",
    ];
    NAMES.contains(&lower)
        || PREFIXES.iter().any(|p| lower.starts_with(p))
        || lower.contains("method-override")
        || lower.contains("x-http-method")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
// Declared in alphabetical order, so the order rules list methods in is the
// order of their names, as in a management change.
pub enum Method {
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "DELETE" => Method::Delete,
            "OPTIONS" => Method::Options,
            _ => return None,
        })
    }
}

/// Where one secret may be sent over HTTPS, and how it is added.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRule {
    pub host: String,
    pub port: u16,
    pub methods: Vec<Method>,
    pub path_prefix: String,
    /// The header the secret is sent in.
    pub header: String,
    /// The header's value, with `{}` standing for the secret.
    pub format: String,
    /// Further headers the agent may set on requests under this rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_headers: Vec<String>,
}

/// What a credential may do with one vault secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretGrant {
    #[serde(with = "hex_id")]
    pub secret: [u8; 32],
    pub http: Vec<HttpRule>,
}

mod hex_id {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(id: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(id))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        keep_approval::Hex32::parse(&s)
            .map(|h| h.0)
            .map_err(|_| D::Error::custom("a secret id is 64 lowercase hex characters"))
    }
}

fn refuse<T>(message: impl Into<String>) -> Result<T> {
    Err(AgentError::ScopeViolation(message.into()))
}

fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// A header value: visible ASCII, space and tab, with no whitespace at either
/// end.
pub fn is_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b == b'\t' || (b' '..=b'~').contains(&b))
        && !value.first().is_some_and(|b| matches!(b, b' ' | b'\t'))
        && !value.last().is_some_and(|b| matches!(b, b' ' | b'\t'))
}

/// A rule host as the URL parser leaves it (already lowercase ASCII, the
/// IDNA form of any other name, no port or path) and as an approver shows it.
fn check_host(host: &str) -> Result<()> {
    let parsed = Url::parse(&format!("https://{host}/")).ok();
    let same = parsed
        .as_ref()
        .is_some_and(|u| matches!(u.host(), Some(Host::Domain(d)) if d == host));
    if !same || !rule_host_ok(host) {
        return refuse(format!(
            "rule host {host:?} must be a DNS name with a dot, lowercase letters, digits and -, already in ASCII (IDNA) form, with no port, path or trailing dot"
        ));
    }
    Ok(())
}

fn check_prefix(prefix: &str) -> Result<()> {
    if !path_prefix_ok(prefix) {
        return refuse(format!(
            "rule path prefix {prefix:?} must start with /, be more than /, hold only unescaped path characters (no % or ;), and have no empty, . or .. segment"
        ));
    }
    Ok(())
}

fn check_rule_header(name: &str, what: &str) -> Result<()> {
    if !header_name_ok(name) || forbidden_header(name) {
        return refuse(format!(
            "{what} {name:?} must be at most 64 lowercase letters, digits and -, and not a header that changes routing, framing or encoding"
        ));
    }
    Ok(())
}

impl HttpRule {
    fn validate(&self) -> Result<()> {
        check_host(&self.host)?;
        if self.port == 0 {
            return refuse("rule port must be 1 to 65535");
        }
        if self.methods.is_empty() || !self.methods.windows(2).all(|w| w[0] < w[1]) {
            return refuse("rule methods must be listed once each, in alphabetical order");
        }
        check_prefix(&self.path_prefix)?;
        check_rule_header(&self.header, "rule header")?;
        if AGENT_HEADERS.contains(&self.header.as_str()) {
            return refuse(format!(
                "rule header {:?} is one agents may set",
                self.header
            ));
        }
        if !format_ok(&self.format) {
            return refuse("rule format must be at most 128 visible ASCII characters and spaces, with exactly one {} and no space at either end");
        }
        if self.agent_headers.len() > MAX_RULE_AGENT_HEADERS {
            return refuse(format!(
                "a rule may let agents set at most {MAX_RULE_AGENT_HEADERS} further headers"
            ));
        }
        if !self.agent_headers.windows(2).all(|w| w[0] < w[1]) {
            return refuse("a rule's agent headers must be listed once each, sorted");
        }
        for name in &self.agent_headers {
            check_rule_header(name, "agent header")?;
            if *name == self.header || AGENT_HEADERS.contains(&name.as_str()) {
                return refuse(format!(
                    "agent header {name:?} is the rule header or one agents may always set"
                ));
            }
        }
        Ok(())
    }

    fn matches_path(&self, path: &str) -> bool {
        let prefix = self.path_prefix.as_str();
        path == prefix
            || (prefix.ends_with('/') && path.starts_with(prefix))
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }

    fn allows_agent_header(&self, lower: &str) -> bool {
        AGENT_HEADERS.contains(&lower) || self.agent_headers.iter().any(|h| h == lower)
    }

    /// Whether some request could match both rules: the same host and port,
    /// and one path prefix matching the other.
    fn overlaps(&self, other: &HttpRule) -> bool {
        self.host == other.host
            && self.port == other.port
            && (self.matches_path(&other.path_prefix) || other.matches_path(&self.path_prefix))
    }

    /// The injected header's value for `secret`, refusing a value that is too
    /// short or long, or not a valid header value once formatted.
    pub fn header_value(&self, secret: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if !(MIN_INJECTED..=MAX_INJECTED).contains(&secret.len()) {
            return refuse(format!(
                "a secret sent in a header must be {MIN_INJECTED} to {MAX_INJECTED} bytes"
            ));
        }
        let (before, after) = self
            .format
            .split_once("{}")
            .expect("validated: one {} in the format");
        let mut value = zeroize::Zeroizing::new(Vec::with_capacity(
            before.len() + secret.len() + after.len(),
        ));
        value.extend_from_slice(before.as_bytes());
        value.extend_from_slice(secret);
        value.extend_from_slice(after.as_bytes());
        if !is_header_value(&value) {
            return refuse("the secret holds bytes a header value cannot carry");
        }
        Ok(value)
    }
}

impl SecretGrant {
    fn validate(&self) -> Result<()> {
        if self.http.is_empty() {
            return refuse("a secret entry must allow at least one use");
        }
        if self.http.len() > MAX_RULES {
            return refuse(format!(
                "a secret entry holds at most {MAX_RULES} HTTP rules"
            ));
        }
        self.http.iter().try_for_each(HttpRule::validate)?;
        let key = |r: &HttpRule| (r.host.clone(), r.port, r.path_prefix.clone());
        if !self.http.windows(2).all(|w| key(&w[0]) < key(&w[1])) {
            return refuse("a secret's HTTP rules must be sorted by host, port and path prefix");
        }
        for (i, a) in self.http.iter().enumerate() {
            if self.http[i + 1..].iter().any(|b| a.overlaps(b)) {
                return refuse(format!(
                    "two rules for {}:{} could both match one request; a request must match one rule at most",
                    a.host, a.port
                ));
            }
        }
        Ok(())
    }
}

/// Validate a grant's secret entries: at most [`MAX_SECRETS`], sorted by id with
/// none repeated, each well formed.
pub fn validate_secrets(secrets: &[SecretGrant]) -> Result<()> {
    if secrets.len() > MAX_SECRETS {
        return refuse(format!("a grant names at most {MAX_SECRETS} secrets"));
    }
    if !secrets.windows(2).all(|w| w[0].secret < w[1].secret) {
        return refuse("a grant's secrets must be sorted by id, each once");
    }
    secrets.iter().try_for_each(SecretGrant::validate)
}

/// An HTTP request as the agent asked for it.
pub struct HttpAsk<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a str,
}

/// A request that passed every check, ready for the secret to be added.
#[derive(Debug)]
pub struct CheckedRequest<'g> {
    pub rule: &'g HttpRule,
    pub method: Method,
    pub url: Url,
}

impl CheckedRequest<'_> {
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }

    pub fn port(&self) -> u16 {
        self.url.port().unwrap_or(443)
    }
}

/// Bytes a path may carry percent-encoded: those the URL parser itself
/// encodes in a path, and bytes of multibyte UTF-8. Never an unreserved
/// character, a delimiter, `%` or a control byte, any of which a server may
/// decode into a different path than the one the rule checked.
fn escapable(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'"' | b'<' | b'>' | b'^' | b'`' | b'{' | b'|' | b'}'
    ) || b >= 0x80
}

/// Whether a query parameter name is a method override once a framework has
/// decoded it: `_method`, however it is escaped or spelled (PHP turns `.`,
/// space and `[` in a name into `_`).
fn overrides_method(name: &str) -> bool {
    // PHP stops a name at NUL and drops its leading spaces; others map those
    // spaces to `_` like the rest. Either reading that gives `_method` counts.
    let name = name.split('\0').next().unwrap_or_default();
    let normalized = |name: &str| -> String {
        name.chars()
            .map(|c| match c {
                '.' | ' ' | '[' => '_',
                c => c.to_ascii_lowercase(),
            })
            .collect()
    };
    normalized(name) == "_method" || normalized(name.trim_start_matches(' ')) == "_method"
}

fn check_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b';' => return false,
            b'%' => {
                let Some(b) = bytes
                    .get(i + 1..i + 3)
                    .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                    .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())
                else {
                    return false;
                };
                if !escapable(b) {
                    return false;
                }
                decoded.push(b);
                i += 3;
            }
            b => {
                decoded.push(b);
                i += 1;
            }
        }
    }
    let Ok(decoded) = std::str::from_utf8(&decoded) else {
        return false;
    };
    !decoded.chars().any(normalizes_to_delimiter) && !path.split('/').any(|s| s == "." || s == "..")
}

/// Whether a non-ASCII character becomes a path delimiter under Unicode
/// compatibility normalization, which some servers apply to paths: fullwidth
/// `．．／`, for one, is `../` once normalized.
fn normalizes_to_delimiter(c: char) -> bool {
    use unicode_normalization::UnicodeNormalization;
    !c.is_ascii() && std::iter::once(c).nfkc().any(|n| "./\\;%?#".contains(n))
}

/// Whether any parameter of a query or form body is a method override.
/// Some frameworks also split parameters on `;`.
fn form_overrides_method(form: &[u8]) -> bool {
    form.split(|&b| b == b';')
        .any(|part| url::form_urlencoded::parse(part).any(|(k, _)| overrides_method(&k)))
}

/// Whether the body could carry a method override a framework would act on.
/// Servers disagree on which content types they parse as a form or as JSON,
/// so every body is read both ways whatever its type: any form field or
/// top-level JSON key that is a method override refuses it, as does a body
/// that looks like a JSON object but does not parse (a server's parser may
/// take what this one refuses) and any multipart body, whose part names are
/// not checked.
fn body_overrides_method(content_type: Option<&str>, body: &str) -> bool {
    let multipart = content_type.is_some_and(|t| {
        t.trim_start()
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("multipart/"))
    });
    if multipart || form_overrides_method(body.as_bytes()) {
        return true;
    }
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(map)) => map.keys().any(|k| overrides_method(k)),
        Ok(_) => false,
        Err(_) => body.trim_start().starts_with('{'),
    }
}

/// Check an agent's request against a secret's rules: the first rule whose
/// host, port, method and path prefix all match, a URL in normal form with
/// nothing a server could route differently, and only headers agents may
/// set. Every refusal is one `ScopeViolation`, so the agent learns only that
/// the request was refused.
pub fn check_request<'g>(entry: &'g SecretGrant, ask: &HttpAsk<'_>) -> Result<CheckedRequest<'g>> {
    let Some(method) = Method::parse(ask.method) else {
        return refuse("method not allowed");
    };
    let Ok(url) = Url::parse(ask.url) else {
        return refuse("url does not parse");
    };
    if url.as_str() != ask.url {
        return refuse("url must be written exactly as it parses");
    }
    let Some(Host::Domain(host)) = url.host() else {
        return refuse("url must name a DNS host");
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !check_path(url.path())
        || url
            .query()
            .is_some_and(|q| form_overrides_method(q.as_bytes()))
    {
        return refuse("url not allowed");
    }
    let port = url.port().unwrap_or(443);
    let Some(rule) = entry.http.iter().find(|r| {
        r.host == host
            && r.port == port
            && r.methods.contains(&method)
            && r.matches_path(url.path())
    }) else {
        return refuse("no rule allows this request");
    };
    if ask.headers.len() > MAX_AGENT_HEADERS
        || ask
            .headers
            .iter()
            .map(|(n, v)| n.len() + v.len())
            .sum::<usize>()
            > MAX_AGENT_HEADER_BYTES
    {
        return refuse("too many headers");
    }
    let mut seen: Vec<String> = Vec::with_capacity(ask.headers.len());
    for (name, value) in ask.headers {
        let lower = name.to_ascii_lowercase();
        if !is_token(name)
            || !rule.allows_agent_header(&lower)
            || !is_header_value(value.as_bytes())
            || seen.contains(&lower)
        {
            return refuse("header not allowed");
        }
        seen.push(lower);
    }
    if ask.body.len() > MAX_BODY {
        return refuse("body too large");
    }
    let content_type = ask
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str());
    if body_overrides_method(content_type, ask.body) {
        return refuse("body not allowed");
    }
    Ok(CheckedRequest {
        rule,
        method,
        url: url.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> HttpRule {
        HttpRule {
            host: "api.example.com".into(),
            port: 443,
            methods: vec![Method::Get, Method::Post],
            path_prefix: "/v1/items".into(),
            header: "authorization".into(),
            format: "Bearer {}".into(),
            agent_headers: vec!["idempotency-key".into()],
        }
    }

    fn entry() -> SecretGrant {
        SecretGrant {
            secret: [7; 32],
            http: vec![rule()],
        }
    }

    fn ask<'a>(method: &'a str, url: &'a str, headers: &'a [(String, String)]) -> HttpAsk<'a> {
        HttpAsk {
            method,
            url,
            headers,
            body: "",
        }
    }

    fn allowed(url: &str) -> bool {
        check_request(&entry(), &ask("GET", url, &[])).is_ok()
    }

    fn h(n: &str, v: &str) -> (String, String) {
        (n.into(), v.into())
    }

    #[test]
    fn a_well_formed_rule_validates() {
        validate_secrets(&[entry()]).unwrap();
    }

    #[test]
    fn rules_refuse_bad_hosts() {
        for host in [
            "API.example.com",
            "api.example.com.",
            "localhost",
            "1.2.3.4",
            "[::1]",
            "api.example.com:443",
            "api.example.com/x",
            "user@api.example.com",
            "bücher.example",
            "a_b.example.com",
            &format!("{}.com", "a".repeat(64)),
            "",
            &format!("{}.com", "a".repeat(250)),
        ] {
            let mut r = rule();
            r.host = host.into();
            assert!(r.validate().is_err(), "{host:?} should be refused");
        }
        let mut r = rule();
        r.host = "xn--bcher-kva.example".into();
        r.validate().unwrap();
    }

    #[test]
    fn rules_refuse_bad_prefixes() {
        for prefix in [
            "/", "", "v1", "/v1//x", "/v1/./x", "/v1/../x", "/v1/%2e", "/v1;x", "/v1/ x", "/v1?x",
            "/v1#x", "/v1\\x",
        ] {
            let mut r = rule();
            r.path_prefix = prefix.into();
            assert!(r.validate().is_err(), "{prefix:?} should be refused");
        }
        let mut r = rule();
        r.path_prefix = format!("/{}", "a".repeat(256));
        assert!(r.validate().is_err());
    }

    #[test]
    fn rules_refuse_bad_headers_formats_and_methods() {
        type Mutation = Box<dyn Fn(&mut HttpRule)>;
        let cases: Vec<Mutation> = vec![
            Box::new(|r| r.header = "x_api_key".into()),
            Box::new(|r| r.header = "x.api.key".into()),
            Box::new(|r| r.agent_headers = vec!["x+y".into()]),
            Box::new(|r| r.header = "Authorization".into()),
            Box::new(|r| r.header = "host".into()),
            Box::new(|r| r.header = "accept".into()),
            Box::new(|r| r.header = "Bad Header".into()),
            Box::new(|r| r.header = "".into()),
            Box::new(|r| r.format = "Bearer".into()),
            Box::new(|r| r.format = "{} {}".into()),
            Box::new(|r| r.format = " {}".into()),
            Box::new(|r| r.format = "{}\n".into()),
            Box::new(|r| r.methods = vec![]),
            Box::new(|r| r.methods = vec![Method::Post, Method::Get]),
            Box::new(|r| r.methods = vec![Method::Post, Method::Patch]),
            Box::new(|r| r.methods = vec![Method::Get, Method::Get]),
            Box::new(|r| r.port = 0),
            Box::new(|r| r.agent_headers = vec!["authorization".into()]),
            Box::new(|r| r.agent_headers = vec!["accept".into()]),
            Box::new(|r| r.agent_headers = vec!["Idempotency-Key".into()]),
            Box::new(|r| r.agent_headers = vec!["x-http-method-override".into()]),
            Box::new(|r| r.agent_headers = vec!["x-forwarded-for".into()]),
            Box::new(|r| r.agent_headers = vec!["range".into()]),
            Box::new(|r| r.agent_headers = vec!["accept-encoding".into()]),
            Box::new(|r| r.agent_headers = vec!["cookie".into()]),
            Box::new(|r| r.agent_headers = vec!["a".into(), "a".into()]),
            Box::new(|r| r.agent_headers = vec!["b".into(), "a".into()]),
            Box::new(|r| r.agent_headers = (0..9).map(|i| format!("x-{i}")).collect()),
        ];
        for (i, change) in cases.iter().enumerate() {
            let mut r = rule();
            change(&mut r);
            assert!(r.validate().is_err(), "case {i} should be refused");
        }
    }

    #[test]
    fn grants_refuse_unsorted_repeated_empty_or_too_many_entries() {
        let mut a = entry();
        let mut b = entry();
        b.secret = [8; 32];
        validate_secrets(&[a.clone(), b.clone()]).unwrap();
        assert!(validate_secrets(&[b.clone(), a.clone()]).is_err());
        assert!(validate_secrets(&[a.clone(), a.clone()]).is_err());
        a.http.clear();
        assert!(validate_secrets(&[a.clone()]).is_err());
        let with_reveal = r#"{"secret":"0707070707070707070707070707070707070707070707070707070707070707","http":[],"reveal":true}"#;
        assert!(serde_json::from_str::<SecretGrant>(with_reveal).is_err());
        b.http = (0..=MAX_RULES)
            .map(|i| HttpRule {
                path_prefix: format!("/p{i}"),
                ..rule()
            })
            .collect();
        assert!(validate_secrets(&[b]).is_err());
        let many: Vec<_> = (0..=MAX_SECRETS as u8)
            .map(|i| SecretGrant {
                secret: [i; 32],
                ..entry()
            })
            .collect();
        assert!(validate_secrets(&many).is_err());
    }

    #[test]
    fn rules_must_be_sorted_and_never_both_match_a_request() {
        let with = |prefixes: &[&str]| SecretGrant {
            http: prefixes
                .iter()
                .map(|p| HttpRule {
                    path_prefix: (*p).into(),
                    ..rule()
                })
                .collect(),
            ..entry()
        };
        validate_secrets(&[with(&["/v1/a", "/v1/b"])]).unwrap();
        validate_secrets(&[with(&["/v1/a", "/v1/ab"])]).unwrap();
        assert!(validate_secrets(&[with(&["/v1/b", "/v1/a"])]).is_err());
        assert!(validate_secrets(&[with(&["/v1", "/v1/a"])]).is_err());
        assert!(validate_secrets(&[with(&["/v1/", "/v1/a"])]).is_err());
        assert!(validate_secrets(&[with(&["/v1/a", "/v1/a/"])]).is_err());
        let mut other_port = with(&["/v1/a", "/v1/a/x"]);
        other_port.http[1].port = 8443;
        validate_secrets(&[other_port]).unwrap();
    }

    #[test]
    fn secret_ids_are_lowercase_hex() {
        let json = serde_json::to_string(&entry()).unwrap();
        assert!(json.contains(&"07".repeat(32)));
        assert_eq!(serde_json::from_str::<SecretGrant>(&json).unwrap(), entry());
        let upper = json.replace(&"07".repeat(32), &"0A".repeat(32));
        assert!(serde_json::from_str::<SecretGrant>(&upper).is_err());
        let short = json.replace(&"07".repeat(32), "07");
        assert!(serde_json::from_str::<SecretGrant>(&short).is_err());
    }

    #[test]
    fn matching_requests_are_allowed() {
        assert!(allowed("https://api.example.com/v1/items"));
        assert!(allowed("https://api.example.com/v1/items/42?x=1&y=%20z"));
        assert!(allowed("https://api.example.com/v1/items/caf%C3%A9"));
        assert!(allowed("https://api.example.com/v1/items/a%20b"));
        assert!(allowed(
            "https://api.example.com/v1/items?payment_method=pm_1"
        ));
        let e = entry();
        let checked =
            check_request(&e, &ask("POST", "https://api.example.com/v1/items/1", &[])).unwrap();
        assert_eq!((checked.host(), checked.port()), ("api.example.com", 443));
        assert_eq!(checked.method, Method::Post);
    }

    #[test]
    fn requests_outside_the_rule_are_refused() {
        for url in [
            "http://api.example.com/v1/items",
            "https://api.example.com/v1/itemsx",
            "https://api.example.com/v1/item",
            "https://api.example.com/v2/items",
            "https://api.example.com:8443/v1/items",
            "https://other.example.com/v1/items",
            "https://API.example.com/v1/items",
            "https://api.example.com:443/v1/items",
            "https://api.example.com/v1/items#frag",
            "https://user@api.example.com/v1/items",
            "https://user:pw@api.example.com/v1/items",
            "https://:pw@api.example.com/v1/items",
            "https://api.example.com/v1/items/%C0%AE%C0%AE/admin",
            "https://api.example.com/v1/items/%+1",
            "https://api.example.com/v1/items/%EF%BC%8E%EF%BC%8E%EF%BC%8Fadmin",
            "https://api.example.com/v1/items/%E2%80%A5/admin",
            "https://api.example.com/v1/items?a=1;_method=DELETE",
            "https://api.example.com/v1/items?+_method=DELETE",
            "https://api.example.com/v1/items?_method%00=DELETE",
            "https://api.example.com/v1/items/../../admin",
            "https://api.example.com/v1/items/./x",
            "https://api.example.com/v1/items/%2e%2e/admin",
            "https://api.example.com/v1/items/%2E%2E/admin",
            "https://api.example.com/v1/items/%2f..%2fadmin",
            "https://api.example.com/v1/items/%5c..%5cadmin",
            "https://api.example.com/v1/items/%252e%252e/admin",
            "https://api.example.com/v1/items/..;/admin",
            "https://api.example.com/v1/items;x",
            "https://api.example.com/v1/items/%00",
            "https://api.example.com/v1/items/%41",
            "https://api.example.com/v1/items/%ff",
            "https://api.example.com/v1/items/%zz",
            "https://api.example.com/v1/items\\..\\admin",
            "https://api.example.com/v1/items/\tx",
            "https://api.example.com/v1/items?_method=DELETE",
            "https://api.example.com/v1/items?_METHOD=DELETE",
            "https://api.example.com/v1/items?%5Fmethod=DELETE",
            "https://api.example.com/v1/items?.method=DELETE",
            "https://api.example.com/v1/items?a=1&[method=DELETE",
            "https://api.example.com/v1/items?+method=DELETE",
            "https://api.example.com/v1/items/%23",
            "https://api.example.com/v1/items/%3F",
            "https://api.example.com/v1/items/%3B",
            "https://api.example.com/v1/items/%25",
            "https://api.example.com/v1/items/x y",
            "https://api.example.com",
            "https://93.184.216.34/v1/items",
            "https://[2606:2800::1]/v1/items",
            "not a url",
        ] {
            assert!(!allowed(url), "{url:?} should be refused");
        }
        assert!(check_request(
            &entry(),
            &ask("DELETE", "https://api.example.com/v1/items", &[])
        )
        .is_err());
        assert!(check_request(
            &entry(),
            &ask("get", "https://api.example.com/v1/items", &[])
        )
        .is_err());
    }

    #[test]
    fn a_prefix_ending_in_a_slash_matches_below_it_only() {
        let mut e = entry();
        e.http[0].path_prefix = "/v1/".into();
        let ok = |u: &str| check_request(&e, &ask("GET", u, &[])).is_ok();
        assert!(ok("https://api.example.com/v1/"));
        assert!(ok("https://api.example.com/v1/x"));
        assert!(!ok("https://api.example.com/v1"));
        assert!(!ok("https://api.example.com/v1x"));
    }

    #[test]
    fn only_allowlisted_headers_pass() {
        let url = "https://api.example.com/v1/items";
        let ok = |hs: &[(String, String)]| check_request(&entry(), &ask("GET", url, hs)).is_ok();
        assert!(ok(&[
            h("Accept", "application/json"),
            h("content-type", "text/plain"),
            h("Idempotency-Key", "abc"),
        ]));
        for bad in [
            h("Authorization", "Bearer mine"),
            h("authorization", "x"),
            h("Accept-Encoding", "gzip"),
            h("Range", "bytes=0-3"),
            h("X-HTTP-Method-Override", "DELETE"),
            h("X-Original-URL", "/admin"),
            h("Host", "evil.example"),
            h("Cookie", "a=b"),
            h("X-Other", "x"),
            h("Accept", "a\r\nX: y"),
            h("Accept", " leading"),
            h("Accept", "trailing "),
            h("Accept", "caf\u{e9}"),
            h("Bad Name", "x"),
        ] {
            assert!(!ok(std::slice::from_ref(&bad)), "{bad:?} should be refused");
        }
        assert!(!ok(&[h("Accept", "a"), h("accept", "b")]));
        let many: Vec<_> = (0..=MAX_AGENT_HEADERS).map(|_| h("Accept", "a")).collect();
        assert!(!ok(&many));
        assert!(!ok(&[h("Accept", &"a".repeat(MAX_AGENT_HEADER_BYTES))]));
    }

    #[test]
    fn a_method_override_in_the_body_is_refused() {
        let url = "https://api.example.com/v1/items";
        let ok = |content_type: Option<&str>, body: &str| {
            let headers: Vec<_> = content_type
                .map(|t| h("Content-Type", t))
                .into_iter()
                .collect();
            check_request(
                &entry(),
                &HttpAsk {
                    method: "POST",
                    url,
                    headers: &headers,
                    body,
                },
            )
            .is_ok()
        };
        assert!(ok(None, "name=x&payment_method=card"));
        assert!(ok(
            Some("application/json"),
            r#"{"payment_method":"card","a":{"_method":"x"}}"#
        ));
        assert!(ok(Some("application/json"), "[1,2]"));
        assert!(ok(Some("text/plain"), "hello"));
        let deep = format!(
            r#"{{"_method":"DELETE","x":{}{}}}"#,
            "[".repeat(200),
            "]".repeat(200)
        );
        for (content_type, body) in [
            (Some("text/plain"), "_method=DELETE"),
            (
                Some("application/x-www-form-urlencoded,x"),
                "_method=DELETE",
            ),
            (None, "+_method=DELETE"),
            (None, "%20_method=DELETE"),
            (None, "+.method=DELETE"),
            (None, "_method%00=DELETE"),
            (Some("application/json"), deep.as_str()),
            (Some("application/json"), "{not json"),
            (Some(" Multipart/form-data; boundary=x"), "--x--"),
            (None, "_method=DELETE"),
            (None, "a=1&%5Fmethod=DELETE"),
            (None, "a=1;_method=DELETE"),
            (None, ".method=PUT"),
            (
                Some("application/x-www-form-urlencoded; charset=utf-8"),
                "_method=DELETE",
            ),
            (Some("Application/X-WWW-Form-Urlencoded"), "_METHOD=DELETE"),
            (Some("application/json"), r#"{"_method":"DELETE"}"#),
            (Some("text/plain"), r#"{"_method":"DELETE"}"#),
            (Some("multipart/form-data; boundary=x"), "--x--"),
        ] {
            assert!(
                !ok(content_type, body),
                "{content_type:?} {body:?} should be refused"
            );
        }
    }

    #[test]
    fn bodies_over_the_limit_are_refused() {
        let url = "https://api.example.com/v1/items";
        let big = "a".repeat(MAX_BODY + 1);
        let ask = HttpAsk {
            method: "POST",
            url,
            headers: &[],
            body: &big,
        };
        assert!(check_request(&entry(), &ask).is_err());
        let fits = "a".repeat(MAX_BODY);
        let ask = HttpAsk { body: &fits, ..ask };
        assert!(check_request(&entry(), &ask).is_ok());
    }

    #[test]
    fn the_injected_value_follows_the_format_and_refuses_bad_secrets() {
        let r = rule();
        assert_eq!(
            &*r.header_value(b"0123456789abcdef").unwrap(),
            b"Bearer 0123456789abcdef"
        );
        assert!(r.header_value(b"short").is_err());
        assert!(r.header_value(&[b'a'; MAX_INJECTED + 1]).is_err());
        assert!(r.header_value(b"0123456789ab\r\nX: y").is_err());
        assert!(r.header_value(b"0123456789abcdef ").is_err());
        assert!(r.header_value("0123456789abcd\u{e9}".as_bytes()).is_err());
    }
}
