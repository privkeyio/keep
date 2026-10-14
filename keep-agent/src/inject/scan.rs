// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Finding a secret in a response, in the encodings servers commonly echo it
//! in. A guard against reflection (error pages, echo endpoints), not against
//! a host that transforms the secret on purpose.
//!
//! Encoders escape some characters and leave others alone, and which ones
//! differs between them, so the response is decoded rather than the secret
//! encoded: the secret, ASCII case-folded, is looked for in the response as
//! is and in percent-, JSON- and HTML-decoded views of it, and one with NUL,
//! CR and LF removed (UTF-16 or UTF-32 text, base64 wrapped into lines),
//! alone and chained. Base64 and hex are whole-string encodings, so those
//! forms of the secret are looked for in the same views.

use memchr::memmem;
use zeroize::Zeroizing;

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The most digits a numeric HTML entity may have and still be decoded:
/// enough for any code point, `&#x10FFFF;`.
const MAX_ENTITY_DIGITS: usize = 6;

/// The longest escape any one decoder accepts for one character: an HTML
/// entity (`&#x` + 6 digits + `;`, and no named one is longer).
const MAX_ESCAPE: usize = 10;

/// How many bytes past a cut must be read so that any form of a secret of
/// `len` bytes that starts before the cut is read whole: views chain two
/// decoders, so one byte of the secret is at most `MAX_ESCAPE` squared
/// characters of response.
pub fn longest_form(len: usize) -> usize {
    len.saturating_mul(MAX_ESCAPE * MAX_ESCAPE)
        .saturating_add(8)
}

type Decoder = fn(&[u8]) -> Zeroizing<Vec<u8>>;

const DECODERS: [Decoder; 5] = [
    percent_decode,
    form_decode,
    json_decode,
    html_decode,
    strip_decode,
];

/// The decoded views searched: the response as it is, each decoder alone,
/// and every ordered pair of decoders (a pair is applied left to right).
fn views() -> impl Iterator<Item = Vec<Decoder>> {
    std::iter::once(Vec::new())
        .chain(DECODERS.iter().map(|d| vec![*d]))
        .chain(
            DECODERS
                .iter()
                .flat_map(|a| DECODERS.iter().map(move |b| vec![*a, *b])),
        )
}

/// One secret's forms, built once and searched for in each response.
pub struct Scanner {
    /// The secret, lowercased, compared against lowercased views.
    folded: Vec<Zeroizing<Vec<u8>>>,
    /// Base64 forms, compared against views as they are.
    exact: Vec<Zeroizing<Vec<u8>>>,
}

/// The shortest run of the secret's start or end that is looked for on its
/// own: a server that echoes a value cut short still gives most of it away.
const MIN_PART: usize = 16;

impl Scanner {
    pub fn new(secret: &[u8]) -> Self {
        // The whole secret, and its first and last halves (at least
        // [`MIN_PART`] bytes each, the whole when shorter).
        let part = MIN_PART.max(secret.len().div_ceil(2)).min(secret.len());
        let parts = [secret, &secret[..part], &secret[secret.len() - part..]];
        let mut folded = Vec::new();
        for p in parts {
            folded.push(Zeroizing::new(p.to_ascii_lowercase()));
            let mut hex = Zeroizing::new(vec![0; p.len() * 2]);
            hex::encode_to_slice(p, &mut hex).expect("sized for the hex");
            folded.push(hex);
        }
        // A Basic credential is base64 of `user:password`, and servers echo
        // it decoded: look for the pair and the password as well.
        if let Some(pair) = basic_pair(secret) {
            if let Some(colon) = pair.iter().position(|&b| b == b':') {
                let password = &pair[colon + 1..];
                if password.len() >= 8 {
                    folded.push(Zeroizing::new(password.to_ascii_lowercase()));
                }
            }
            folded.push(Zeroizing::new(pair.to_ascii_lowercase()));
        }
        folded.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        folded.dedup();
        let mut exact = Vec::new();
        for p in parts {
            for alphabet in [B64_STD, B64_URL] {
                for offset in 0..3 {
                    let form = base64_inner(p, offset, alphabet);
                    if !form.is_empty() {
                        exact.push(form);
                    }
                }
            }
        }
        exact.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        exact.dedup();
        Self { folded, exact }
    }

    /// Whether the secret occurs anywhere in `haystack`, in any form.
    pub fn found_in(&self, haystack: &[u8]) -> bool {
        views().any(|chain| {
            let mut view = Zeroizing::new(haystack.to_vec());
            for decode in chain {
                view = decode(&view);
            }
            let lowered = Zeroizing::new(view.to_ascii_lowercase());
            self.folded
                .iter()
                .any(|f| memmem::find(&lowered, f).is_some())
                || self.exact.iter().any(|f| memmem::find(&view, f).is_some())
        })
    }
}

fn hex_value(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

fn push_char(out: &mut Vec<u8>, code: u32) -> bool {
    match char::from_u32(code) {
        Some(c) => {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            true
        }
        None => false,
    }
}

/// The secret base64-decoded, when it is base64 of `user:password` in
/// printable ASCII.
fn basic_pair(secret: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    use base64::Engine;
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(secret)
            .ok()?,
    );
    (decoded.contains(&b':') && decoded.iter().all(|b| (b' '..=b'~').contains(b)))
        .then_some(decoded)
}

/// Without NUL, CR and LF: UTF-16 or UTF-32 text of ASCII, and base64 or
/// hex broken into lines, read as the bytes they carry.
fn strip_decode(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    out.extend(input.iter().filter(|&&b| !matches!(b, 0 | b'\r' | b'\n')));
    out
}

/// `%XX` in either case to its byte; `+` is left alone, as in a path.
fn percent_decode(input: &[u8]) -> Zeroizing<Vec<u8>> {
    percent_decode_with(input, false)
}

/// `%XX` in either case to its byte, and `+` to a space, as in a form.
fn form_decode(input: &[u8]) -> Zeroizing<Vec<u8>> {
    percent_decode_with(input, true)
}

fn percent_decode_with(input: &[u8], plus_is_space: bool) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' => match (
                input.get(i + 1).copied().and_then(hex_value),
                input.get(i + 2).copied().and_then(hex_value),
            ) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' if plus_is_space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// JSON string escapes to what they stand for. A `\uXXXX` that is half of a
/// surrogate pair, or not hex, is passed through.
fn json_decode(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\\' {
            let simple = match input.get(i + 1) {
                Some(b'/') => Some(b'/'),
                Some(b'"') => Some(b'"'),
                Some(b'\\') => Some(b'\\'),
                Some(b'b') => Some(0x08),
                Some(b'f') => Some(0x0c),
                Some(b'n') => Some(b'\n'),
                Some(b'r') => Some(b'\r'),
                Some(b't') => Some(b'\t'),
                _ => None,
            };
            if let Some(b) = simple {
                out.push(b);
                i += 2;
                continue;
            }
            if input.get(i + 1) == Some(&b'u') {
                let code = input
                    .get(i + 2..i + 6)
                    .filter(|h| h.iter().all(|b| b.is_ascii_hexdigit()))
                    .and_then(|h| u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
                if let Some(code) = code {
                    if push_char(&mut out, code) {
                        i += 6;
                        continue;
                    }
                }
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

/// HTML character references to what they stand for: the named ones for
/// characters an encoder escapes, and numeric ones of at most
/// [`MAX_ENTITY_DIGITS`] digits. Anything else is passed through.
fn html_decode(input: &[u8]) -> Zeroizing<Vec<u8>> {
    const NAMED: &[(&[u8], u8)] = &[
        (b"amp;", b'&'),
        (b"lt;", b'<'),
        (b"gt;", b'>'),
        (b"quot;", b'"'),
        (b"apos;", b'\''),
        (b"sol;", b'/'),
        (b"bsol;", b'\\'),
        (b"plus;", b'+'),
        (b"equals;", b'='),
        (b"percnt;", b'%'),
        (b"num;", b'#'),
        (b"colon;", b':'),
        (b"lowbar;", b'_'),
        (b"period;", b'.'),
        (b"comma;", b','),
        (b"excl;", b'!'),
        (b"quest;", b'?'),
        (b"dollar;", b'$'),
        (b"commat;", b'@'),
        (b"nbsp;", b' '),
        (b"lpar;", b'('),
        (b"rpar;", b')'),
        (b"ast;", b'*'),
        (b"midast;", b'*'),
        (b"semi;", b';'),
        (b"lsqb;", b'['),
        (b"lbrack;", b'['),
        (b"rsqb;", b']'),
        (b"rbrack;", b']'),
        (b"hat;", b'^'),
        (b"grave;", b'`'),
        (b"lcub;", b'{'),
        (b"lbrace;", b'{'),
        (b"rcub;", b'}'),
        (b"rbrace;", b'}'),
        (b"verbar;", b'|'),
        (b"vert;", b'|'),
        (b"tab;", b'\t'),
        (b"newline;", b'\n'),
        (b"tilde;", b'~'),
        (b"minus;", b'-'),
        (b"hyphen;", b'-'),
        (b"dash;", b'-'),
    ];
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut i = 0;
    'outer: while i < input.len() {
        if input[i] == b'&' {
            let rest = &input[i + 1..];
            if rest.first() == Some(&b'#') {
                let (radix, start) = match rest.get(1) {
                    Some(b'x' | b'X') => (16, 2),
                    _ => (10, 1),
                };
                let digits = rest[start..]
                    .iter()
                    .take(MAX_ENTITY_DIGITS + 1)
                    .take_while(|b| (**b as char).is_digit(radix))
                    .count();
                if (1..=MAX_ENTITY_DIGITS).contains(&digits)
                    && rest.get(start + digits) == Some(&b';')
                {
                    let text = std::str::from_utf8(&rest[start..start + digits]).unwrap_or("");
                    if let Ok(code) = u32::from_str_radix(text, radix) {
                        if push_char(&mut out, code) {
                            i += 1 + start + digits + 1;
                            continue;
                        }
                    }
                }
            } else {
                for (name, b) in NAMED {
                    if rest.len() >= name.len() && rest[..name.len()].eq_ignore_ascii_case(name) {
                        out.push(*b);
                        i += 1 + name.len();
                        continue 'outer;
                    }
                }
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

/// The base64 characters that depend only on `secret` when it is encoded
/// after `offset` other bytes, whatever those bytes and whatever follows: the
/// form the secret takes inside a larger base64 string at that alignment.
fn base64_inner(secret: &[u8], offset: usize, alphabet: &[u8; 64]) -> Zeroizing<Vec<u8>> {
    let start_bit = offset * 8;
    let end_bit = (offset + secret.len()) * 8;
    let first = start_bit.div_ceil(6);
    let Some(last) = (end_bit / 6).checked_sub(1) else {
        return Zeroizing::new(Vec::new());
    };
    let bit = |i: usize| -> u8 {
        if i < start_bit || i >= end_bit {
            0
        } else {
            let j = i - start_bit;
            (secret[j / 8] >> (7 - j % 8)) & 1
        }
    };
    Zeroizing::new(
        (first..=last)
            .map(|c| {
                let v = (0..6).fold(0u8, |acc, k| (acc << 1) | bit(c * 6 + k));
                alphabet[usize::from(v)]
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const SECRET: &[u8] = b"tk_live_Ab/+=&<>\"'\\ x9";

    fn json(s: &[u8]) -> Vec<u8> {
        serde_json::to_string(std::str::from_utf8(s).unwrap())
            .unwrap()
            .into_bytes()
    }

    fn encoded_forms() -> Vec<Vec<u8>> {
        let mut forms = vec![
            SECRET.to_vec(),
            SECRET.to_ascii_uppercase(),
            hex::encode(SECRET).into_bytes(),
            hex::encode_upper(SECRET).into_bytes(),
            urlencoding::encode_binary(SECRET).into_owned().into_bytes(),
            urlencoding::encode_binary(SECRET)
                .replace("%20", "+")
                .to_lowercase()
                .into_bytes(),
            json(SECRET),
            // PHP: `/` escaped, `+` left alone.
            br#"tk_live_Ab\/+=&<>\"'\\ x9"#.to_vec(),
            // Go: `<`, `>`, `&` as \u escapes.
            br#"tk_live_Ab/+=&<>\"'\\ x9"#.to_vec(),
            br#"tk_live_Ab/+=\u0026\u003C\u003E\"'\\ x9"#.to_vec(),
            // encodeURIComponent leaves !'()* alone; Python quote leaves / alone.
            b"tk_live_Ab/%2B%3D%26%3C%3E%22'%5C%20x9".to_vec(),
            b"tk_live_Ab&#x2f;+=&amp;&lt;&gt;&quot;&#39;\\ x9".to_vec(),
            b"tk&#95;live&#95;Ab&#47;&#43;&#61;&#38;&#60;&#62;&#34;&#39;&#92;&#32;x9".to_vec(),
            b"tk_live_Ab&#X00002F;+=&AMP;&LT;&GT;&QUOT;&apos;&bsol;&nbsp;x9".to_vec(),
            // Go's PathEscape: `+` left alone, `/` encoded.
            b"tk_live_Ab%2F+=&%3C%3E%22%27%5C%20x9".to_vec(),
            // HTML-escaped JSON, as server-rendered props carry it.
            br#"tk_live_Ab\/+=&amp;&lt;&gt;&quot;&#39;\\ x9"#.to_vec(),
            b"tk_live_Ab&sol;&plus;&equals;&amp;&lt;&gt;&quot;&apos;&bsol; x9".to_vec(),
            // A percent-encoded value inside a JSON string, and inside HTML.
            json(urlencoding::encode_binary(SECRET).as_bytes()),
            urlencoding::encode_binary(SECRET)
                .replace('%', "&#37;")
                .into_bytes(),
        ];
        let all_u: String = SECRET
            .iter()
            .map(|&b| {
                if b.is_ascii_alphanumeric() {
                    (b as char).to_string()
                } else {
                    format!("\\u{b:04X}")
                }
            })
            .collect();
        forms.push(all_u.into_bytes());
        // UTF-16 and UTF-32, either byte order, as a server answering in the
        // request's charset writes them.
        let wide = |width: usize, big: bool| -> Vec<u8> {
            SECRET
                .iter()
                .flat_map(|&b| {
                    let mut unit = vec![0; width];
                    unit[if big { width - 1 } else { 0 }] = b;
                    unit
                })
                .collect()
        };
        for (width, big) in [(2, false), (2, true), (4, false), (4, true)] {
            forms.push(wide(width, big));
        }
        let engines = [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ];
        for engine in engines {
            for prefix in [&b""[..], b"x", b"xy", b"user:"] {
                let mut input = prefix.to_vec();
                input.extend_from_slice(SECRET);
                input.extend_from_slice(b"tail");
                let b64 = engine.encode(&input).into_bytes();
                // MIME and PEM wrap base64 into lines; wrapped short here so
                // no part of the secret survives unbroken.
                let wrapped: Vec<u8> = b64.chunks(6).collect::<Vec<_>>().join(&b"\r\n"[..]);
                forms.push(wrapped);
                forms.push(json(&b64).replace_slash());
                forms.push(b64);
                let mut bare = prefix.to_vec();
                bare.extend_from_slice(SECRET);
                forms.push(engine.encode(&bare).into_bytes());
            }
        }
        forms
    }

    trait ReplaceSlash {
        fn replace_slash(self) -> Vec<u8>;
    }

    impl ReplaceSlash for Vec<u8> {
        /// JSON with `/` escaped, as PHP writes it.
        fn replace_slash(self) -> Vec<u8> {
            String::from_utf8(self)
                .unwrap()
                .replace('/', "\\/")
                .into_bytes()
        }
    }

    #[test]
    fn every_encoded_form_is_found_inside_other_text() {
        let scanner = Scanner::new(SECRET);
        for form in encoded_forms() {
            let mut body = b"{\"headers\":{\"Authorization\":\"Bearer ".to_vec();
            body.extend_from_slice(&form);
            body.extend_from_slice(b"\"}}");
            assert!(
                scanner.found_in(&body),
                "not found: {}",
                String::from_utf8_lossy(&form)
            );
        }
    }

    #[test]
    fn a_fragment_shorter_than_the_parts_looked_for_is_not_found() {
        let scanner = Scanner::new(SECRET);
        assert!(!scanner.found_in(b"{\"ok\":true}"));
        assert!(!scanner.found_in(&SECRET[..MIN_PART - 1]));
        assert!(!scanner.found_in(&SECRET[SECRET.len() - MIN_PART + 1..]));
        assert!(!scanner.found_in(&SECRET[3..3 + MIN_PART]));
        assert!(!scanner.found_in(b""));
        // Broken in both halves: neither is intact.
        let mut broken = SECRET.to_vec();
        broken[5] = b'#';
        broken[SECRET.len() - 5] = b'#';
        assert!(!scanner.found_in(&broken));
    }

    fn pct(input: &[u8]) -> Vec<u8> {
        input
            .iter()
            .flat_map(|b| format!("%{b:02X}").into_bytes())
            .collect()
    }

    fn json_u(input: &[u8]) -> Vec<u8> {
        input
            .iter()
            .flat_map(|b| format!("\\u{b:04x}").into_bytes())
            .collect()
    }

    fn html_x(input: &[u8]) -> Vec<u8> {
        input
            .iter()
            .flat_map(|b| format!("&#x{b:06x};").into_bytes())
            .collect()
    }

    /// Each encoder writes every byte in the longest escape its decoder
    /// accepts, so a pair of them is the longest form a view finds.
    #[test]
    fn the_longest_form_bounds_every_view() {
        let scanner = Scanner::new(SECRET);
        type Encoder = fn(&[u8]) -> Vec<u8>;
        let encoders: [Encoder; 3] = [pct, json_u, html_x];
        assert_eq!(html_x(b"/").len(), MAX_ESCAPE);
        for outer in encoders {
            for inner in encoders {
                let body = outer(&inner(SECRET));
                assert!(body.len() <= longest_form(SECRET.len()));
                assert!(
                    scanner.found_in(&body),
                    "{}",
                    String::from_utf8_lossy(&body)
                );
            }
            let body = outer(SECRET);
            assert!(scanner.found_in(&body));
        }
        let too_long: Vec<u8> = SECRET
            .iter()
            .flat_map(|b| format!("&#x{b:07x};").into_bytes())
            .collect();
        assert!(!scanner.found_in(&too_long));
    }

    #[test]
    fn a_basic_credential_is_found_decoded() {
        use base64::Engine;
        let secret = base64::engine::general_purpose::STANDARD.encode("deploy:hunter2-Long!");
        let scanner = Scanner::new(secret.as_bytes());
        assert!(scanner.found_in(b"invalid user deploy:hunter2-Long! for realm"));
        assert!(scanner.found_in(b"wrong password: hunter2-long!"));
        assert!(!scanner.found_in(b"user deploy is unknown"));
        let short = base64::engine::general_purpose::STANDARD.encode("u:pw");
        let scanner = Scanner::new(short.as_bytes());
        assert!(!scanner.found_in(b"pw"));
        assert!(scanner.found_in(b"u:pw"));
    }

    /// A server that echoes the value cut short, from either end, gives
    /// most of it away: its first or last half is enough to refuse.
    #[test]
    fn an_echo_of_most_of_the_secret_is_found() {
        use base64::Engine;
        let secret = b"tk_live_0123456789abcdefghijklmnopqrstuvwxyz";
        let scanner = Scanner::new(secret);
        let half = secret.len().div_ceil(2);
        for echo in [
            secret[..secret.len() - 3].to_vec(),
            secret[3..].to_vec(),
            secret[..half].to_vec(),
            secret[secret.len() - half..].to_vec(),
            base64::engine::general_purpose::STANDARD
                .encode(&secret[..secret.len() - 2])
                .into_bytes(),
            hex::encode(&secret[4..]).into_bytes(),
        ] {
            assert!(
                scanner.found_in(&echo),
                "{}",
                String::from_utf8_lossy(&echo)
            );
        }
        assert!(!scanner.found_in(&secret[..half - 1]));
        // A short secret is looked for whole.
        let short = Scanner::new(b"0123456789ab");
        assert!(!short.found_in(b"0123456789a"));
        assert!(short.found_in(b"x0123456789abx"));
    }

    #[test]
    fn decoders_pass_through_what_is_not_an_escape() {
        assert_eq!(&*percent_decode(b"%zz%4%41+%+1"), b"%zz%4A+%+1");
        assert_eq!(&*form_decode(b"%zz%4%41+"), b"%zz%4A ");
        assert_eq!(
            &*json_decode(b"\\q\\u12\\ud800\\u0041"),
            b"\\q\\u12\\ud800A"
        );
        assert_eq!(
            &*html_decode(b"&bogus; &#; &#x; &#65 &#0000065; &#65;"),
            b"&bogus; &#; &#x; &#65 &#0000065; A"
        );
    }

    #[test]
    fn base64_inner_forms_match_a_real_encoder_at_each_alignment() {
        let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
        for offset in 0..3 {
            let inner = base64_inner(SECRET, offset, B64_STD);
            for pad in [0u8, 0xff] {
                let mut input = vec![pad; offset];
                input.extend_from_slice(SECRET);
                input.extend_from_slice(&[pad; 2]);
                let encoded = engine.encode(&input);
                assert!(memmem::find(encoded.as_bytes(), &inner).is_some());
            }
        }
    }
}
