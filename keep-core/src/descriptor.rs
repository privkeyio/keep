// SPDX-FileCopyrightText: (C) 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

//! Shared text-level helpers for output descriptor strings.
//!
//! These helpers live in `keep-core` so that both `keep-bitcoin` (for
//! normalization) and `keep-nip46` (for validation) can agree on how a
//! single-path `/0/*` or `/1/*` tail is detected.

/// Returns true if the descriptor body contains a terminating `/{digit}/*`
/// derivation suffix, i.e. a `/{digit}/*` immediately followed by `)` or `,`.
/// The guard `bytes[i - 1] != b'/'` only rejects a doubled slash `//{digit}/*`;
/// nested paths like `xpub.../0/0/*)` also match at the trailing segment
/// because that segment drives external/change derivation.
pub fn contains_tail(body: &str, digit: char) -> bool {
    let bytes = body.as_bytes();
    let digit_byte = digit as u8;
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i] == b'/'
            && bytes[i + 1] == digit_byte
            && bytes[i + 2] == b'/'
            && bytes[i + 3] == b'*'
            && matches!(bytes[i + 4], b')' | b',')
            && (i == 0 || bytes[i - 1] != b'/')
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Rewrite every anchored `/0/*` tail (a `/0/*` followed by `)` or `,`, whose
/// leading `/` is not itself preceded by another `/`) to `/<0;1>/*`. Works on
/// byte indices but copies unchanged regions as UTF-8 slices so the output
/// stays well-formed even if the input contains non-ASCII bytes.
pub fn rewrite_trailing_zero_star(body: &str) -> String {
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len() + 8);
    let mut i = 0;
    let mut run_start = 0;
    while i < bytes.len() {
        if i + 4 < bytes.len()
            && bytes[i] == b'/'
            && bytes[i + 1] == b'0'
            && bytes[i + 2] == b'/'
            && bytes[i + 3] == b'*'
            && matches!(bytes[i + 4], b')' | b',')
            && (i == 0 || bytes[i - 1] != b'/')
        {
            if run_start < i {
                out.push_str(&body[run_start..i]);
            }
            out.push_str("/<0;1>/*");
            i += 4;
            run_start = i;
        } else {
            i += 1;
        }
    }
    if run_start < bytes.len() {
        out.push_str(&body[run_start..]);
    }
    out
}

/// Returns true if the descriptor body contains any BIP-389 multipath
/// placeholder (`<0;1>` or `<1;0>`).
pub fn has_multipath_marker(body: &str) -> bool {
    body.contains("<0;1>") || body.contains("<1;0>")
}

/// Returns true if the descriptor body contains a terminating single-path
/// `/0/*` or `/1/*` derivation suffix on any key expression.
pub fn has_single_path_tail(body: &str) -> bool {
    contains_tail(body, '0') || contains_tail(body, '1')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_tail_matches_terminating_tail_of_deeper_path() {
        // Deeper paths like /86'/0'/0'/0/* also terminate in /0/*; the final
        // segment drives external/change derivation and must be flagged.
        assert!(contains_tail("xpub.../0/0/*)", '0'));
    }

    #[test]
    fn contains_tail_ignores_non_terminating_matches() {
        // /0/*/ is not a tail (not followed by ')' or ','): do not match.
        assert!(!contains_tail("xpub.../0/*/0/*)", '1'));
        // /0 not followed by /* is not a tail.
        assert!(!contains_tail("xpub.../0/1/*)", '0'));
    }

    #[test]
    fn contains_tail_accepts_trailing() {
        assert!(contains_tail("xpub.../0/*)", '0'));
        assert!(contains_tail("xpub.../0/*,", '0'));
    }

    #[test]
    fn rewrite_targets_the_terminating_segment() {
        let input = "tr(xpub.../0/0/*)";
        let out = rewrite_trailing_zero_star(input);
        assert_eq!(out, "tr(xpub.../0/<0;1>/*)");
    }

    #[test]
    fn rewrite_handles_multiple_keys() {
        let input = "wsh(sortedmulti(2,xpub1/0/*,xpub2/0/*))";
        let out = rewrite_trailing_zero_star(input);
        assert_eq!(out, "wsh(sortedmulti(2,xpub1/<0;1>/*,xpub2/<0;1>/*))");
    }

    #[test]
    fn rewrite_ignores_origin_info() {
        let input = "tr([deadbeef/86'/0'/0']xpub.../0/*)";
        let out = rewrite_trailing_zero_star(input);
        assert_eq!(out, "tr([deadbeef/86'/0'/0']xpub.../<0;1>/*)");
    }
}
