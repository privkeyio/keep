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

/// Rewrite every anchored `/0/*` tail to `/1/*`, using the same anchoring
/// rules as [`rewrite_trailing_zero_star`] so nested paths and origin info
/// are left alone. Used to derive an internal (change) descriptor from an
/// external (receive) descriptor without touching unrelated `/0/*` substrings.
pub fn rewrite_trailing_zero_to_one(body: &str) -> String {
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len());
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
            out.push_str("/1/*");
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

    #[test]
    fn rewrite_zero_to_one_targets_terminating_segment() {
        assert_eq!(
            rewrite_trailing_zero_to_one("tr(xpub.../0/0/*)"),
            "tr(xpub.../0/1/*)"
        );
    }

    #[test]
    fn rewrite_zero_to_one_ignores_origin_info() {
        assert_eq!(
            rewrite_trailing_zero_to_one("tr([deadbeef/86'/0'/0']xpub.../0/*)"),
            "tr([deadbeef/86'/0'/0']xpub.../1/*)"
        );
    }

    #[test]
    fn rewrite_zero_to_one_handles_multiple_keys() {
        assert_eq!(
            rewrite_trailing_zero_to_one("wsh(sortedmulti(2,xpub1/0/*,xpub2/0/*))"),
            "wsh(sortedmulti(2,xpub1/1/*,xpub2/1/*))"
        );
    }

    // === #417 round 3: targeted unit tests killing the byte-scan mutants ===

    /// `contains_tail` MUST reject the doubled-slash pattern `//{digit}/*)`.
    /// A regression on the `i == 0 || bytes[i - 1] != b'/'` guard would let a
    /// descriptor with a bogus `//0/*)` substring drive the rewrite path,
    /// producing nonsense output. Both the i==0 boundary and the prior-byte
    /// check are pinned here.
    #[test]
    fn contains_tail_rejects_doubled_slash() {
        assert!(!contains_tail("xpub..//0/*)", '0'));
        assert!(!contains_tail("xpub..//1/*)", '1'));
        // ...but a single slash with the same shape DOES match.
        assert!(contains_tail("xpub../0/*)", '0'));
    }

    /// The `i == 0` boundary in the prior-byte guard: a descriptor body
    /// starting with the tail itself MUST match. Mutating the equality flips
    /// every match through the prior-byte check, which underflows or matches
    /// the wrong byte when `i == 0`.
    #[test]
    fn contains_tail_matches_at_position_zero() {
        assert!(contains_tail("/0/*)", '0'));
        assert!(contains_tail("/1/*,", '1'));
    }

    /// The trailing byte must be `)` or `,`. Any other character (including
    /// space, end-of-string, or `/`) MUST NOT match, otherwise the rewrite
    /// fires on arbitrary nested paths and the descriptor becomes malformed.
    #[test]
    fn contains_tail_requires_close_paren_or_comma_after_star() {
        // The five-byte window is /0/*X; X must be ) or , .
        assert!(!contains_tail("xpub.../0/* ", '0'));
        assert!(!contains_tail("xpub.../0/*/", '0'));
        assert!(!contains_tail("xpub.../0/*x", '0'));
        // Exactly at end-of-string the next byte doesn't exist — loop
        // condition `i + 4 < bytes.len()` excludes the last 4-byte window,
        // so a body ending in `/0/*` with no trailing byte cannot match.
        assert!(!contains_tail("/0/*", '0'));
    }

    /// `contains_tail` MUST NOT match a wrong digit. Pin `contains_tail("/0/*)", '1')`
    /// → false and the reverse → true so a regression that ignores the digit
    /// parameter (e.g. replaces `bytes[i + 1] == digit_byte` with `true`) is
    /// caught.
    #[test]
    fn contains_tail_only_matches_the_requested_digit() {
        assert!(!contains_tail("xpub.../0/*)", '1'));
        assert!(!contains_tail("xpub.../1/*)", '0'));
        // Both digits exist as terminating tails in the body; each call
        // matches only its own.
        let mixed = "wsh(sortedmulti(2,xpub1/0/*,xpub2/1/*))";
        assert!(contains_tail(mixed, '0'));
        assert!(contains_tail(mixed, '1'));
    }

    /// `rewrite_trailing_zero_star` MUST be the identity on inputs with no
    /// terminating `/0/*` tail. A regression that always emits the rewrite
    /// would corrupt unrelated descriptors and any input containing a `/1/*`
    /// (the change descriptor) would lose its derivation tail.
    #[test]
    fn rewrite_trailing_zero_star_is_identity_when_no_match() {
        // No /0/* tail at all.
        assert_eq!(
            rewrite_trailing_zero_star("tr(xpub.../1/*)"),
            "tr(xpub.../1/*)"
        );
        // Empty body.
        assert_eq!(rewrite_trailing_zero_star(""), "");
        // Multipath marker already present.
        let already = "tr(xpub.../<0;1>/*)";
        assert_eq!(rewrite_trailing_zero_star(already), already);
        // Doubled-slash pattern — anchoring rejects.
        let doubled = "tr(xpub..//0/*)";
        assert_eq!(rewrite_trailing_zero_star(doubled), doubled);
    }

    /// `rewrite_trailing_zero_star` preserves content before AND after the
    /// matched tail. A regression that drops the `out.push_str(&body[run_start..i])`
    /// would silently truncate the prefix; one that drops the trailing copy
    /// after the loop would silently truncate the suffix. The input is
    /// asymmetric on purpose: a distinctive origin-info prefix and a checksum
    /// suffix flank a single rewrite, so dropping either copy fails uniquely.
    #[test]
    fn rewrite_trailing_zero_star_preserves_prefix_and_suffix() {
        let input = "tr([deadbeef/86'/0'/0']xpub.../0/*)#abcd1234";
        let out = rewrite_trailing_zero_star(input);
        assert_eq!(out, "tr([deadbeef/86'/0'/0']xpub.../<0;1>/*)#abcd1234");
    }

    /// `rewrite_trailing_zero_to_one` is the identity on inputs without a
    /// terminating `/0/*`. Same anchoring as `rewrite_trailing_zero_star`;
    /// pin both functions independently in case the implementation diverges.
    #[test]
    fn rewrite_trailing_zero_to_one_is_identity_when_no_match() {
        assert_eq!(
            rewrite_trailing_zero_to_one("tr(xpub.../1/*)"),
            "tr(xpub.../1/*)"
        );
        assert_eq!(rewrite_trailing_zero_to_one(""), "");
        let doubled = "tr(xpub..//0/*)";
        assert_eq!(rewrite_trailing_zero_to_one(doubled), doubled);
    }

    /// `has_multipath_marker` matches the exact `<0;1>` and `<1;0>` literals,
    /// NOT partial forms. A regression that checks for `<` alone or just
    /// `0;1` would let any descriptor with a stray `<` slip past the marker
    /// gate and reach the rewrite path with a malformed shape.
    #[test]
    fn has_multipath_marker_requires_exact_literal() {
        assert!(has_multipath_marker("tr(xpub.../<0;1>/*)"));
        assert!(has_multipath_marker("tr(xpub.../<1;0>/*)"));

        // Partial matches must not register.
        assert!(!has_multipath_marker("tr(xpub.../0;1/*)"));
        assert!(!has_multipath_marker("tr(xpub.../<0;/*)"));
        assert!(!has_multipath_marker("tr(xpub.../0;1>/*)"));
        // Empty body.
        assert!(!has_multipath_marker(""));
        // Non-matching substring.
        assert!(!has_multipath_marker("tr(xpub.../0/*)"));
    }

    /// `has_single_path_tail` MUST return true if EITHER `/0/*` or `/1/*`
    /// terminates the body. A regression that drops one of the two
    /// `contains_tail` checks (e.g. swaps `||` for `&&`) would let one
    /// digit slip past, defeating the gate's purpose.
    #[test]
    fn has_single_path_tail_matches_either_digit() {
        assert!(has_single_path_tail("tr(xpub.../0/*)"));
        assert!(has_single_path_tail("tr(xpub.../1/*)"));
        // Multipath: neither single-path tail matches.
        assert!(!has_single_path_tail("tr(xpub.../<0;1>/*)"));
        // Empty body.
        assert!(!has_single_path_tail(""));
    }

    /// The inner-window bound `i + 4 < bytes.len()` MUST stay strict. With
    /// `<=`, an input of length exactly 4 (e.g. `"/0/*"`) would let the if
    /// chain index `bytes[i + 4]` past the end, panicking the rewrite. Pin
    /// both rewrite functions with a length-4 input so the mutation is
    /// caught as a test panic.
    #[test]
    fn rewrite_handles_minimum_length_input_without_panicking() {
        // The body "/0/*" is exactly the 4-byte tail with no trailing
        // ')' or ',', so neither rewrite function should match. The
        // `< → <=` mutation on the window bound would push past the
        // end of the slice during the `matches!(bytes[i + 4], ...)`
        // check and panic.
        assert_eq!(rewrite_trailing_zero_star("/0/*"), "/0/*");
        assert_eq!(rewrite_trailing_zero_to_one("/0/*"), "/0/*");
        // Length-4 with a non-matching prefix — exercises the same
        // boundary at i+4 == 4.
        assert_eq!(rewrite_trailing_zero_star("xyzw"), "xyzw");
        assert_eq!(rewrite_trailing_zero_to_one("xyzw"), "xyzw");
    }
}
