// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};

/// Truncate a string to `prefix` leading chars + `...` + `suffix` trailing chars.
///
/// Returns the original string unchanged if it is short enough or not ASCII.
pub fn truncate_str(s: &str, prefix: usize, suffix: usize) -> String {
    let guard = prefix + suffix + 3;
    if !s.is_ascii() || s.len() <= guard {
        return s.to_owned();
    }
    format!("{}...{}", &s[..prefix], &s[s.len() - suffix..])
}

/// Format a Unix timestamp as `"2024-01-15 10:30 UTC"`.
pub fn format_timestamp(ts: i64) -> String {
    DateTime::<Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Format a Unix timestamp as `"Jan 15, 2024 10:30:00"` (detailed, no timezone label).
pub fn format_timestamp_detailed(ts: i64) -> String {
    DateTime::<Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string())
        .unwrap_or_else(|| ts.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate_str("npub1abc", 12, 6), "npub1abc");
    }

    #[test]
    fn truncate_non_ascii_unchanged() {
        let s = "npub1こんにちは世界abc";
        assert_eq!(truncate_str(s, 12, 6), s);
    }

    #[test]
    fn truncate_at_guard_boundary_unchanged() {
        // prefix=8, suffix=6, guard=17; string of length 17 should be unchanged
        let s = "a".repeat(17);
        assert_eq!(truncate_str(&s, 8, 6), s);
    }

    #[test]
    fn truncate_one_over_guard() {
        let s = "a".repeat(18);
        let result = truncate_str(&s, 8, 6);
        assert_eq!(result, "aaaaaaaa...aaaaaa");
        assert_eq!(result.len(), 17);
    }

    #[test]
    fn truncate_npub_style() {
        let npub = "npub1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbb";
        let result = truncate_str(npub, 12, 6);
        assert_eq!(&result[..12], "npub1aaaaaaa");
        assert!(result.contains("..."));
        assert_eq!(&result[result.len() - 6..], "bbbbbb");
    }

    #[test]
    fn truncate_hex_style() {
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let result = truncate_str(hex, 8, 6);
        assert_eq!(&result[..8], "abcdef01");
        assert!(result.contains("..."));
        assert_eq!(&result[result.len() - 6..], "456789");
    }

    #[test]
    fn format_timestamp_valid() {
        let result = format_timestamp(1705314600);
        assert_eq!(result, "2024-01-15 10:30 UTC");
    }

    #[test]
    fn format_timestamp_zero() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00 UTC");
    }

    #[test]
    fn format_timestamp_detailed_valid() {
        let result = format_timestamp_detailed(1705314600);
        assert_eq!(result, "Jan 15, 2024 10:30:00");
    }
}
