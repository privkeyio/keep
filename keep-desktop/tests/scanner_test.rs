// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use std::collections::HashMap;

const MAX_SHARE_LENGTH: usize = 8192;
const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn is_valid_bech32_payload(prefix: &str, data: &str) -> bool {
    data.len() <= MAX_SHARE_LENGTH
        && data.starts_with(prefix)
        && data[prefix.len()..]
            .bytes()
            .all(|b| BECH32_CHARSET.contains(&b))
        && data.len() > prefix.len()
}

fn process_qr_content(
    content: &str,
    collected_frames: &mut HashMap<usize, String>,
    total_expected: &mut Option<usize>,
) -> (Option<String>, &'static str) {
    let trimmed = content.trim();

    if is_valid_bech32_payload("kshare1", trimmed)
        || is_valid_bech32_payload("nsec1", trimmed)
        || is_valid_bech32_payload("ncryptsec1", trimmed)
    {
        return (Some(trimmed.to_string()), "recognized");
    }

    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let (Some(f), Some(t), Some(_d)) = (
            parsed.get("f").and_then(|v| v.as_u64()),
            parsed.get("t").and_then(|v| v.as_u64()),
            parsed.get("d").and_then(|v| v.as_str()),
        ) {
            const MAX_ANIMATED_FRAMES: usize = 100;
            let Some(idx) = usize::try_from(f).ok() else {
                return (None, "invalid");
            };
            let Some(total) = usize::try_from(t).ok() else {
                return (None, "invalid");
            };
            if total == 0 || total > MAX_ANIMATED_FRAMES || idx >= total {
                return (None, "invalid");
            }
            match *total_expected {
                None => *total_expected = Some(total),
                Some(existing) if existing != total => {
                    collected_frames.clear();
                    *total_expected = Some(total);
                }
                _ => {}
            }
            collected_frames.insert(idx, trimmed.to_string());
            return (None, "collecting");
        }

        if parsed.get("version").is_some() && parsed.get("encrypted_share").is_some() {
            return (Some(trimmed.to_string()), "json_share");
        }
    }

    (None, "unrecognized")
}

#[test]
fn test_single_kshare1_recognized() {
    let mut frames = HashMap::new();
    let mut total = None;
    let kshare = "kshare1qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let (result, kind) = process_qr_content(kshare, &mut frames, &mut total);
    assert_eq!(result, Some(kshare.to_string()));
    assert_eq!(kind, "recognized");
}

#[test]
fn test_single_nsec_recognized() {
    let mut frames = HashMap::new();
    let mut total = None;
    let nsec = "nsec1qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let (result, _) = process_qr_content(nsec, &mut frames, &mut total);
    assert_eq!(result, Some(nsec.to_string()));
}

#[test]
fn test_single_ncryptsec_recognized() {
    let mut frames = HashMap::new();
    let mut total = None;
    let ncryptsec = "ncryptsec1qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let (result, _) = process_qr_content(ncryptsec, &mut frames, &mut total);
    assert_eq!(result, Some(ncryptsec.to_string()));
}

#[test]
fn test_unrecognized_content() {
    let mut frames = HashMap::new();
    let mut total = None;
    let (result, kind) = process_qr_content("https://example.com", &mut frames, &mut total);
    assert!(result.is_none());
    assert_eq!(kind, "unrecognized");
}

#[test]
fn test_json_share_format() {
    let mut frames = HashMap::new();
    let mut total = None;
    let json = r#"{"version":1,"encrypted_share":"deadbeef"}"#;
    let (result, kind) = process_qr_content(json, &mut frames, &mut total);
    assert_eq!(result, Some(json.to_string()));
    assert_eq!(kind, "json_share");
}

#[test]
fn test_animated_frame_collection() {
    let mut frames = HashMap::new();
    let mut total = None;

    let (r, k) = process_qr_content(r#"{"f":0,"t":3,"d":"chunk0"}"#, &mut frames, &mut total);
    assert!(r.is_none());
    assert_eq!(k, "collecting");
    assert_eq!(frames.len(), 1);
    assert_eq!(total, Some(3));

    let (r, _) = process_qr_content(r#"{"f":1,"t":3,"d":"chunk1"}"#, &mut frames, &mut total);
    assert!(r.is_none());
    assert_eq!(frames.len(), 2);
}

#[test]
fn test_animated_frame_total_mismatch_resets() {
    let mut frames = HashMap::new();
    let mut total = None;

    process_qr_content(r#"{"f":0,"t":3,"d":"chunk0"}"#, &mut frames, &mut total);
    assert_eq!(frames.len(), 1);

    process_qr_content(r#"{"f":0,"t":5,"d":"chunk0"}"#, &mut frames, &mut total);
    assert_eq!(total, Some(5));
    assert_eq!(frames.len(), 1);
}

#[test]
fn test_animated_frame_zero_total_rejected() {
    let mut frames = HashMap::new();
    let mut total = None;
    let (r, k) = process_qr_content(r#"{"f":0,"t":0,"d":"chunk0"}"#, &mut frames, &mut total);
    assert!(r.is_none());
    assert_eq!(k, "invalid");
    assert!(frames.is_empty());
}

#[test]
fn test_animated_frame_index_exceeds_total() {
    let mut frames = HashMap::new();
    let mut total = None;
    let (r, k) = process_qr_content(r#"{"f":5,"t":3,"d":"chunk0"}"#, &mut frames, &mut total);
    assert!(r.is_none());
    assert_eq!(k, "invalid");
    assert!(frames.is_empty());
}

#[test]
fn test_kshare_too_long_rejected() {
    let mut frames = HashMap::new();
    let mut total = None;
    let long = format!("kshare1{}", "q".repeat(8200));
    let (result, kind) = process_qr_content(&long, &mut frames, &mut total);
    assert!(result.is_none());
    assert_eq!(kind, "unrecognized");
}

#[test]
fn test_kshare_empty_payload_rejected() {
    let mut frames = HashMap::new();
    let mut total = None;
    let (result, kind) = process_qr_content("kshare1", &mut frames, &mut total);
    assert!(result.is_none());
    assert_eq!(kind, "unrecognized");
}

#[test]
fn test_whitespace_trimmed() {
    let mut frames = HashMap::new();
    let mut total = None;
    let (result, _) = process_qr_content(
        "  kshare1qpzry9x8gf2tvdw0s3jn54khce6mua7l  ",
        &mut frames,
        &mut total,
    );
    assert_eq!(
        result,
        Some("kshare1qpzry9x8gf2tvdw0s3jn54khce6mua7l".to_string())
    );
}

#[test]
fn test_invalid_bech32_chars_rejected() {
    let mut frames = HashMap::new();
    let mut total = None;
    let (result, _) = process_qr_content("kshare1INVALID_CHARS!", &mut frames, &mut total);
    assert!(result.is_none());
}

#[test]
fn test_animated_max_frames_exceeded() {
    let mut frames = HashMap::new();
    let mut total = None;
    let (r, k) =
        process_qr_content(r#"{"f":0,"t":101,"d":"chunk0"}"#, &mut frames, &mut total);
    assert!(r.is_none());
    assert_eq!(k, "invalid");
}

#[test]
fn test_duplicate_frame_overwrites() {
    let mut frames = HashMap::new();
    let mut total = None;

    process_qr_content(r#"{"f":0,"t":3,"d":"first"}"#, &mut frames, &mut total);
    process_qr_content(r#"{"f":0,"t":3,"d":"second"}"#, &mut frames, &mut total);
    assert_eq!(frames.len(), 1);
    assert!(frames.get(&0).unwrap().contains("second"));
}
