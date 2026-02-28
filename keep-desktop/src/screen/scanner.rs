// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use iced::widget::{button, column, container, image as iced_image, row, text, Space};
use iced::{Alignment, Element, Length};

use crate::theme;

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

#[derive(Clone, Debug)]
pub enum Message {
    Close,
    Retry,
}

pub enum Event {
    Close,
    Retry,
}

pub struct ScannerScreen {
    pub frame_handle: Option<iced_image::Handle>,
    pub collected_frames: HashMap<usize, String>,
    pub total_expected: Option<usize>,
    pub status: ScannerStatus,
    pub camera_active: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
pub enum ScannerStatus {
    Initializing,
    Scanning,
    CollectingFrames { got: usize, total: usize },
    Unrecognized(String),
    Error(String),
}

impl ScannerScreen {
    pub fn new() -> Self {
        Self {
            frame_handle: None,
            collected_frames: HashMap::new(),
            total_expected: None,
            status: ScannerStatus::Initializing,
            camera_active: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::Close => Some(Event::Close),
            Message::Retry => Some(Event::Retry),
        }
    }

    pub fn stop_camera(&self) {
        self.camera_active.store(false, Ordering::Release);
    }

    pub fn process_qr_content(&mut self, content: &str) -> Option<String> {
        let trimmed = content.trim();

        if is_valid_bech32_payload("kshare1", trimmed)
            || is_valid_bech32_payload("nsec1", trimmed)
            || is_valid_bech32_payload("ncryptsec1", trimmed)
        {
            return Some(trimmed.to_string());
        }

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let (Some(f), Some(t), Some(_d)) = (
                parsed.get("f").and_then(|v| v.as_u64()),
                parsed.get("t").and_then(|v| v.as_u64()),
                parsed.get("d").and_then(|v| v.as_str()),
            ) {
                const MAX_ANIMATED_FRAMES: usize = 100;
                let idx = usize::try_from(f).ok()?;
                let total = usize::try_from(t).ok()?;
                if total == 0 || total > MAX_ANIMATED_FRAMES || idx >= total {
                    return None;
                }
                match self.total_expected {
                    None => self.total_expected = Some(total),
                    Some(existing) if existing != total => {
                        self.collected_frames.clear();
                        self.total_expected = Some(total);
                        self.status = ScannerStatus::CollectingFrames { got: 0, total };
                    }
                    _ => {}
                }
                self.collected_frames.insert(idx, trimmed.to_string());
                self.status = ScannerStatus::CollectingFrames {
                    got: self.collected_frames.len(),
                    total,
                };

                if self.collected_frames.len() == total {
                    let frames: Option<Vec<String>> = (0..total)
                        .map(|i| self.collected_frames.get(&i).cloned())
                        .collect();
                    let frames = frames?;
                    match keep_core::frost::ShareExport::from_animated_frames(&frames) {
                        Ok(export) => return export.to_bech32().or_else(|_| export.to_json()).ok(),
                        Err(_) => {
                            self.collected_frames.clear();
                            self.total_expected = None;
                            self.status = ScannerStatus::Scanning;
                        }
                    }
                }
                return None;
            }

            if parsed.get("version").is_some() && parsed.get("encrypted_share").is_some() {
                return Some(trimmed.to_string());
            }
        }

        self.status = ScannerStatus::Unrecognized(content.chars().take(40).collect());
        None
    }

    pub fn view(&self) -> Element<'_, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::Close)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title = text("Scan QR Code")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header =
            row![back_btn, Space::new().width(theme::space::SM), title].align_y(Alignment::Center);

        let status_color = match &self.status {
            ScannerStatus::Error(_) | ScannerStatus::Unrecognized(_) => theme::color::ERROR,
            _ => theme::color::TEXT_MUTED,
        };

        let status_text = match &self.status {
            ScannerStatus::Initializing => "Opening camera...".into(),
            ScannerStatus::Scanning => "Point camera at QR code".into(),
            ScannerStatus::CollectingFrames { got, total } => {
                format!("Scanning animated QR: frame {got} of {total}")
            }
            ScannerStatus::Unrecognized(s) => format!("Unrecognized QR: {s}..."),
            ScannerStatus::Error(e) => format!("Error: {e}"),
        };

        let status = text(status_text)
            .size(theme::size::BODY)
            .color(status_color);

        let mut content = column![header, Space::new().height(theme::space::MD), status,]
            .spacing(theme::space::XS);

        if let Some(handle) = &self.frame_handle {
            let img = iced_image::Image::new(handle.clone())
                .width(Length::Fixed(480.0))
                .height(Length::Fixed(360.0));
            content = content.push(
                container(img)
                    .center_x(Length::Fill)
                    .padding(theme::space::SM),
            );
        }

        if matches!(self.status, ScannerStatus::Error(_)) {
            content = content.push(
                button(text("Retry").size(theme::size::BODY))
                    .on_press(Message::Retry)
                    .style(theme::primary_button)
                    .padding(theme::space::MD),
            );
        }

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

pub fn start_camera(active: Arc<AtomicBool>, tx: tokio::sync::mpsc::Sender<CameraEvent>) {
    std::thread::spawn(move || {
        use nokhwa::pixel_format::RgbFormat;
        use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType, Resolution};
        use nokhwa::Camera;
        use rxing::Reader;

        let requested = RequestedFormat::new::<RgbFormat>(RequestedFormatType::Closest(
            nokhwa::utils::CameraFormat::new(
                Resolution::new(640, 480),
                nokhwa::utils::FrameFormat::MJPEG,
                30,
            ),
        ));
        let mut camera = match Camera::new(CameraIndex::Index(0), requested) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.try_send(CameraEvent::Error(format!("Camera open failed: {e}")));
                return;
            }
        };

        if let Err(e) = camera.open_stream() {
            let _ = tx.try_send(CameraEvent::Error(format!("Camera stream failed: {e}")));
            return;
        }

        let _ = tx.try_send(CameraEvent::Ready);

        let hints = rxing::DecodeHints {
            PossibleFormats: Some([rxing::BarcodeFormat::QR_CODE].into_iter().collect()),
            TryHarder: Some(true),
            ..Default::default()
        };

        let mut frame_failures: u32 = 0;
        const MAX_FRAME_FAILURES: u32 = 5;

        while active.load(Ordering::Acquire) {
            let buffer = match camera.frame() {
                Ok(b) => {
                    frame_failures = 0;
                    b
                }
                Err(e) => {
                    frame_failures += 1;
                    if frame_failures >= MAX_FRAME_FAILURES {
                        let _ = tx.try_send(CameraEvent::Error(format!(
                            "Camera failed after {frame_failures} consecutive errors: {e}"
                        )));
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
            };

            let rgb_image = match buffer.decode_image::<RgbFormat>() {
                Ok(img) => img,
                Err(_) => continue,
            };

            let (w, h) = (rgb_image.width(), rgb_image.height());

            let dynamic = ::image::DynamicImage::from(rgb_image);

            let luma = dynamic.to_luma8();
            let source =
                rxing::BufferedImageLuminanceSource::new(::image::DynamicImage::from(luma));
            let binarizer = rxing::common::HybridBinarizer::new(source);
            let mut bitmap = rxing::BinaryBitmap::new(binarizer);
            let decoded = rxing::MultiFormatReader::default()
                .decode_with_hints(&mut bitmap, &hints)
                .ok()
                .map(|r| r.getText().to_string());

            let rgba: Vec<u8> = dynamic
                .into_rgb8()
                .pixels()
                .flat_map(|p| [p[0], p[1], p[2], 255])
                .collect();

            let _ = tx.try_send(CameraEvent::Frame {
                rgba,
                width: w,
                height: h,
                decoded,
            });

            std::thread::sleep(std::time::Duration::from_millis(33));
        }

        let _ = camera.stop_stream();
    });
}

#[derive(Clone, Debug)]
pub enum CameraEvent {
    Ready,
    Frame {
        rgba: Vec<u8>,
        width: u32,
        height: u32,
        decoded: Option<String>,
    },
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_kshare1_recognized() {
        let mut s = ScannerScreen::new();
        let kshare = "kshare1qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let result = s.process_qr_content(kshare);
        assert_eq!(result, Some(kshare.to_string()));
    }

    #[test]
    fn test_single_nsec_recognized() {
        let mut s = ScannerScreen::new();
        let nsec = "nsec1qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        assert_eq!(s.process_qr_content(nsec), Some(nsec.to_string()));
    }

    #[test]
    fn test_single_ncryptsec_recognized() {
        let mut s = ScannerScreen::new();
        let ncryptsec = "ncryptsec1qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        assert_eq!(s.process_qr_content(ncryptsec), Some(ncryptsec.to_string()));
    }

    #[test]
    fn test_unrecognized_content() {
        let mut s = ScannerScreen::new();
        assert!(s.process_qr_content("https://example.com").is_none());
        assert!(matches!(s.status, ScannerStatus::Unrecognized(_)));
    }

    #[test]
    fn test_json_share_format() {
        let mut s = ScannerScreen::new();
        let json = r#"{"version":1,"encrypted_share":"deadbeef"}"#;
        assert_eq!(s.process_qr_content(json), Some(json.to_string()));
    }

    #[test]
    fn test_animated_frame_collection() {
        let mut s = ScannerScreen::new();
        assert!(s
            .process_qr_content(r#"{"f":0,"t":3,"d":"chunk0"}"#)
            .is_none());
        assert_eq!(s.collected_frames.len(), 1);
        assert_eq!(s.total_expected, Some(3));
        assert!(matches!(
            s.status,
            ScannerStatus::CollectingFrames { got: 1, total: 3 }
        ));

        assert!(s
            .process_qr_content(r#"{"f":1,"t":3,"d":"chunk1"}"#)
            .is_none());
        assert_eq!(s.collected_frames.len(), 2);
    }

    #[test]
    fn test_animated_frame_total_mismatch_resets() {
        let mut s = ScannerScreen::new();
        s.process_qr_content(r#"{"f":0,"t":3,"d":"chunk0"}"#);
        assert_eq!(s.collected_frames.len(), 1);

        s.process_qr_content(r#"{"f":0,"t":5,"d":"chunk0"}"#);
        assert_eq!(s.total_expected, Some(5));
        assert_eq!(s.collected_frames.len(), 1);
    }

    #[test]
    fn test_animated_frame_zero_total_rejected() {
        let mut s = ScannerScreen::new();
        assert!(s
            .process_qr_content(r#"{"f":0,"t":0,"d":"chunk0"}"#)
            .is_none());
        assert!(s.collected_frames.is_empty());
    }

    #[test]
    fn test_animated_frame_index_exceeds_total() {
        let mut s = ScannerScreen::new();
        assert!(s
            .process_qr_content(r#"{"f":5,"t":3,"d":"chunk0"}"#)
            .is_none());
        assert!(s.collected_frames.is_empty());
    }

    #[test]
    fn test_kshare_too_long_rejected() {
        let mut s = ScannerScreen::new();
        let long = format!("kshare1{}", "q".repeat(8200));
        assert!(s.process_qr_content(&long).is_none());
    }

    #[test]
    fn test_kshare_empty_payload_rejected() {
        let mut s = ScannerScreen::new();
        assert!(s.process_qr_content("kshare1").is_none());
    }

    #[test]
    fn test_whitespace_trimmed() {
        let mut s = ScannerScreen::new();
        let result = s.process_qr_content("  kshare1qpzry9x8gf2tvdw0s3jn54khce6mua7l  ");
        assert_eq!(
            result,
            Some("kshare1qpzry9x8gf2tvdw0s3jn54khce6mua7l".to_string())
        );
    }

    #[test]
    fn test_invalid_bech32_chars_rejected() {
        let mut s = ScannerScreen::new();
        assert!(s.process_qr_content("kshare1INVALID_CHARS!").is_none());
    }

    #[test]
    fn test_animated_max_frames_exceeded() {
        let mut s = ScannerScreen::new();
        assert!(s
            .process_qr_content(r#"{"f":0,"t":101,"d":"chunk0"}"#)
            .is_none());
    }

    #[test]
    fn test_duplicate_frame_overwrites() {
        let mut s = ScannerScreen::new();
        s.process_qr_content(r#"{"f":0,"t":3,"d":"first"}"#);
        s.process_qr_content(r#"{"f":0,"t":3,"d":"second"}"#);
        assert_eq!(s.collected_frames.len(), 1);
        assert!(s.collected_frames.get(&0).unwrap().contains("second"));
    }

    #[test]
    fn test_is_valid_bech32_payload() {
        assert!(is_valid_bech32_payload("kshare1", "kshare1qpzry9x8"));
        assert!(!is_valid_bech32_payload("kshare1", "kshare1"));
        assert!(!is_valid_bech32_payload("kshare1", "kshare1INVALID"));
        assert!(!is_valid_bech32_payload("kshare1", "wrong_prefix"));
    }
}
