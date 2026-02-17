// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use iced::widget::{button, column, container, image as iced_image, row, text, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::theme;

pub struct ScannerScreen {
    pub frame_rgba: Option<Vec<u8>>,
    pub frame_width: u32,
    pub frame_height: u32,
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
    Error(String),
}

impl ScannerScreen {
    pub fn new() -> Self {
        Self {
            frame_rgba: None,
            frame_width: 0,
            frame_height: 0,
            collected_frames: HashMap::new(),
            total_expected: None,
            status: ScannerStatus::Initializing,
            camera_active: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn stop_camera(&self) {
        self.camera_active.store(false, Ordering::Relaxed);
    }

    pub fn process_qr_content(&mut self, content: &str) -> Option<String> {
        let trimmed = content.trim();

        if trimmed.starts_with("kshare1") || trimmed.starts_with("nsec1") {
            return Some(trimmed.to_string());
        }

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let (Some(f), Some(t), Some(_d)) = (
                parsed.get("f").and_then(|v| v.as_u64()),
                parsed.get("t").and_then(|v| v.as_u64()),
                parsed.get("d").and_then(|v| v.as_str()),
            ) {
                let idx = f as usize;
                let total = t as usize;
                if idx >= total {
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
                    let Some(frames) = frames else {
                        return None;
                    };
                    match keep_core::frost::ShareExport::from_animated_frames(&frames) {
                        Ok(export) => {
                            return export.to_bech32().or_else(|_| export.to_json()).ok();
                        }
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

        None
    }

    pub fn view_content(&self) -> Element<Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::ScannerClose)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title = text("Scan QR Code")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header =
            row![back_btn, Space::new().width(theme::space::SM), title].align_y(Alignment::Center);

        let status_color = match &self.status {
            ScannerStatus::Error(_) => theme::color::ERROR,
            _ => theme::color::TEXT_MUTED,
        };

        let status_text = match &self.status {
            ScannerStatus::Initializing => "Opening camera...".into(),
            ScannerStatus::Scanning => "Point camera at QR code".into(),
            ScannerStatus::CollectingFrames { got, total } => {
                format!("Scanning animated QR: frame {got} of {total}")
            }
            ScannerStatus::Error(e) => format!("Error: {e}"),
        };

        let status = text(status_text)
            .size(theme::size::BODY)
            .color(status_color);

        let mut content = column![header, Space::new().height(theme::space::MD), status,]
            .spacing(theme::space::XS);

        if let Some(rgba) = &self.frame_rgba {
            if self.frame_width > 0 && self.frame_height > 0 {
                let handle = iced_image::Handle::from_rgba(
                    self.frame_width,
                    self.frame_height,
                    rgba.clone(),
                );
                let img = iced_image::Image::new(handle)
                    .width(Length::Fixed(480.0))
                    .height(Length::Fixed(360.0));
                content = content.push(
                    container(img)
                        .center_x(Length::Fill)
                        .padding(theme::space::SM),
                );
            }
        }

        if matches!(self.status, ScannerStatus::Error(_)) {
            content = content.push(
                button(text("Retry").size(theme::size::BODY))
                    .on_press(Message::ScannerRetry)
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

pub fn start_camera(active: Arc<AtomicBool>, tx: tokio::sync::mpsc::UnboundedSender<CameraEvent>) {
    std::thread::spawn(move || {
        use nokhwa::pixel_format::RgbFormat;
        use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
        use nokhwa::Camera;

        let requested =
            RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
        let mut camera = match Camera::new(CameraIndex::Index(0), requested) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(CameraEvent::Error(format!("Camera open failed: {e}")));
                return;
            }
        };

        if let Err(e) = camera.open_stream() {
            let _ = tx.send(CameraEvent::Error(format!("Camera stream failed: {e}")));
            return;
        }

        let _ = tx.send(CameraEvent::Ready);

        while active.load(Ordering::Relaxed) {
            let buffer = match camera.frame() {
                Ok(b) => b,
                Err(_) => {
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
            let gray = dynamic.to_luma8();
            let mut prepared = rqrr::PreparedImage::prepare(gray);
            let grids = prepared.detect_grids();
            let decoded = grids
                .into_iter()
                .find_map(|g| g.decode().ok().map(|(_, content)| content));

            let rgba: Vec<u8> = dynamic
                .into_rgb8()
                .pixels()
                .flat_map(|p| [p[0], p[1], p[2], 255])
                .collect();

            let _ = tx.send(CameraEvent::Frame {
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
