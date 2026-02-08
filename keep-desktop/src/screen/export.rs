// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, qr_code, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::message::Message;
use crate::screen::shares::ShareEntry;

pub enum QrDisplay {
    Single(qr_code::Data),
    Animated {
        frames: Vec<qr_code::Data>,
        current: usize,
    },
}

pub struct ExportScreen {
    pub share: ShareEntry,
    pub passphrase: Zeroizing<String>,
    pub bech32: Option<Zeroizing<String>>,
    pub qr_display: Option<QrDisplay>,
    pub error: Option<String>,
    pub loading: bool,
    pub copied: bool,
}

impl ExportScreen {
    pub fn new(share: ShareEntry) -> Self {
        Self {
            share,
            passphrase: Zeroizing::new(String::new()),
            bech32: None,
            qr_display: None,
            error: None,
            loading: false,
            copied: false,
        }
    }

    pub fn reset(&mut self) {
        self.passphrase = Zeroizing::new(String::new());
        self.bech32 = None;
        self.qr_display = None;
        self.error = None;
        self.loading = false;
        self.copied = false;
    }

    pub fn set_export(&mut self, bech32: Zeroizing<String>, frames: Vec<Zeroizing<String>>) {
        self.loading = false;

        if let Ok(data) = qr_code::Data::new(&*bech32) {
            self.bech32 = Some(bech32);
            self.qr_display = Some(QrDisplay::Single(data));
            return;
        }

        let mut qr_frames = Vec::with_capacity(frames.len());
        for (i, f) in frames.iter().enumerate() {
            match qr_code::Data::new(&**f) {
                Ok(data) => qr_frames.push(data),
                Err(_) => {
                    self.error = Some(format!("QR generation failed on frame {}", i + 1));
                    return;
                }
            }
        }

        if qr_frames.is_empty() {
            self.error = Some("QR generation failed: no frames produced".into());
        } else {
            self.bech32 = Some(bech32);
            self.qr_display = Some(QrDisplay::Animated {
                frames: qr_frames,
                current: 0,
            });
        }
    }

    pub fn advance_frame(&mut self) {
        if let Some(QrDisplay::Animated { frames, current }) = &mut self.qr_display {
            *current = (*current + 1) % frames.len();
        }
    }

    pub fn is_animated(&self) -> bool {
        matches!(self.qr_display, Some(QrDisplay::Animated { .. }))
    }

    pub fn view(&self) -> Element<Message> {
        let back_btn = button(text("< Back")).on_press(Message::GoBack).padding(8);

        let title = text(format!("Export: {}", self.share.name)).size(24);

        let info = text(format!(
            "Share #{} | {}-of-{} | {}...",
            self.share.identifier,
            self.share.threshold,
            self.share.total_shares,
            &self.share.group_pubkey_hex[..16]
        ))
        .size(12)
        .color(iced::Color::from_rgb(0.6, 0.6, 0.6));

        let header = row![back_btn, Space::new().width(10), title].align_y(Alignment::Center);

        let mut content = column![header, info, Space::new().height(20)].spacing(8);

        if let (Some(qr_display), Some(bech32)) = (&self.qr_display, &self.bech32) {
            match qr_display {
                QrDisplay::Single(data) => {
                    let qr_widget = qr_code::QRCode::new(data).cell_size(5);
                    content = content.push(container(qr_widget).center_x(Length::Fill).padding(10));
                }
                QrDisplay::Animated { frames, current } => {
                    let qr_widget = qr_code::QRCode::new(&frames[*current]).cell_size(5);
                    content = content.push(container(qr_widget).center_x(Length::Fill).padding(10));
                    content = content.push(
                        text(format!("Frame {} of {}", current + 1, frames.len()))
                            .size(12)
                            .color(iced::Color::from_rgb(0.6, 0.6, 0.6)),
                    );
                }
            }

            let display = if bech32.len() > 80 {
                format!("{}...", &bech32[..80])
            } else {
                bech32.to_string()
            };
            content = content.push(
                text(display)
                    .size(11)
                    .color(iced::Color::from_rgb(0.55, 0.55, 0.55)),
            );

            let copy_label = if self.copied {
                "Copied!"
            } else {
                "Copy to Clipboard"
            };
            let copy_msg = if self.copied {
                None
            } else {
                Some(Message::CopyToClipboard(bech32.clone()))
            };
            content = content.push(
                row![
                    button(text(copy_label)).on_press_maybe(copy_msg).padding(8),
                    button(text("Change Passphrase"))
                        .on_press(Message::ResetExport)
                        .padding(8),
                ]
                .spacing(8),
            );
        } else {
            let passphrase_input = text_input("Encryption passphrase", &self.passphrase)
                .on_input(|s| Message::ExportPassphraseChanged(Zeroizing::new(s)))
                .on_submit(Message::GenerateExport)
                .secure(true)
                .padding(10)
                .width(400);

            content = content.push(passphrase_input);

            let passphrase_ok = self.passphrase.len() >= 8;
            if !self.passphrase.is_empty() && !passphrase_ok {
                content = content.push(
                    text("Passphrase must be at least 8 characters")
                        .size(12)
                        .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
                );
            }

            if self.loading {
                content = content.push(text("Generating...").size(14));
            } else {
                let mut btn = button(text("Generate QR Code")).padding(10);
                if passphrase_ok {
                    btn = btn.on_press(Message::GenerateExport);
                }
                content = content.push(btn);
            }
        }

        if let Some(err) = &self.error {
            content = content.push(
                text(err.as_str())
                    .size(14)
                    .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
            );
        }

        container(content)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
