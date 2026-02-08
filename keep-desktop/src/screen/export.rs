// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use iced::widget::{button, column, container, qr_code, row, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::screen::shares::ShareEntry;

pub struct ExportScreen {
    pub share: ShareEntry,
    pub passphrase: String,
    pub bech32: Option<String>,
    pub qr_data: Option<qr_code::Data>,
    pub error: Option<String>,
    pub loading: bool,
}

impl ExportScreen {
    pub fn new(share: ShareEntry) -> Self {
        Self {
            share,
            passphrase: String::new(),
            bech32: None,
            qr_data: None,
            error: None,
            loading: false,
        }
    }

    pub fn set_bech32(&mut self, bech32: String) {
        match qr_code::Data::new(&bech32) {
            Ok(data) => {
                self.qr_data = Some(data);
                self.bech32 = Some(bech32);
                self.error = None;
            }
            Err(e) => {
                self.error = Some(format!("QR generation failed: {e}"));
            }
        }
        self.loading = false;
    }

    pub fn view(&self) -> Element<Message> {
        let back_btn = button(text("< Back")).on_press(Message::GoBack).padding(8);

        let title = text(format!("Export: {}", self.share.name)).size(24);

        let info = text(format!(
            "Share #{} | {}-of-{} | {}...",
            self.share.identifier,
            self.share.threshold,
            self.share.total_shares,
            &self.share.group_pubkey_hex[..16.min(self.share.group_pubkey_hex.len())]
        ))
        .size(12)
        .color(iced::Color::from_rgb(0.5, 0.5, 0.5));

        let header = row![back_btn, Space::with_width(10), title].align_y(Alignment::Center);

        let mut content = column![header, info, Space::with_height(20)].spacing(8);

        if let (Some(qr), Some(bech32)) = (&self.qr_data, &self.bech32) {
            let qr_widget = qr_code::QRCode::new(qr).cell_size(5);

            content = content.push(container(qr_widget).center_x(Length::Fill).padding(10));

            let display = if bech32.len() > 80 {
                format!("{}...", &bech32[..80])
            } else {
                bech32.clone()
            };
            content = content.push(
                text(display)
                    .size(11)
                    .color(iced::Color::from_rgb(0.4, 0.4, 0.4)),
            );

            content = content.push(
                button(text("Copy to Clipboard"))
                    .on_press(Message::CopyToClipboard(bech32.clone()))
                    .padding(8),
            );
        } else {
            let passphrase_input = text_input("Encryption passphrase", &self.passphrase)
                .on_input(Message::ExportPassphraseChanged)
                .secure(true)
                .padding(10)
                .width(400);

            content = content.push(passphrase_input);

            if self.loading {
                content = content.push(text("Generating...").size(14));
            } else {
                let mut btn = button(text("Generate QR Code")).padding(10);
                if !self.passphrase.is_empty() {
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
