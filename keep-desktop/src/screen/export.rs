// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use iced::widget::{button, column, container, qr_code, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::app::MIN_EXPORT_PASSPHRASE_LEN;
use crate::screen::shares::ShareEntry;
use crate::theme;

fn passphrase_strength(passphrase: &str) -> (&'static str, iced::Color) {
    let len = passphrase.chars().count();
    let has_upper = passphrase.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = passphrase.chars().any(|c| c.is_ascii_digit());
    let has_special = passphrase.chars().any(|c| !c.is_ascii_alphanumeric());
    let variety: usize = [has_upper, has_digit, has_special]
        .iter()
        .filter(|&&b| b)
        .count();
    let score = len + variety * 5;

    if score < 20 {
        ("Weak", theme::color::ERROR)
    } else if score < 28 {
        ("Fair", theme::color::TEXT_MUTED)
    } else if score < 38 {
        ("Good", theme::color::PRIMARY)
    } else {
        ("Strong", theme::color::SUCCESS)
    }
}

#[derive(Clone)]
pub enum Message {
    PassphraseChanged(Zeroizing<String>),
    ConfirmPassphraseChanged(Zeroizing<String>),
    GoBack,
    Generate,
    AdvanceFrame,
    CopyToClipboard(Zeroizing<String>),
    Reset,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PassphraseChanged(_) => f.write_str("PassphraseChanged(***)"),
            Self::ConfirmPassphraseChanged(_) => f.write_str("ConfirmPassphraseChanged(***)"),
            Self::GoBack => f.write_str("GoBack"),
            Self::Generate => f.write_str("Generate"),
            Self::AdvanceFrame => f.write_str("AdvanceFrame"),
            Self::CopyToClipboard(_) => f.write_str("CopyToClipboard(***)"),
            Self::Reset => f.write_str("Reset"),
        }
    }
}

pub enum Event {
    GoBack,
    Generate {
        share: ShareEntry,
        passphrase: Zeroizing<String>,
    },
    CopyToClipboard(Zeroizing<String>),
    Reset,
}

pub enum QrDisplay {
    Single(qr_code::Data),
    Animated {
        frames: Vec<qr_code::Data>,
        current: usize,
    },
}

pub struct State {
    share: ShareEntry,
    passphrase: Zeroizing<String>,
    confirm_passphrase: Zeroizing<String>,
    bech32: Option<Zeroizing<String>>,
    qr_display: Option<QrDisplay>,
    error: Option<String>,
    loading: bool,
    pub copied: bool,
}

impl State {
    pub fn new(share: ShareEntry) -> Self {
        Self {
            share,
            passphrase: Zeroizing::new(String::new()),
            confirm_passphrase: Zeroizing::new(String::new()),
            bech32: None,
            qr_display: None,
            error: None,
            loading: false,
            copied: false,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::PassphraseChanged(p) => {
                self.passphrase = p;
                self.confirm_passphrase = Zeroizing::new(String::new());
                None
            }
            Message::ConfirmPassphraseChanged(p) => {
                self.confirm_passphrase = p;
                None
            }
            Message::GoBack => Some(Event::GoBack),
            Message::Generate => {
                if self.loading || self.passphrase.chars().count() < MIN_EXPORT_PASSPHRASE_LEN {
                    return None;
                }
                if *self.passphrase != *self.confirm_passphrase {
                    self.error = Some("Passphrases do not match".into());
                    return None;
                }
                self.loading = true;
                self.error = None;
                Some(Event::Generate {
                    share: self.share.clone(),
                    passphrase: self.passphrase.clone(),
                })
            }
            Message::AdvanceFrame => {
                self.advance_frame();
                None
            }
            Message::CopyToClipboard(t) => Some(Event::CopyToClipboard(t)),
            Message::Reset => Some(Event::Reset),
        }
    }

    pub fn reset(&mut self) {
        self.passphrase = Zeroizing::new(String::new());
        self.confirm_passphrase = Zeroizing::new(String::new());
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

    pub fn export_failed(&mut self, error: String) {
        self.loading = false;
        self.error = Some(error);
    }

    fn advance_frame(&mut self) {
        if let Some(QrDisplay::Animated { frames, current }) = &mut self.qr_display {
            *current = (*current + 1) % frames.len();
        }
    }

    pub fn is_animated(&self) -> bool {
        matches!(self.qr_display, Some(QrDisplay::Animated { .. }))
    }

    pub fn view(&self) -> Element<'_, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::GoBack)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title = text(format!("Export: {}", self.share.name))
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let truncated_npub = self.share.truncated_npub();
        let info = text(format!(
            "Share #{} | {}-of-{} | {}",
            self.share.identifier, self.share.threshold, self.share.total_shares, truncated_npub,
        ))
        .size(theme::size::SMALL)
        .color(theme::color::TEXT_MUTED);

        let header =
            row![back_btn, Space::new().width(theme::space::SM), title].align_y(Alignment::Center);

        let mut content =
            column![header, info, Space::new().height(theme::space::XL)].spacing(theme::space::SM);

        if let (Some(qr_display), Some(bech32)) = (&self.qr_display, &self.bech32) {
            content = content.push(
                text("Scan with Keep Android to import this share")
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT_MUTED),
            );

            let qr_data = match qr_display {
                QrDisplay::Single(data) => data,
                QrDisplay::Animated { frames, current } => &frames[*current],
            };
            let qr_widget = qr_code::QRCode::new(qr_data).cell_size(5);
            content = content.push(
                container(qr_widget)
                    .center_x(Length::Fill)
                    .padding(theme::space::MD),
            );
            if let QrDisplay::Animated { frames, current } = qr_display {
                content = content.push(
                    text(format!("Frame {} of {}", current + 1, frames.len()))
                        .size(theme::size::SMALL)
                        .color(theme::color::TEXT_MUTED),
                );
            }

            let display = if bech32.len() > 80 {
                format!("{}...", &bech32[..80])
            } else {
                bech32.to_string()
            };
            content = content.push(
                text(display)
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
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
                    button(text(copy_label).size(theme::size::BODY))
                        .on_press_maybe(copy_msg)
                        .style(theme::primary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                    button(text("Change Passphrase").size(theme::size::BODY))
                        .on_press(Message::Reset)
                        .style(theme::secondary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                ]
                .spacing(theme::space::SM),
            );

            content = content.push(
                text("Or copy and paste into Keep Android's import screen")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_DIM),
            );

            content = content.push(Space::new().height(theme::space::SM));
            content = content.push(
                container(
                    text("Anyone with this export and passphrase can access your signing key share. Do not share it publicly.")
                        .size(theme::size::SMALL)
                        .color(theme::color::ERROR),
                )
                .style(theme::warning_style)
                .padding(theme::space::MD)
                .width(theme::size::INPUT_WIDTH),
            );
        } else {
            content = content.push(theme::label("Passphrase"));
            content = content.push(
                text("This passphrase encrypts the share for transport. You'll need it when importing on your phone.")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );

            let passphrase_ok = self.passphrase.chars().count() >= MIN_EXPORT_PASSPHRASE_LEN;
            let passphrases_match = *self.passphrase == *self.confirm_passphrase;
            let can_generate = passphrase_ok && passphrases_match;

            let passphrase_input = text_input("Encryption passphrase", &self.passphrase)
                .on_input(|s| Message::PassphraseChanged(Zeroizing::new(s)))
                .secure(true)
                .padding(theme::space::MD)
                .width(theme::size::INPUT_WIDTH);

            content = content.push(passphrase_input);

            if !self.passphrase.is_empty() {
                if !passphrase_ok {
                    content = content.push(
                        text(format!(
                            "Passphrase must be at least {MIN_EXPORT_PASSPHRASE_LEN} characters"
                        ))
                        .size(theme::size::BODY)
                        .color(theme::color::ERROR),
                    );
                } else {
                    let (strength_label, strength_color) = passphrase_strength(&self.passphrase);
                    content = content.push(
                        text(format!("Strength: {strength_label}"))
                            .size(theme::size::SMALL)
                            .color(strength_color),
                    );
                }
            }

            if passphrase_ok {
                let confirm_input = text_input("Confirm passphrase", &self.confirm_passphrase)
                    .on_input(|s| Message::ConfirmPassphraseChanged(Zeroizing::new(s)))
                    .on_submit_maybe(can_generate.then_some(Message::Generate))
                    .secure(true)
                    .padding(theme::space::MD)
                    .width(theme::size::INPUT_WIDTH);
                content = content.push(confirm_input);

                if !self.confirm_passphrase.is_empty() && !passphrases_match {
                    content = content.push(
                        text("Passphrases do not match")
                            .size(theme::size::BODY)
                            .color(theme::color::ERROR),
                    );
                }
            }

            if self.loading {
                content = content.push(theme::label("Generating..."));
            } else {
                let mut btn = button(text("Generate QR Code").size(theme::size::BODY))
                    .style(theme::primary_button)
                    .padding(theme::space::MD);
                if can_generate {
                    btn = btn.on_press(Message::Generate);
                }
                content = content.push(btn);
            }
        }

        if let Some(err) = &self.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
