// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use iced::widget::{button, column, container, qr_code, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use super::truncate_npub;
use crate::app::MIN_EXPORT_PASSPHRASE_LEN;
use crate::theme;

fn password_strength(password: &str) -> (&'static str, iced::Color) {
    let len = password.chars().count();
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
    let variety = has_upper as usize + has_digit as usize + has_special as usize;
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
    PasswordChanged(Zeroizing<String>),
    ConfirmPasswordChanged(Zeroizing<String>),
    GoBack,
    Generate,
    CopyToClipboard(Zeroizing<String>),
    Reset,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordChanged(_) => f.write_str("PasswordChanged(***)"),
            Self::ConfirmPasswordChanged(_) => f.write_str("ConfirmPasswordChanged(***)"),
            Self::GoBack => f.write_str("GoBack"),
            Self::Generate => f.write_str("Generate"),
            Self::CopyToClipboard(_) => f.write_str("CopyToClipboard(***)"),
            Self::Reset => f.write_str("Reset"),
        }
    }
}

pub enum Event {
    GoBack,
    Generate {
        pubkey_hex: String,
        password: Zeroizing<String>,
    },
    CopyToClipboard(Zeroizing<String>),
    Reset,
}

pub struct State {
    pubkey_hex: String,
    name: String,
    npub: String,
    password: Zeroizing<String>,
    confirm_password: Zeroizing<String>,
    ncryptsec: Option<Zeroizing<String>>,
    qr_data: Option<qr_code::Data>,
    error: Option<String>,
    loading: bool,
    pub copied: bool,
}

impl State {
    pub fn new(pubkey_hex: String, name: String, npub: String) -> Self {
        Self {
            pubkey_hex,
            name,
            npub,
            password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            ncryptsec: None,
            qr_data: None,
            error: None,
            loading: false,
            copied: false,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::PasswordChanged(p) => {
                self.password = p;
                self.confirm_password = Zeroizing::new(String::new());
                self.error = None;
                None
            }
            Message::ConfirmPasswordChanged(p) => {
                self.confirm_password = p;
                self.error = None;
                None
            }
            Message::GoBack => Some(Event::GoBack),
            Message::Generate => {
                if self.loading || self.password.chars().count() < MIN_EXPORT_PASSPHRASE_LEN {
                    return None;
                }
                if *self.password != *self.confirm_password {
                    self.error = Some("Passwords do not match".into());
                    return None;
                }
                self.loading = true;
                self.error = None;
                Some(Event::Generate {
                    pubkey_hex: self.pubkey_hex.clone(),
                    password: self.password.clone(),
                })
            }
            Message::CopyToClipboard(t) => Some(Event::CopyToClipboard(t)),
            Message::Reset => Some(Event::Reset),
        }
    }

    pub fn reset(&mut self) {
        self.password = Zeroizing::new(String::new());
        self.confirm_password = Zeroizing::new(String::new());
        self.ncryptsec = None;
        self.qr_data = None;
        self.error = None;
        self.loading = false;
        self.copied = false;
    }

    pub fn set_result(&mut self, ncryptsec: Zeroizing<String>) {
        self.loading = false;
        if let Ok(data) = qr_code::Data::new(&*ncryptsec) {
            self.qr_data = Some(data);
        }
        self.ncryptsec = Some(ncryptsec);
    }

    pub fn export_failed(&mut self, error: String) {
        self.loading = false;
        self.error = Some(error);
    }

    pub fn view(&self) -> Element<'_, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::GoBack)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title = text(format!("Export Encrypted: {}", self.name))
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let truncated_npub = truncate_npub(&self.npub);

        let info = text(format!("nsec | {truncated_npub}"))
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let header =
            row![back_btn, Space::new().width(theme::space::SM), title].align_y(Alignment::Center);

        let mut content =
            column![header, info, Space::new().height(theme::space::XL)].spacing(theme::space::SM);

        if let Some(ncryptsec) = &self.ncryptsec {
            content = content.push(
                text("Scan or copy this encrypted key to import in another client")
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT_MUTED),
            );

            if let Some(qr_data) = &self.qr_data {
                let qr_widget = qr_code::QRCode::new(qr_data).cell_size(5);
                content = content.push(
                    container(qr_widget)
                        .center_x(Length::Fill)
                        .padding(theme::space::MD),
                );
            }

            let display = if ncryptsec.len() > 80 {
                format!("{}...", ncryptsec.chars().take(80).collect::<String>())
            } else {
                ncryptsec.to_string()
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
            let copy_msg = (!self.copied).then(|| Message::CopyToClipboard(ncryptsec.clone()));
            content = content.push(
                row![
                    button(text(copy_label).size(theme::size::BODY))
                        .on_press_maybe(copy_msg)
                        .style(theme::primary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                    button(text("Change Password").size(theme::size::BODY))
                        .on_press(Message::Reset)
                        .style(theme::secondary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                ]
                .spacing(theme::space::SM),
            );

            content = content.push(Space::new().height(theme::space::SM));
            content = content.push(
                container(
                    text("Anyone with this string and the password can access your private key. Do not share it publicly.")
                        .size(theme::size::SMALL)
                        .color(theme::color::ERROR),
                )
                .style(theme::warning_style)
                .padding(theme::space::MD)
                .width(theme::size::INPUT_WIDTH),
            );
        } else {
            content = content.push(theme::label("Password"));
            content = content.push(
                text("This password encrypts your private key using NIP-49. You'll need it to decrypt in another client.")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );

            let password_ok = self.password.chars().count() >= MIN_EXPORT_PASSPHRASE_LEN;
            let passwords_match = *self.password == *self.confirm_password;
            let can_generate = password_ok && passwords_match;

            let password_input = text_input("Encryption password", &self.password)
                .on_input(|s| Message::PasswordChanged(Zeroizing::new(s)))
                .secure(true)
                .padding(theme::space::MD)
                .width(theme::size::INPUT_WIDTH);

            content = content.push(password_input);

            if !self.password.is_empty() {
                if !password_ok {
                    content = content.push(
                        text(format!(
                            "Password must be at least {MIN_EXPORT_PASSPHRASE_LEN} characters"
                        ))
                        .size(theme::size::BODY)
                        .color(theme::color::ERROR),
                    );
                } else {
                    let (strength_label, strength_color) = password_strength(&self.password);
                    content = content.push(
                        text(format!("Strength: {strength_label}"))
                            .size(theme::size::SMALL)
                            .color(strength_color),
                    );
                }
            }

            if password_ok {
                let confirm_input = text_input("Confirm password", &self.confirm_password)
                    .on_input(|s| Message::ConfirmPasswordChanged(Zeroizing::new(s)))
                    .on_submit_maybe(can_generate.then_some(Message::Generate))
                    .secure(true)
                    .padding(theme::space::MD)
                    .width(theme::size::INPUT_WIDTH);
                content = content.push(confirm_input);

                if !self.confirm_password.is_empty() && !passwords_match {
                    content = content.push(
                        text("Passwords do not match")
                            .size(theme::size::BODY)
                            .color(theme::color::ERROR),
                    );
                }
            }

            if self.loading {
                content = content.push(theme::label("Encrypting..."));
            } else {
                content = content.push(
                    button(text("Encrypt Key").size(theme::size::BODY))
                        .on_press_maybe(can_generate.then_some(Message::Generate))
                        .style(theme::primary_button)
                        .padding(theme::space::MD),
                );
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
