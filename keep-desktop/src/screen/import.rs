// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::theme;

#[derive(Clone, Debug, PartialEq)]
pub enum ImportMode {
    Unknown,
    FrostShare,
    Nsec,
    Ncryptsec,
}

#[derive(Clone)]
pub enum Message {
    DataChanged(Zeroizing<String>),
    PassphraseChanged(Zeroizing<String>),
    NameChanged(String),
    ToggleVisibility,
    GoBack,
    ScannerOpen,
    ImportShare,
    ImportNsec,
    ImportNcryptsec,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataChanged(_) => f.write_str("DataChanged(***)"),
            Self::PassphraseChanged(_) => f.write_str("PassphraseChanged(***)"),
            Self::NameChanged(n) => f.debug_tuple("NameChanged").field(n).finish(),
            Self::ToggleVisibility => f.write_str("ToggleVisibility"),
            Self::GoBack => f.write_str("GoBack"),
            Self::ScannerOpen => f.write_str("ScannerOpen"),
            Self::ImportShare => f.write_str("ImportShare"),
            Self::ImportNsec => f.write_str("ImportNsec"),
            Self::ImportNcryptsec => f.write_str("ImportNcryptsec"),
        }
    }
}

pub enum Event {
    GoBack,
    ScannerOpen,
    ImportShare {
        data: Zeroizing<String>,
        passphrase: Zeroizing<String>,
    },
    ImportNsec {
        data: Zeroizing<String>,
        name: String,
    },
    ImportNcryptsec {
        data: Zeroizing<String>,
        password: Zeroizing<String>,
        name: String,
    },
}

pub struct State {
    data: Zeroizing<String>,
    passphrase: Zeroizing<String>,
    name: String,
    nsec_visible: bool,
    npub_preview: Option<String>,
    error: Option<String>,
    loading: bool,
    mode: ImportMode,
}

impl State {
    pub fn new() -> Self {
        Self {
            data: Zeroizing::new(String::new()),
            passphrase: Zeroizing::new(String::new()),
            name: "Desktop Key".to_string(),
            nsec_visible: false,
            npub_preview: None,
            error: None,
            loading: false,
            mode: ImportMode::Unknown,
        }
    }

    pub fn with_data(result: String) -> Self {
        let trimmed = result.trim();
        let mode = Self::detect_mode(trimmed);
        let npub_preview = if mode == ImportMode::Nsec {
            keep_core::keys::NostrKeypair::from_nsec(trimmed)
                .ok()
                .map(|kp| kp.to_npub())
        } else {
            None
        };
        Self {
            data: Zeroizing::new(result),
            passphrase: Zeroizing::new(String::new()),
            name: "Desktop Key".to_string(),
            nsec_visible: false,
            npub_preview,
            error: None,
            loading: false,
            mode,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::DataChanged(d) => {
                let trimmed = d.trim();
                let new_mode = Self::detect_mode(trimmed);
                if new_mode != self.mode {
                    self.passphrase = Zeroizing::new(String::new());
                }
                self.mode = new_mode;
                self.npub_preview = if self.mode == ImportMode::Nsec {
                    keep_core::keys::NostrKeypair::from_nsec(trimmed)
                        .ok()
                        .map(|kp| kp.to_npub())
                } else {
                    None
                };
                self.data = d;
                None
            }
            Message::PassphraseChanged(p) => {
                self.passphrase = p;
                None
            }
            Message::NameChanged(n) => {
                if n.chars().count() <= 64 {
                    self.name = n;
                }
                None
            }
            Message::ToggleVisibility => {
                self.nsec_visible = !self.nsec_visible;
                None
            }
            Message::GoBack => Some(Event::GoBack),
            Message::ScannerOpen => Some(Event::ScannerOpen),
            Message::ImportShare => {
                if self.loading || self.data.is_empty() || self.passphrase.is_empty() {
                    return None;
                }
                self.loading = true;
                self.error = None;
                Some(Event::ImportShare {
                    data: self.data.clone(),
                    passphrase: self.passphrase.clone(),
                })
            }
            Message::ImportNsec => {
                if self.loading || self.data.is_empty() || self.name.trim().is_empty() {
                    return None;
                }
                self.loading = true;
                self.error = None;
                Some(Event::ImportNsec {
                    data: self.data.clone(),
                    name: self.name.clone(),
                })
            }
            Message::ImportNcryptsec => {
                if self.loading
                    || self.data.is_empty()
                    || self.passphrase.is_empty()
                    || self.name.trim().is_empty()
                {
                    return None;
                }
                self.loading = true;
                self.error = None;
                Some(Event::ImportNcryptsec {
                    data: self.data.clone(),
                    password: self.passphrase.clone(),
                    name: self.name.clone(),
                })
            }
        }
    }

    pub fn import_failed(&mut self, error: String) {
        self.loading = false;
        self.error = Some(error);
    }

    pub fn detect_mode(trimmed: &str) -> ImportMode {
        if trimmed.starts_with("ncryptsec1") {
            ImportMode::Ncryptsec
        } else if trimmed.starts_with("nsec1") {
            ImportMode::Nsec
        } else if trimmed.starts_with("kshare1") || trimmed.starts_with('{') {
            ImportMode::FrostShare
        } else {
            ImportMode::Unknown
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::GoBack)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Import")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text("Paste a FROST share, Nostr secret key, or encrypted key")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let scan_btn = button(text("Scan QR Code").size(theme::size::BODY))
            .on_press(Message::ScannerOpen)
            .style(theme::secondary_button)
            .padding([theme::space::XS, theme::space::MD]);

        let is_secret = self.mode == ImportMode::Nsec;

        let data_input = text_input(
            "Paste kshare1..., nsec1..., or ncryptsec1... here",
            &self.data,
        )
        .on_input(|s| Message::DataChanged(Zeroizing::new(s)))
        .secure(is_secret && !self.nsec_visible)
        .padding(theme::space::MD)
        .width(Length::Fill);

        let data_row = if is_secret {
            let toggle_label = if self.nsec_visible { "Hide" } else { "Show" };
            let toggle_btn = button(text(toggle_label).size(theme::size::SMALL))
                .on_press(Message::ToggleVisibility)
                .style(theme::text_button)
                .padding([theme::space::XS, theme::space::SM]);
            row![data_input, toggle_btn]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center)
        } else {
            row![data_input].align_y(Alignment::Center)
        };

        let mut content = column![
            header,
            subtitle,
            scan_btn,
            Space::new().height(theme::space::LG),
            theme::label("Data"),
            data_row,
        ]
        .spacing(theme::space::XS);

        let trimmed_data = self.data.trim();
        if !trimmed_data.is_empty() {
            match self.mode {
                ImportMode::Nsec => {
                    if let Some(npub) = &self.npub_preview {
                        let truncated = if npub.is_ascii() && npub.len() > 20 {
                            format!("{}...{}", &npub[..12], &npub[npub.len() - 6..])
                        } else {
                            npub.clone()
                        };
                        content = content.push(
                            text(format!("Public key: {truncated}"))
                                .size(theme::size::BODY)
                                .color(theme::color::SUCCESS),
                        );
                    } else {
                        content = content.push(theme::success_text("Nostr secret key detected"));
                    }
                }
                ImportMode::Ncryptsec => {
                    content = content.push(theme::success_text(
                        "Encrypted secret key detected (NIP-49)",
                    ));
                }
                ImportMode::FrostShare => {
                    if trimmed_data.starts_with("kshare1") {
                        content =
                            content.push(theme::success_text("Encrypted bech32 share detected"));
                    } else {
                        content = content.push(theme::success_text("JSON format detected"));
                    }
                }
                ImportMode::Unknown => {
                    content = content.push(theme::error_text(
                        "Expected kshare1..., nsec1..., or ncryptsec1... format",
                    ));
                }
            }
        } else {
            content = content.push(
                text("Accepts kshare1..., nsec1..., or ncryptsec1... format")
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
            );
        }

        match self.mode {
            ImportMode::Nsec => {
                let can_import = !trimmed_data.is_empty() && !self.name.trim().is_empty();
                let submit_msg = can_import.then_some(Message::ImportNsec);

                let name_input = text_input("Key name", &self.name)
                    .on_input(Message::NameChanged)
                    .on_submit_maybe(submit_msg)
                    .padding(theme::space::MD)
                    .width(theme::size::INPUT_WIDTH);

                content = content
                    .push(Space::new().height(theme::space::MD))
                    .push(theme::label("Key Name"))
                    .push(
                        text("A label for this key in your vault")
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_MUTED),
                    )
                    .push(name_input)
                    .push(Space::new().height(theme::space::MD));

                if self.loading {
                    content = content.push(theme::label("Importing..."));
                } else {
                    content = content.push(
                        button(text("Import").size(theme::size::BODY))
                            .on_press_maybe(can_import.then_some(Message::ImportNsec))
                            .style(theme::primary_button)
                            .padding(theme::space::MD),
                    );
                }
            }
            ImportMode::Ncryptsec => {
                let has_password = !self.passphrase.is_empty();
                let has_name = !self.name.trim().is_empty();
                let can_import = !trimmed_data.is_empty() && has_password && has_name;

                let password_input = text_input("Decryption password", &self.passphrase)
                    .on_input(|s| Message::PassphraseChanged(Zeroizing::new(s)))
                    .on_submit_maybe(can_import.then_some(Message::ImportNcryptsec))
                    .secure(true)
                    .padding(theme::space::MD)
                    .width(theme::size::INPUT_WIDTH);

                content = content
                    .push(Space::new().height(theme::space::MD))
                    .push(theme::label("Password"))
                    .push(
                        text("Enter the password used to encrypt this key")
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_MUTED),
                    )
                    .push(password_input);

                let name_input = text_input("Key name", &self.name)
                    .on_input(Message::NameChanged)
                    .on_submit_maybe(can_import.then_some(Message::ImportNcryptsec))
                    .padding(theme::space::MD)
                    .width(theme::size::INPUT_WIDTH);

                content = content
                    .push(Space::new().height(theme::space::MD))
                    .push(theme::label("Key Name"))
                    .push(
                        text("A label for this key in your vault")
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_MUTED),
                    )
                    .push(name_input)
                    .push(Space::new().height(theme::space::MD));

                if self.loading {
                    content = content.push(theme::label("Decrypting..."));
                } else {
                    content = content.push(
                        button(text("Decrypt & Import").size(theme::size::BODY))
                            .on_press_maybe(can_import.then_some(Message::ImportNcryptsec))
                            .style(theme::primary_button)
                            .padding(theme::space::MD),
                    );
                }
            }
            _ => {
                let can_import = self.mode == ImportMode::FrostShare && !self.passphrase.is_empty();

                let passphrase_input = text_input("Decryption passphrase", &self.passphrase)
                    .on_input(|s| Message::PassphraseChanged(Zeroizing::new(s)))
                    .on_submit_maybe(can_import.then_some(Message::ImportShare))
                    .secure(true)
                    .padding(theme::space::MD)
                    .width(theme::size::INPUT_WIDTH);

                content = content
                    .push(Space::new().height(theme::space::MD))
                    .push(theme::label("Passphrase"))
                    .push(
                        text("Enter the passphrase used when exporting the share")
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_MUTED),
                    )
                    .push(passphrase_input)
                    .push(Space::new().height(theme::space::MD));

                if self.loading {
                    content = content.push(theme::label("Importing..."));
                } else {
                    content = content.push(
                        button(text("Import").size(theme::size::BODY))
                            .on_press_maybe(can_import.then_some(Message::ImportShare))
                            .style(theme::primary_button)
                            .padding(theme::space::MD),
                    );
                }
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
