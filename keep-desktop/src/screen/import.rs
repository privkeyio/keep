// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use keep_core::frost::ShareExport;
use keep_core::keys::bytes_to_npub;
use zeroize::Zeroizing;

use super::truncate_npub;
use crate::theme;

fn detail_row<'a>(label: &str, value: &str) -> Element<'a, Message> {
    row![
        text(label.to_string())
            .size(theme::size::BODY)
            .color(theme::color::TEXT_MUTED)
            .width(120.0),
        text(value.to_string())
            .size(theme::size::BODY)
            .color(theme::color::TEXT),
    ]
    .spacing(theme::space::SM)
    .align_y(Alignment::Center)
    .into()
}

#[derive(Clone, Debug, PartialEq)]
pub enum ImportMode {
    Unknown,
    FrostShare,
    Nsec,
    Ncryptsec,
}

#[derive(Clone, Debug, PartialEq)]
enum FrostStep {
    Input,
    Verify,
    Decrypt,
}

#[derive(Clone, Debug)]
struct ParsedShareInfo {
    group_npub_truncated: String,
    group_pubkey_hex: String,
    identifier: u16,
    threshold: u16,
    total: u16,
}

#[derive(Clone, Debug)]
struct GroupMatch {
    name: String,
    share_count: usize,
    has_same_id: bool,
}

#[derive(Clone, Debug)]
pub struct ExistingShareSummary {
    pub group_pubkey_hex: String,
    pub name: String,
    pub identifier: u16,
}

#[derive(Clone)]
pub enum Message {
    DataChanged(Zeroizing<String>),
    PassphraseChanged(Zeroizing<String>),
    NameChanged(String),
    ToggleVisibility,
    GoBack,
    ScannerOpen,
    ContinueToVerify,
    ContinueToDecrypt,
    BackStep,
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
            Self::ContinueToVerify => f.write_str("ContinueToVerify"),
            Self::ContinueToDecrypt => f.write_str("ContinueToDecrypt"),
            Self::BackStep => f.write_str("BackStep"),
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
    frost_step: FrostStep,
    parsed_info: Option<ParsedShareInfo>,
    group_match: Option<GroupMatch>,
    existing_shares: Vec<ExistingShareSummary>,
}

impl State {
    pub fn new(existing_shares: Vec<ExistingShareSummary>) -> Self {
        Self {
            data: Zeroizing::new(String::new()),
            passphrase: Zeroizing::new(String::new()),
            name: "Desktop Key".to_string(),
            nsec_visible: false,
            npub_preview: None,
            error: None,
            loading: false,
            mode: ImportMode::Unknown,
            frost_step: FrostStep::Input,
            parsed_info: None,
            group_match: None,
            existing_shares,
        }
    }

    pub fn with_data(result: String, existing_shares: Vec<ExistingShareSummary>) -> Self {
        let trimmed = result.trim();
        let mode = Self::detect_mode(trimmed);
        let npub_preview = if mode == ImportMode::Nsec {
            keep_core::keys::NostrKeypair::from_nsec(trimmed)
                .ok()
                .map(|kp| kp.to_npub())
        } else {
            None
        };
        let (parsed_info, group_match) = if mode == ImportMode::FrostShare {
            let info = Self::try_parse_share(trimmed);
            let gm = info
                .as_ref()
                .and_then(|i| Self::find_group_match_static(&existing_shares, i));
            (info, gm)
        } else {
            (None, None)
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
            frost_step: FrostStep::Input,
            parsed_info,
            group_match,
            existing_shares,
        }
    }

    fn try_parse_share(data: &str) -> Option<ParsedShareInfo> {
        let export = ShareExport::parse(data).ok()?;
        let pubkey_bytes = hex::decode(&export.group_pubkey).ok()?;
        if pubkey_bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pubkey_bytes);
        let npub = bytes_to_npub(&arr);
        Some(ParsedShareInfo {
            group_npub_truncated: truncate_npub(&npub),
            group_pubkey_hex: export.group_pubkey,
            identifier: export.identifier,
            threshold: export.threshold,
            total: export.total,
        })
    }

    fn find_group_match(&self, info: &ParsedShareInfo) -> Option<GroupMatch> {
        Self::find_group_match_static(&self.existing_shares, info)
    }

    fn find_group_match_static(
        existing: &[ExistingShareSummary],
        info: &ParsedShareInfo,
    ) -> Option<GroupMatch> {
        let matches: Vec<_> = existing
            .iter()
            .filter(|s| s.group_pubkey_hex == info.group_pubkey_hex)
            .collect();
        if matches.is_empty() {
            return None;
        }
        Some(GroupMatch {
            name: matches[0].name.clone(),
            share_count: matches.len(),
            has_same_id: matches.iter().any(|s| s.identifier == info.identifier),
        })
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::DataChanged(d) => {
                let trimmed = d.trim();
                let new_mode = Self::detect_mode(trimmed);
                if new_mode != self.mode {
                    self.passphrase = Zeroizing::new(String::new());
                    self.frost_step = FrostStep::Input;
                }
                self.mode = new_mode.clone();
                self.npub_preview = if self.mode == ImportMode::Nsec {
                    keep_core::keys::NostrKeypair::from_nsec(trimmed)
                        .ok()
                        .map(|kp| kp.to_npub())
                } else {
                    None
                };
                if new_mode == ImportMode::FrostShare {
                    self.parsed_info = Self::try_parse_share(trimmed);
                    self.group_match = self
                        .parsed_info
                        .as_ref()
                        .and_then(|i| self.find_group_match(i));
                } else {
                    self.parsed_info = None;
                    self.group_match = None;
                }
                self.error = None;
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
            Message::ContinueToVerify => {
                if self.parsed_info.is_some() {
                    self.error = None;
                    self.frost_step = FrostStep::Verify;
                }
                None
            }
            Message::ContinueToDecrypt => {
                self.error = None;
                self.frost_step = FrostStep::Decrypt;
                None
            }
            Message::BackStep => {
                match self.frost_step {
                    FrostStep::Verify => self.frost_step = FrostStep::Input,
                    FrostStep::Decrypt => {
                        self.passphrase = Zeroizing::new(String::new());
                        self.frost_step = FrostStep::Verify;
                    }
                    FrostStep::Input => {}
                }
                self.error = None;
                None
            }
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
        if self.mode == ImportMode::FrostShare && self.frost_step != FrostStep::Input {
            return match self.frost_step {
                FrostStep::Verify => self.view_frost_verify(),
                FrostStep::Decrypt => self.view_frost_decrypt(),
                FrostStep::Input => unreachable!(),
            };
        }
        self.view_input()
    }

    fn view_input(&self) -> Element<'_, Message> {
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
                    if self.parsed_info.is_some() {
                        content =
                            content.push(theme::success_text("FROST share detected and parsed"));
                    } else {
                        content = content.push(theme::error_text(
                            "Could not parse share data. Check the format.",
                        ));
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
            ImportMode::FrostShare => {
                content = content.push(Space::new().height(theme::space::MD));
                content = content.push(
                    button(text("Continue").size(theme::size::BODY))
                        .on_press_maybe(self.parsed_info.as_ref().map(|_| Message::ContinueToVerify))
                        .style(theme::primary_button)
                        .padding(theme::space::MD),
                );
            }
            ImportMode::Unknown => {
                content = content
                    .push(Space::new().height(theme::space::MD))
                    .push(theme::label("Passphrase"))
                    .push(
                        text("Enter the passphrase used when exporting the share")
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_MUTED),
                    )
                    .push(
                        text_input("Decryption passphrase", &self.passphrase)
                            .on_input(|s| Message::PassphraseChanged(Zeroizing::new(s)))
                            .secure(true)
                            .padding(theme::space::MD)
                            .width(theme::size::INPUT_WIDTH),
                    )
                    .push(Space::new().height(theme::space::MD))
                    .push(
                        button(text("Import").size(theme::size::BODY))
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

    fn view_frost_verify(&self) -> Element<'_, Message> {
        let info = match &self.parsed_info {
            Some(i) => i,
            None => return self.view_input(),
        };

        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::BackStep)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Verify Share")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text("Confirm the share details before importing")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let card_content = column![
            text("Share Details")
                .size(theme::size::BODY)
                .color(theme::color::TEXT),
            Space::new().height(theme::space::SM),
            detail_row("Group", &info.group_npub_truncated),
            detail_row(
                "Share",
                &format!("{} of {}", info.identifier, info.total),
            ),
            detail_row(
                "Threshold",
                &format!("{} of {} required to sign", info.threshold, info.total),
            ),
        ]
        .spacing(theme::space::XS);

        let card = container(card_content)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill);

        let mut content = column![
            header,
            subtitle,
            Space::new().height(theme::space::MD),
            card,
            Space::new().height(theme::space::MD),
        ]
        .spacing(theme::space::XS);

        if let Some(gm) = &self.group_match {
            let match_text = format!(
                "Matches keyset '{}' ({} existing share{})",
                gm.name,
                gm.share_count,
                if gm.share_count == 1 { "" } else { "s" }
            );
            content = content.push(
                text(match_text)
                    .size(theme::size::BODY)
                    .color(theme::color::SUCCESS),
            );

            if gm.has_same_id {
                let warn = container(
                    text("A share with this identifier already exists in your vault. Importing will replace it.")
                        .size(theme::size::SMALL),
                )
                .style(theme::warning_style)
                .padding(theme::space::MD)
                .width(Length::Fill);
                content = content.push(warn);
            }
        } else {
            content = content.push(
                text("New keyset \u{2014} not yet in your vault")
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT_MUTED),
            );
        }

        content = content.push(Space::new().height(theme::space::MD));
        content = content.push(
            button(text("Continue").size(theme::size::BODY))
                .on_press(Message::ContinueToDecrypt)
                .style(theme::primary_button)
                .padding(theme::space::MD),
        );

        if let Some(err) = &self.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_frost_decrypt(&self) -> Element<'_, Message> {
        let info = match &self.parsed_info {
            Some(i) => i,
            None => return self.view_input(),
        };

        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::BackStep)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Decrypt Share")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let summary = text(format!(
            "Importing share {} for group {}",
            info.identifier, info.group_npub_truncated
        ))
        .size(theme::size::SMALL)
        .color(theme::color::TEXT_MUTED);

        let can_import = !self.passphrase.is_empty();

        let passphrase_input = text_input("Decryption passphrase", &self.passphrase)
            .on_input(|s| Message::PassphraseChanged(Zeroizing::new(s)))
            .on_submit_maybe(can_import.then_some(Message::ImportShare))
            .secure(true)
            .padding(theme::space::MD)
            .width(theme::size::INPUT_WIDTH);

        let mut content = column![
            header,
            summary,
            Space::new().height(theme::space::LG),
            theme::label("Passphrase"),
            text("Enter the passphrase used when exporting the share")
                .size(theme::size::SMALL)
                .color(theme::color::TEXT_MUTED),
            passphrase_input,
            Space::new().height(theme::space::MD),
        ]
        .spacing(theme::space::XS);

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
