// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::message::Message;
use crate::screen::layout::{self, NavItem};
use crate::theme;

#[derive(Clone, Debug, PartialEq)]
pub enum ImportMode {
    Unknown,
    FrostShare,
    Nsec,
}

pub struct ImportScreen {
    pub data: Zeroizing<String>,
    pub passphrase: Zeroizing<String>,
    pub name: String,
    pub nsec_visible: bool,
    pub npub_preview: Option<String>,
    pub error: Option<String>,
    pub loading: bool,
    pub mode: ImportMode,
}

impl ImportScreen {
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

    pub fn detect_mode(trimmed: &str) -> ImportMode {
        if trimmed.starts_with("nsec1") {
            ImportMode::Nsec
        } else if trimmed.starts_with("kshare1") || trimmed.starts_with('{') {
            ImportMode::FrostShare
        } else {
            ImportMode::Unknown
        }
    }

    pub fn view(&self, pending_requests: usize, kill_switch_active: bool) -> Element<Message> {
        let back_btn = button(text("< Back").size(theme::size::BODY))
            .on_press(Message::GoBack)
            .style(theme::text_button)
            .padding([theme::space::XS, theme::space::SM]);

        let title_text = text("Import")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let header = row![back_btn, Space::new().width(theme::space::SM), title_text]
            .align_y(Alignment::Center);

        let subtitle = text("Paste a FROST share or Nostr secret key")
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let is_nsec = self.mode == ImportMode::Nsec;

        let data_input = text_input("Paste kshare1..., JSON, or nsec1... here", &self.data)
            .on_input(|s| Message::ImportDataChanged(Zeroizing::new(s)))
            .secure(is_nsec && !self.nsec_visible)
            .padding(theme::space::MD)
            .width(Length::Fill);

        let data_row = if is_nsec {
            let toggle_label = if self.nsec_visible { "Hide" } else { "Show" };
            let toggle_btn = button(text(toggle_label).size(theme::size::SMALL))
                .on_press(Message::ImportToggleVisibility)
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
                        let truncated = format!("{}...{}", &npub[..12], &npub[npub.len() - 8..]);
                        content = content.push(
                            text(format!("Public key: {truncated}"))
                                .size(theme::size::BODY)
                                .color(theme::color::SUCCESS),
                        );
                    } else {
                        content = content.push(theme::success_text("Nostr secret key detected"));
                    }
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
                        "Expected kshare1..., JSON, or nsec1... format",
                    ));
                }
            }
        } else {
            content = content.push(
                text("Accepts kshare1... (bech32), JSON, or nsec1... format")
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
            );
        }

        match self.mode {
            ImportMode::Nsec => {
                let can_import = !self.data.trim().is_empty() && !self.name.trim().is_empty();
                let submit_msg = can_import.then_some(Message::ImportNsec);

                let name_input = text_input("Key name", &self.name)
                    .on_input(Message::ImportNameChanged)
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
                    let mut btn = button(text("Import").size(theme::size::BODY))
                        .style(theme::primary_button)
                        .padding(theme::space::MD);
                    if can_import {
                        btn = btn.on_press(Message::ImportNsec);
                    }
                    content = content.push(btn);
                }
            }
            _ => {
                let can_import = self.mode == ImportMode::FrostShare && !self.passphrase.is_empty();

                let passphrase_input = text_input("Decryption passphrase", &self.passphrase)
                    .on_input(|s| Message::ImportPassphraseChanged(Zeroizing::new(s)))
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
                    let mut btn = button(text("Import").size(theme::size::BODY))
                        .style(theme::primary_button)
                        .padding(theme::space::MD);
                    if can_import {
                        btn = btn.on_press(Message::ImportShare);
                    }
                    content = content.push(btn);
                }
            }
        }

        if let Some(err) = &self.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        let inner = container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill);

        layout::with_sidebar_kill_switch(
            NavItem::Import,
            inner.into(),
            None,
            pending_requests,
            kill_switch_active,
        )
    }
}
