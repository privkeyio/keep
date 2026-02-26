// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};
use keep_core::keys::{bytes_to_npub, KeyRecord, KeyType};

use super::{format_timestamp, truncate_npub};
use crate::message::Message;
use crate::theme;

#[derive(Debug, Clone)]
pub struct NsecKeyEntry {
    pub name: String,
    #[allow(dead_code)]
    pub pubkey: [u8; 32],
    pub pubkey_hex: String,
    pub npub: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub sign_count: u64,
}

impl NsecKeyEntry {
    pub fn from_record(record: &KeyRecord) -> Option<Self> {
        if record.key_type != KeyType::Nostr {
            return None;
        }
        Some(Self {
            name: record.name.clone(),
            pubkey: record.pubkey,
            pubkey_hex: hex::encode(record.pubkey),
            npub: bytes_to_npub(&record.pubkey),
            created_at: record.created_at,
            last_used: record.last_used,
            sign_count: record.sign_count,
        })
    }

    fn truncated_npub(&self) -> String {
        truncate_npub(&self.npub)
    }

    fn created_display(&self) -> String {
        format_timestamp(self.created_at)
    }

    fn last_used_display(&self) -> String {
        self.last_used
            .map(format_timestamp)
            .unwrap_or_else(|| "Never".into())
    }
}

pub struct NsecKeysScreen {
    pub keys: Vec<NsecKeyEntry>,
    pub active_key_hex: Option<String>,
    pub delete_confirm: Option<String>,
    pub expanded: Option<usize>,
}

impl NsecKeysScreen {
    pub fn new(keys: Vec<NsecKeyEntry>, active_key_hex: Option<String>) -> Self {
        Self {
            keys,
            active_key_hex,
            delete_confirm: None,
            expanded: None,
        }
    }

    pub fn view_content(&self) -> Element<'_, Message> {
        let title = theme::heading("Nsec Keys");

        let mut content = column![title].spacing(theme::space::MD);

        if self.keys.is_empty() {
            let import_card = container(
                column![
                    text("Import Nsec Key")
                        .size(theme::size::HEADING)
                        .color(theme::color::TEXT),
                    text("Import a nostr secret key (nsec or ncryptsec)")
                        .size(theme::size::SMALL)
                        .color(theme::color::TEXT_MUTED),
                    Space::new().height(theme::space::SM),
                    button(
                        text("Import")
                            .width(Length::Fill)
                            .align_x(Alignment::Center),
                    )
                    .on_press(Message::GoToImport)
                    .style(theme::primary_button)
                    .padding(theme::space::MD)
                    .width(Length::Fill),
                ]
                .spacing(theme::space::SM),
            )
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::FillPortion(1));

            let empty = column![
                text("No nsec keys imported")
                    .size(theme::size::TITLE)
                    .color(theme::color::TEXT),
                text("Import a nostr secret key to get started")
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT_MUTED),
                Space::new().height(theme::space::LG),
                import_card,
            ]
            .align_x(Alignment::Center)
            .spacing(theme::space::SM);

            content = content.push(
                container(empty)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill),
            );
        } else {
            let mut list = column![].spacing(theme::space::SM);
            for (i, key) in self.keys.iter().enumerate() {
                list = list.push(self.key_card(i, key));
            }
            content = content.push(scrollable(list).height(Length::Fill));
        }

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn key_card<'a>(&self, i: usize, key: &NsecKeyEntry) -> Element<'a, Message> {
        let is_active = self.active_key_hex.as_deref() == Some(&key.pubkey_hex);

        let truncated_npub = key.truncated_npub();

        let npub_text = text(truncated_npub)
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let arrow = if self.expanded == Some(i) { "v" } else { ">" };
        let name_btn = button(
            text(format!("{arrow} {}", key.name))
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
        )
        .on_press(Message::ToggleNsecKeyDetails(i))
        .style(theme::text_button)
        .padding(0);

        let mut header_buttons = row![].spacing(theme::space::SM).align_y(Alignment::Center);

        if !is_active {
            let activate_btn = button(text("Activate").size(theme::size::SMALL))
                .on_press(Message::SwitchIdentity(key.pubkey_hex.clone()))
                .style(theme::secondary_button)
                .padding([theme::space::XS, theme::space::MD]);

            header_buttons = header_buttons.push(activate_btn);
        }

        let export_btn = button(text("Export ncryptsec").size(theme::size::SMALL))
            .on_press(Message::GoToExportNcryptsec(key.pubkey_hex.clone()))
            .style(theme::primary_button)
            .padding([theme::space::XS, theme::space::MD]);

        header_buttons = header_buttons.push(export_btn);

        let header_top = row![name_btn, Space::new().width(Length::Fill), header_buttons,]
            .align_y(Alignment::Center);

        let mut info_row = row![].spacing(theme::space::SM).align_y(Alignment::Center);

        if is_active {
            let active_badge_elem = container(
                text("ACTIVE")
                    .size(theme::size::TINY)
                    .color(iced::Color::WHITE),
            )
            .style(theme::active_badge)
            .padding([2.0, theme::space::SM]);

            info_row = info_row.push(active_badge_elem);
        }

        info_row = info_row.push(npub_text);

        let header_info = column![header_top, info_row].spacing(theme::space::XS);

        let mut card_content = column![header_info].spacing(theme::space::SM);

        if self.expanded == Some(i) {
            let npub_row = row![
                text(format!("npub: {}", key.npub))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                button(text("Copy").size(theme::size::TINY))
                    .on_press(Message::CopyNpub(key.npub.clone()))
                    .style(theme::secondary_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            let details = column![
                npub_row,
                text(format!("hex: {}", key.pubkey_hex))
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
                text(format!("Created: {}", key.created_display()))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                text(format!("Last used: {}", key.last_used_display()))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                text(format!("Signatures: {}", key.sign_count))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            ]
            .spacing(theme::space::XS);

            let actions = if self.delete_confirm.as_deref() == Some(&key.pubkey_hex) {
                row![
                    text(format!("Delete '{}'? This cannot be undone.", key.name))
                        .size(theme::size::BODY)
                        .color(theme::color::ERROR),
                    Space::new().width(Length::Fill),
                    button(text("Yes").size(theme::size::BODY))
                        .on_press(Message::ConfirmDeleteNsecKey(key.pubkey_hex.clone()))
                        .style(theme::danger_button)
                        .padding([theme::space::XS, theme::space::MD]),
                    button(text("No").size(theme::size::BODY))
                        .on_press(Message::CancelDeleteNsecKey)
                        .style(theme::secondary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                ]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center)
            } else {
                row![
                    Space::new().width(Length::Fill),
                    button(text("Delete").size(theme::size::BODY))
                        .on_press(Message::RequestDeleteNsecKey(key.pubkey_hex.clone()))
                        .style(theme::danger_button)
                        .padding([theme::space::XS, theme::space::MD]),
                ]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center)
            };

            card_content = card_content.push(details).push(actions);
        }

        let card_style = if is_active {
            theme::active_card_style
        } else {
            theme::card_style
        };

        container(card_content)
            .style(card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }
}
