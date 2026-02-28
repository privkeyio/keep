// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};
use keep_core::keys::bytes_to_npub;

use super::{format_timestamp, truncate_npub};
use crate::message::ShareIdentity;
use crate::theme;

#[derive(Debug, Clone)]
pub struct ShareEntry {
    pub name: String,
    pub identifier: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub group_pubkey: [u8; 32],
    pub group_pubkey_hex: String,
    pub npub: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub sign_count: u64,
}

impl ShareEntry {
    pub fn from_stored(stored: &keep_core::frost::StoredShare) -> Self {
        let m = &stored.metadata;
        Self {
            name: m.name.clone(),
            identifier: m.identifier,
            threshold: m.threshold,
            total_shares: m.total_shares,
            group_pubkey: m.group_pubkey,
            group_pubkey_hex: hex::encode(m.group_pubkey),
            npub: bytes_to_npub(&m.group_pubkey),
            created_at: m.created_at,
            last_used: m.last_used,
            sign_count: m.sign_count,
        }
    }

    fn created_display(&self) -> String {
        format_timestamp(self.created_at)
    }

    pub fn truncated_npub(&self) -> String {
        truncate_npub(&self.npub)
    }

    fn last_used_display(&self) -> String {
        self.last_used
            .map(format_timestamp)
            .unwrap_or_else(|| "Never".into())
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    ToggleDetails(usize),
    GoToExport(usize),
    GoToCreate,
    GoToImport,
    ActivateShare(String),
    CopyNpub(String),
    RequestDelete(ShareIdentity),
    ConfirmDelete(ShareIdentity),
    CancelDelete,
}

pub enum Event {
    GoToExport(usize),
    GoToCreate,
    GoToImport,
    ActivateShare(String),
    CopyNpub(String),
    ConfirmDelete(ShareIdentity),
}

pub struct State {
    shares: Vec<ShareEntry>,
    active_share_hex: Option<String>,
    delete_confirm: Option<ShareIdentity>,
    expanded: Option<usize>,
}

impl State {
    pub fn new(shares: Vec<ShareEntry>, active_share_hex: Option<String>) -> Self {
        Self {
            shares,
            active_share_hex,
            delete_confirm: None,
            expanded: None,
        }
    }

    pub fn refresh(&mut self, shares: Vec<ShareEntry>, active_share_hex: Option<String>) {
        self.shares = shares;
        self.active_share_hex = active_share_hex;
        self.delete_confirm = None;
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::ToggleDetails(i) => {
                self.expanded = if self.expanded == Some(i) {
                    None
                } else {
                    Some(i)
                };
                None
            }
            Message::GoToExport(i) => Some(Event::GoToExport(i)),
            Message::GoToCreate => Some(Event::GoToCreate),
            Message::GoToImport => Some(Event::GoToImport),
            Message::ActivateShare(hex) => Some(Event::ActivateShare(hex)),
            Message::CopyNpub(npub) => Some(Event::CopyNpub(npub)),
            Message::RequestDelete(id) => {
                self.delete_confirm = Some(id);
                None
            }
            Message::ConfirmDelete(id) => Some(Event::ConfirmDelete(id)),
            Message::CancelDelete => {
                self.delete_confirm = None;
                None
            }
        }
    }

    pub fn clear_delete_confirm(&mut self) {
        self.delete_confirm = None;
    }

    pub fn view(&self) -> Element<'_, Message> {
        let title = theme::heading("FROST Shares");

        let mut content = column![title].spacing(theme::space::MD);

        if self.shares.is_empty() {
            let create_card = container(
                column![
                    text("Create Keyset")
                        .size(theme::size::HEADING)
                        .color(theme::color::TEXT),
                    text("Generate a new set of threshold signing shares")
                        .size(theme::size::SMALL)
                        .color(theme::color::TEXT_MUTED),
                    Space::new().height(theme::space::SM),
                    button(
                        text("Create")
                            .width(Length::Fill)
                            .align_x(Alignment::Center),
                    )
                    .on_press(Message::GoToCreate)
                    .style(theme::primary_button)
                    .padding(theme::space::MD)
                    .width(Length::Fill),
                ]
                .spacing(theme::space::SM),
            )
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::FillPortion(1));

            let import_card = container(
                column![
                    text("Import Share")
                        .size(theme::size::HEADING)
                        .color(theme::color::TEXT),
                    text("Scan or paste a share exported from another Keep device")
                        .size(theme::size::SMALL)
                        .color(theme::color::TEXT_MUTED),
                    Space::new().height(theme::space::SM),
                    button(
                        text("Import")
                            .width(Length::Fill)
                            .align_x(Alignment::Center),
                    )
                    .on_press(Message::GoToImport)
                    .style(theme::secondary_button)
                    .padding(theme::space::MD)
                    .width(Length::Fill),
                ]
                .spacing(theme::space::SM),
            )
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::FillPortion(1));

            let cards = row![create_card, import_card].spacing(theme::space::LG);

            let empty = column![
                text("Welcome to Keep")
                    .size(theme::size::TITLE)
                    .color(theme::color::TEXT),
                text("Manage your FROST threshold signing shares")
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT_MUTED),
                text("Create a keyset to generate shares, then export each share to a different device using QR codes.")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_DIM),
                Space::new().height(theme::space::LG),
                cards,
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
            for (i, share) in self.shares.iter().enumerate() {
                list = list.push(self.share_card(i, share));
            }
            content = content.push(scrollable(list).height(Length::Fill));
        }

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn share_card<'a>(&self, i: usize, share: &ShareEntry) -> Element<'a, Message> {
        let is_active = self.active_share_hex.as_deref() == Some(&share.group_pubkey_hex);

        let truncated_npub = share.truncated_npub();

        let badge = container(
            text(format!("{}-of-{}", share.threshold, share.total_shares))
                .size(theme::size::TINY)
                .color(theme::color::PRIMARY),
        )
        .style(theme::badge_style)
        .padding([2.0, theme::space::SM]);

        let share_index = text(format!("#{}", share.identifier))
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let npub_text = text(truncated_npub)
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let arrow = if self.expanded == Some(i) { "v" } else { ">" };
        let name_btn = button(
            text(format!("{arrow} {}", share.name))
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
        )
        .on_press(Message::ToggleDetails(i))
        .style(theme::text_button)
        .padding(0);

        let mut header_buttons = row![].spacing(theme::space::SM).align_y(Alignment::Center);

        if !is_active {
            let activate_btn = button(text("Activate").size(theme::size::SMALL))
                .on_press(Message::ActivateShare(share.group_pubkey_hex.clone()))
                .style(theme::secondary_button)
                .padding([theme::space::XS, theme::space::MD]);

            header_buttons = header_buttons.push(activate_btn);
        }

        let export_btn = button(text("Export QR").size(theme::size::SMALL))
            .on_press(Message::GoToExport(i))
            .style(theme::primary_button)
            .padding([theme::space::XS, theme::space::MD]);

        header_buttons = header_buttons.push(export_btn);

        let header_top = row![name_btn, Space::new().width(Length::Fill), header_buttons,]
            .align_y(Alignment::Center);

        let mut info_row = row![badge, share_index]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

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
                text(format!("npub: {}", share.npub))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                button(text("Copy").size(theme::size::TINY))
                    .on_press(Message::CopyNpub(share.npub.clone()))
                    .style(theme::secondary_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            let details = column![
                npub_row,
                text(format!("hex: {}", share.group_pubkey_hex))
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
                text(format!("Created: {}", share.created_display()))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                text(format!("Last used: {}", share.last_used_display()))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                text(format!("Signatures: {}", share.sign_count))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            ]
            .spacing(theme::space::XS);

            let share_id = ShareIdentity {
                group_pubkey: share.group_pubkey,
                identifier: share.identifier,
            };
            let actions = if self.delete_confirm.as_ref() == Some(&share_id) {
                row![
                    text(format!("Delete '{}'? This cannot be undone.", share.name))
                        .size(theme::size::BODY)
                        .color(theme::color::ERROR),
                    Space::new().width(Length::Fill),
                    button(text("Yes").size(theme::size::BODY))
                        .on_press(Message::ConfirmDelete(share_id.clone()))
                        .style(theme::danger_button)
                        .padding([theme::space::XS, theme::space::MD]),
                    button(text("No").size(theme::size::BODY))
                        .on_press(Message::CancelDelete)
                        .style(theme::secondary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                ]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center)
            } else {
                row![
                    Space::new().width(Length::Fill),
                    button(text("Delete").size(theme::size::BODY))
                        .on_press(Message::RequestDelete(share_id))
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
