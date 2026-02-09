// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};

use crate::message::{Message, ShareIdentity};
use crate::screen::layout::{self, NavItem};
use crate::theme;

#[derive(Debug, Clone)]
pub struct ShareEntry {
    pub name: String,
    pub identifier: u16,
    pub threshold: u16,
    pub total_shares: u16,
    pub group_pubkey: [u8; 32],
    pub group_pubkey_hex: String,
    pub created_at: i64,
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
            created_at: m.created_at,
            sign_count: m.sign_count,
        }
    }

    fn created_display(&self) -> String {
        DateTime::<Utc>::from_timestamp(self.created_at, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| self.created_at.to_string())
    }
}

pub struct ShareListScreen {
    pub shares: Vec<ShareEntry>,
    pub delete_confirm: Option<usize>,
    pub error: Option<String>,
    pub success_message: Option<String>,
    pub expanded: Option<usize>,
}

impl ShareListScreen {
    pub fn new(shares: Vec<ShareEntry>) -> Self {
        Self {
            shares,
            delete_confirm: None,
            error: None,
            success_message: None,
            expanded: None,
        }
    }

    pub fn with_message(shares: Vec<ShareEntry>, message: String) -> Self {
        Self {
            success_message: Some(message),
            ..Self::new(shares)
        }
    }

    pub fn view(&self) -> Element<Message> {
        let title = theme::heading("FROST Shares");

        let mut content = column![title].spacing(theme::space::MD);

        if let Some(msg) = &self.success_message {
            content = content.push(theme::success_text(msg.as_str()));
        }

        if let Some(err) = &self.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        if self.shares.is_empty() {
            let empty = column![
                text("No shares yet")
                    .size(theme::size::HEADING)
                    .color(theme::color::TEXT_MUTED),
                Space::new().height(theme::space::XL),
                button(text("Create Keyset").width(250).align_x(Alignment::Center),)
                    .on_press(Message::GoToCreate)
                    .style(theme::primary_button)
                    .padding(theme::space::MD),
                Space::new().height(theme::space::SM),
                button(text("Import Share").width(250).align_x(Alignment::Center),)
                    .on_press(Message::GoToImport)
                    .style(theme::secondary_button)
                    .padding(theme::space::MD),
            ]
            .align_x(Alignment::Center)
            .spacing(theme::space::XS);

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

        let inner = container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill);

        layout::with_sidebar(NavItem::Shares, inner.into())
    }

    fn share_card<'a>(&self, i: usize, share: &ShareEntry) -> Element<'a, Message> {
        let truncated_pubkey = format!(
            "{}...",
            &share.group_pubkey_hex[..share.group_pubkey_hex.len().min(16)]
        );

        let badge = text(format!("{}-of-{}", share.threshold, share.total_shares))
            .size(theme::size::TINY)
            .color(theme::color::PRIMARY);

        let pubkey_text = text(truncated_pubkey)
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let arrow = if self.expanded == Some(i) { "v" } else { ">" };
        let name_btn = button(
            text(format!("{arrow} {}", share.name))
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
        )
        .on_press(Message::ToggleShareDetails(i))
        .style(theme::text_button)
        .padding(0);

        let header_info = column![name_btn, row![badge, pubkey_text].spacing(theme::space::SM)]
            .spacing(theme::space::XS);

        let mut card_content = column![header_info].spacing(theme::space::SM);

        if self.expanded == Some(i) {
            let details = column![
                text(format!("Group pubkey: {}", share.group_pubkey_hex))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                text(format!("Share #{}", share.identifier))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                text(format!("Created: {}", share.created_display()))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                text(format!("Signatures: {}", share.sign_count))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            ]
            .spacing(theme::space::XS);

            let actions = if self.delete_confirm == Some(i) {
                row![
                    theme::error_text("Delete? This cannot be undone."),
                    Space::new().width(Length::Fill),
                    button(text("Yes").size(theme::size::BODY))
                        .on_press(Message::ConfirmDelete(ShareIdentity {
                            group_pubkey: share.group_pubkey,
                            identifier: share.identifier,
                        }))
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
                    button(text("Export QR").size(theme::size::BODY))
                        .on_press(Message::GoToExport(i))
                        .style(theme::primary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                    button(text("Delete").size(theme::size::BODY))
                        .on_press(Message::RequestDelete(i))
                        .style(theme::danger_button)
                        .padding([theme::space::XS, theme::space::MD]),
                ]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center)
            };

            card_content = card_content.push(details).push(actions);
        }

        container(card_content)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }
}
