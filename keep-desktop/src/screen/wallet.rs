// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::theme;

#[derive(Debug, Clone)]
pub struct WalletEntry {
    #[allow(dead_code)]
    pub group_pubkey: [u8; 32],
    pub group_hex: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub network: String,
    pub created_at: u64,
}

impl WalletEntry {
    pub fn from_descriptor(d: &keep_core::WalletDescriptor) -> Self {
        let group_hex = hex::encode(d.group_pubkey);
        Self {
            group_pubkey: d.group_pubkey,
            group_hex,
            external_descriptor: d.external_descriptor.clone(),
            internal_descriptor: d.internal_descriptor.clone(),
            network: d.network.clone(),
            created_at: d.created_at,
        }
    }

    fn truncated_hex(&self) -> &str {
        &self.group_hex[..16.min(self.group_hex.len())]
    }
}

pub struct WalletScreen {
    pub descriptors: Vec<WalletEntry>,
    pub expanded: Option<usize>,
}

impl WalletScreen {
    pub fn new(descriptors: Vec<WalletEntry>) -> Self {
        Self {
            descriptors,
            expanded: None,
        }
    }

    pub fn view_content(&self) -> Element<Message> {
        let title = theme::heading("Wallet Descriptors");

        let mut content = column![title].spacing(theme::space::MD);

        if self.descriptors.is_empty() {
            let empty = column![
                text("No wallet descriptors yet")
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT_MUTED),
                text("Wallet descriptors are created during the wallet coordination workflow.")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_DIM),
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
            for (i, entry) in self.descriptors.iter().enumerate() {
                list = list.push(self.wallet_card(i, entry));
            }
            content = content.push(scrollable(list).height(Length::Fill));
        }

        container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn wallet_card<'a>(&self, i: usize, entry: &WalletEntry) -> Element<'a, Message> {
        let network_badge = container(
            text(entry.network.clone())
                .size(theme::size::TINY)
                .color(theme::color::PRIMARY),
        )
        .style(theme::badge_style)
        .padding([2.0, theme::space::SM]);

        let hex_text = text(entry.truncated_hex().to_owned())
            .size(theme::size::SMALL)
            .color(theme::color::TEXT_MUTED);

        let arrow = if self.expanded == Some(i) { "v" } else { ">" };
        let name_btn = button(
            text(format!("{arrow} {}", entry.truncated_hex()))
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
        )
        .on_press(Message::ToggleWalletDetails(i))
        .style(theme::text_button)
        .padding(0);

        let header_top =
            row![name_btn, Space::new().width(Length::Fill)].align_y(Alignment::Center);

        let header_info = column![
            header_top,
            row![network_badge, hex_text]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center),
        ]
        .spacing(theme::space::XS);

        let mut card_content = column![header_info].spacing(theme::space::SM);

        if self.expanded == Some(i) {
            let ext_row = row![
                text("External:")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                button(text("Copy").size(theme::size::TINY))
                    .on_press(Message::CopyDescriptor(entry.external_descriptor.clone()))
                    .style(theme::secondary_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            let ext_value = text(entry.external_descriptor.clone())
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let int_row = row![
                text("Internal:")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
                button(text("Copy").size(theme::size::TINY))
                    .on_press(Message::CopyDescriptor(entry.internal_descriptor.clone()))
                    .style(theme::secondary_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            let int_value = text(entry.internal_descriptor.clone())
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let hex_full = text(format!("Group key: {}", entry.group_hex))
                .size(theme::size::TINY)
                .color(theme::color::TEXT_DIM);

            let created = DateTime::<Utc>::from_timestamp(entry.created_at as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| entry.created_at.to_string());
            let created_text = text(format!("Created: {created}"))
                .size(theme::size::SMALL)
                .color(theme::color::TEXT_MUTED);

            let details = column![
                ext_row,
                ext_value,
                int_row,
                int_value,
                hex_full,
                created_text
            ]
            .spacing(theme::space::XS);

            card_content = card_content.push(details);
        }

        container(card_content)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }
}
