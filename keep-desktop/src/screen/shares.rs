// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use chrono::{DateTime, Utc};
use iced::widget::{button, column, container, row, rule, scrollable, text, Space};
use iced::{Alignment, Element, Length};

use crate::message::{Message, ShareIdentity};

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
            shares,
            delete_confirm: None,
            error: None,
            success_message: Some(message),
            expanded: None,
        }
    }

    pub fn view(&self) -> Element<Message> {
        let header = row![
            text("FROST Shares").size(24),
            Space::new().width(Length::Fill),
            button(text("Create"))
                .on_press(Message::GoToCreate)
                .padding(8),
            button(text("Import"))
                .on_press(Message::GoToImport)
                .padding(8),
            button(text("Lock")).on_press(Message::Lock).padding(8),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let mut content = column![header, rule::horizontal(1)].spacing(10);

        if let Some(msg) = &self.success_message {
            content = content.push(
                text(msg.as_str())
                    .size(14)
                    .color(iced::Color::from_rgb(0.2, 0.6, 0.3)),
            );
        }

        if let Some(err) = &self.error {
            content = content.push(
                text(err.as_str())
                    .size(14)
                    .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
            );
        }

        if self.shares.is_empty() {
            let empty = column![
                text("No shares yet").size(18),
                Space::new().height(20),
                button(text("Create Keyset").width(250).align_x(Alignment::Center),)
                    .on_press(Message::GoToCreate)
                    .padding(12),
                Space::new().height(8),
                button(text("Import Share").width(250).align_x(Alignment::Center),)
                    .on_press(Message::GoToImport)
                    .padding(12),
            ]
            .align_x(Alignment::Center)
            .spacing(4);

            content = content.push(
                container(empty)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill),
            );
        } else {
            let mut list = column![].spacing(5);
            for (i, share) in self.shares.iter().enumerate() {
                let truncated_pubkey = format!("{}...", &share.group_pubkey_hex[..16]);

                let meta = text(format!(
                    "{}-of-{}  |  Share #{}  |  {}",
                    share.threshold, share.total_shares, share.identifier, truncated_pubkey
                ))
                .size(12)
                .color(iced::Color::from_rgb(0.6, 0.6, 0.6));

                let arrow = if self.expanded == Some(i) {
                    "v"
                } else {
                    ">"
                };
                let name_btn = button(text(format!("{arrow} {}", share.name)).size(16))
                    .on_press(Message::ToggleShareDetails(i))
                    .style(button::text)
                    .padding(0);

                let mut info = column![name_btn, meta].spacing(2);

                if self.expanded == Some(i) {
                    let detail_color = iced::Color::from_rgb(0.6, 0.6, 0.6);
                    info = info.push(Space::new().height(4));
                    info = info.push(
                        text(format!("Group pubkey: {}", share.group_pubkey_hex))
                            .size(12)
                            .color(detail_color),
                    );
                    info = info.push(
                        text(format!("Created: {}", share.created_display()))
                            .size(12)
                            .color(detail_color),
                    );
                    info = info.push(
                        text(format!("Signatures: {}", share.sign_count))
                            .size(12)
                            .color(detail_color),
                    );
                }

                let share_row = if self.delete_confirm == Some(i) {
                    row![
                        info,
                        Space::new().width(Length::Fill),
                        text("Delete? This cannot be undone.")
                            .size(14)
                            .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
                        button(text("Yes"))
                            .on_press(Message::ConfirmDelete(ShareIdentity {
                                group_pubkey: share.group_pubkey,
                                identifier: share.identifier,
                            }))
                            .padding(6),
                        button(text("No"))
                            .on_press(Message::CancelDelete)
                            .padding(6),
                    ]
                } else {
                    row![
                        info,
                        Space::new().width(Length::Fill),
                        button(text("Export QR"))
                            .on_press(Message::GoToExport(i))
                            .padding(6),
                        button(text("Delete"))
                            .on_press(Message::RequestDelete(i))
                            .padding(6),
                    ]
                }
                .spacing(8)
                .align_y(Alignment::Center);

                list = list.push(share_row);
                list = list.push(rule::horizontal(1));
            }
            content = content.push(scrollable(list).height(Length::Fill));
        }

        container(content)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
