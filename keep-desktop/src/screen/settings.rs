// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Element, Length};

use crate::message::Message;
use crate::screen::layout::{self, NavItem};
use crate::theme;

pub struct SettingsScreen {
    pub auto_lock_secs: u64,
    pub clipboard_clear_secs: u64,
    pub vault_path: String,
}

impl SettingsScreen {
    pub fn new(auto_lock_secs: u64, clipboard_clear_secs: u64, vault_path: String) -> Self {
        Self {
            auto_lock_secs,
            clipboard_clear_secs,
            vault_path,
        }
    }

    pub fn view(&self) -> Element<Message> {
        let title = theme::heading("Settings");

        let auto_lock_card = self.auto_lock_card();
        let clipboard_card = self.clipboard_card();
        let info_card = self.info_card();

        let content = column![title, auto_lock_card, clipboard_card, info_card]
            .spacing(theme::space::MD)
            .padding(theme::space::LG)
            .width(Length::Fill);

        let inner = scrollable(content).width(Length::Fill).height(Length::Fill);

        layout::with_sidebar(NavItem::Settings, inner.into(), None, 0)
    }

    fn auto_lock_card(&self) -> Element<Message> {
        let options: Vec<(u64, &str)> = vec![
            (60, "1 min"),
            (300, "5 min"),
            (900, "15 min"),
            (3600, "1 hour"),
            (0, "Never"),
        ];

        let buttons =
            options
                .into_iter()
                .fold(row![].spacing(theme::space::SM), |r, (secs, label)| {
                    let is_active = self.auto_lock_secs == secs;
                    let style: fn(&iced::Theme, button::Status) -> button::Style = if is_active {
                        theme::primary_button
                    } else {
                        theme::secondary_button
                    };
                    r.push(
                        button(text(label).size(theme::size::SMALL))
                            .on_press(Message::SettingsAutoLockChanged(secs))
                            .style(style)
                            .padding([theme::space::SM, theme::space::MD]),
                    )
                });

        container(
            column![
                theme::label("Auto-lock timeout"),
                theme::muted("Lock vault after inactivity"),
                buttons,
            ]
            .spacing(theme::space::SM),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill)
        .into()
    }

    fn clipboard_card(&self) -> Element<Message> {
        let options: Vec<(u64, &str)> = vec![(10, "10s"), (30, "30s"), (60, "60s"), (0, "Never")];

        let buttons =
            options
                .into_iter()
                .fold(row![].spacing(theme::space::SM), |r, (secs, label)| {
                    let is_active = self.clipboard_clear_secs == secs;
                    let style: fn(&iced::Theme, button::Status) -> button::Style = if is_active {
                        theme::primary_button
                    } else {
                        theme::secondary_button
                    };
                    r.push(
                        button(text(label).size(theme::size::SMALL))
                            .on_press(Message::SettingsClipboardClearChanged(secs))
                            .style(style)
                            .padding([theme::space::SM, theme::space::MD]),
                    )
                });

        container(
            column![
                theme::label("Clipboard auto-clear"),
                theme::muted("Clear clipboard after copying sensitive data"),
                buttons,
            ]
            .spacing(theme::space::SM),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill)
        .into()
    }

    fn info_card(&self) -> Element<Message> {
        container(
            column![
                column![theme::label("Vault"), theme::muted(&self.vault_path),]
                    .spacing(theme::space::XS),
                column![
                    theme::label("Version"),
                    theme::muted(env!("CARGO_PKG_VERSION")),
                ]
                .spacing(theme::space::XS),
            ]
            .spacing(theme::space::MD),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill)
        .into()
    }
}
