// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length};

use crate::message::Message;
use crate::screen::layout::{self, NavItem};
use crate::theme;

pub struct SettingsScreen {
    pub auto_lock_secs: u64,
    pub clipboard_clear_secs: u64,
    pub vault_path: String,
    pub proxy_enabled: bool,
    pub proxy_port: u16,
    pub proxy_port_input: String,
}

impl SettingsScreen {
    pub fn new(
        auto_lock_secs: u64,
        clipboard_clear_secs: u64,
        vault_path: String,
        proxy_enabled: bool,
        proxy_port: u16,
    ) -> Self {
        Self {
            auto_lock_secs,
            clipboard_clear_secs,
            vault_path,
            proxy_enabled,
            proxy_port,
            proxy_port_input: proxy_port.to_string(),
        }
    }

    pub fn view(&self) -> Element<Message> {
        let title = theme::heading("Settings");

        let auto_lock_card = self.auto_lock_card();
        let clipboard_card = self.clipboard_card();
        let proxy_card = self.proxy_card();
        let info_card = self.info_card();

        let content = column![title, auto_lock_card, clipboard_card, proxy_card, info_card]
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

    fn proxy_card(&self) -> Element<Message> {
        let port_input = text_input("9050", &self.proxy_port_input)
            .on_input(Message::SettingsProxyPortChanged)
            .size(theme::size::BODY)
            .width(Length::Fixed(100.0));

        let (btn_label, btn_style): (&str, fn(&iced::Theme, button::Status) -> button::Style) =
            if self.proxy_enabled {
                ("Deactivate", theme::danger_button)
            } else {
                ("Activate", theme::primary_button)
            };

        let toggle_btn = button(text(btn_label).size(theme::size::SMALL))
            .on_press(Message::SettingsProxyToggled(!self.proxy_enabled))
            .style(btn_style)
            .padding([theme::space::SM, theme::space::MD]);

        let controls = row![text("Port").size(theme::size::BODY), port_input, toggle_btn,]
            .spacing(theme::space::SM)
            .align_y(iced::Alignment::Center);

        let mut col = column![
            theme::label("Tor / SOCKS proxy"),
            theme::muted(
                "Route relay connections through a local SOCKS5 proxy (e.g. Tor on port 9050)"
            ),
            controls,
        ]
        .spacing(theme::space::SM);

        if self.proxy_enabled && self.proxy_port > 0 {
            col = col.push(
                text(format!("Proxy active on port {}", self.proxy_port))
                    .size(theme::size::BODY)
                    .color(theme::color::SUCCESS),
            );
        }

        container(col)
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
