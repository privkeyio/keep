// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length};
use zeroize::Zeroizing;

use crate::message::Message;
use crate::theme;

pub struct SettingsScreen {
    pub auto_lock_secs: u64,
    pub clipboard_clear_secs: u64,
    pub vault_path: String,
    pub proxy_enabled: bool,
    pub proxy_port: u16,
    pub proxy_port_input: String,
    pub kill_switch_active: bool,
    pub kill_switch_confirm: bool,
    pub kill_switch_password: Zeroizing<String>,
    pub kill_switch_loading: bool,
    pub kill_switch_error: Option<String>,
    pub minimize_to_tray: bool,
    pub start_minimized: bool,
    pub has_tray: bool,
    pub certificate_pins: Vec<(String, String)>,
}

fn toggle_button(active: bool, message: Message) -> button::Button<'static, Message> {
    let (label, style): (&str, fn(&iced::Theme, button::Status) -> button::Style) = if active {
        ("On", theme::primary_button)
    } else {
        ("Off", theme::secondary_button)
    };
    button(text(label).size(theme::size::SMALL))
        .on_press(message)
        .style(style)
        .padding([theme::space::SM, theme::space::MD])
}

impl SettingsScreen {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auto_lock_secs: u64,
        clipboard_clear_secs: u64,
        vault_path: String,
        proxy_enabled: bool,
        proxy_port: u16,
        kill_switch_active: bool,
        minimize_to_tray: bool,
        start_minimized: bool,
        has_tray: bool,
        certificate_pins: Vec<(String, String)>,
    ) -> Self {
        Self {
            auto_lock_secs,
            clipboard_clear_secs,
            vault_path,
            proxy_enabled,
            proxy_port,
            proxy_port_input: proxy_port.to_string(),
            kill_switch_active,
            kill_switch_confirm: false,
            kill_switch_password: Zeroizing::new(String::new()),
            kill_switch_loading: false,
            kill_switch_error: None,
            minimize_to_tray,
            start_minimized,
            has_tray,
            certificate_pins,
        }
    }

    pub fn view_content(&self) -> Element<Message> {
        let title = theme::heading("Settings");

        let kill_switch_card = self.kill_switch_card();
        let auto_lock_card = self.auto_lock_card();
        let clipboard_card = self.clipboard_card();
        let proxy_card = self.proxy_card();
        let cert_pins_card = self.cert_pins_card();
        let info_card = self.info_card();

        let mut content = column![title, kill_switch_card, auto_lock_card, clipboard_card,]
            .spacing(theme::space::MD)
            .padding(theme::space::LG)
            .width(Length::Fill);

        if self.has_tray {
            content = content.push(self.tray_card());
        }

        content = content
            .push(proxy_card)
            .push(cert_pins_card)
            .push(info_card);

        scrollable(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn kill_switch_card(&self) -> Element<Message> {
        if self.kill_switch_active {
            let password_input = text_input("Vault password", &self.kill_switch_password)
                .on_input(|s| Message::KillSwitchPasswordChanged(Zeroizing::new(s)))
                .secure(true)
                .size(theme::size::BODY)
                .width(theme::size::INPUT_WIDTH);

            let mut deactivate_btn = button(text("Deactivate").size(theme::size::SMALL))
                .style(theme::primary_button)
                .padding([theme::space::SM, theme::space::MD]);
            if !self.kill_switch_loading && !self.kill_switch_password.is_empty() {
                deactivate_btn = deactivate_btn.on_press(Message::KillSwitchDeactivate);
            }

            let controls = row![password_input, deactivate_btn]
                .spacing(theme::space::SM)
                .align_y(iced::Alignment::Center);

            let mut col = column![
                row![
                    theme::label("Kill Switch"),
                    iced::widget::Space::new().width(theme::space::SM),
                    container(
                        text("ACTIVE")
                            .size(theme::size::TINY)
                            .color(iced::Color::WHITE),
                    )
                    .style(theme::kill_switch_badge_style)
                    .padding([2.0, theme::space::SM]),
                ]
                .align_y(iced::Alignment::Center),
                theme::muted("All signing is blocked. Enter vault password to deactivate."),
                controls,
            ]
            .spacing(theme::space::SM);

            if self.kill_switch_loading {
                col = col.push(
                    text("Verifying...")
                        .size(theme::size::SMALL)
                        .color(theme::color::TEXT_MUTED),
                );
            }

            if let Some(ref err) = self.kill_switch_error {
                col = col.push(theme::error_text(err));
            }

            container(col)
                .style(theme::kill_switch_card_style)
                .padding(theme::space::LG)
                .width(Length::Fill)
                .into()
        } else {
            let action: Element<Message> = if self.kill_switch_confirm {
                row![
                    text("Block all signing?")
                        .size(theme::size::BODY)
                        .color(theme::color::ERROR),
                    iced::widget::Space::new().width(Length::Fill),
                    button(text("Yes").size(theme::size::BODY))
                        .on_press(Message::KillSwitchActivate)
                        .style(theme::danger_button)
                        .padding([theme::space::XS, theme::space::MD]),
                    button(text("No").size(theme::size::BODY))
                        .on_press(Message::KillSwitchCancelConfirm)
                        .style(theme::secondary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                ]
                .spacing(theme::space::SM)
                .align_y(iced::Alignment::Center)
                .into()
            } else {
                button(text("Activate Kill Switch").size(theme::size::SMALL))
                    .on_press(Message::KillSwitchRequestConfirm)
                    .style(theme::danger_button)
                    .padding([theme::space::SM, theme::space::MD])
                    .into()
            };

            container(
                column![
                    theme::label("Kill Switch"),
                    theme::muted(
                        "Emergency block of all signing. Requires vault password to re-enable."
                    ),
                    action,
                ]
                .spacing(theme::space::SM),
            )
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
        }
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

    fn tray_card(&self) -> Element<Message> {
        let minimize_btn = toggle_button(
            self.minimize_to_tray,
            Message::SettingsMinimizeToTrayToggled(!self.minimize_to_tray),
        );
        let start_btn = toggle_button(
            self.start_minimized,
            Message::SettingsStartMinimizedToggled(!self.start_minimized),
        );

        container(
            column![
                theme::label("System tray"),
                row![theme::muted("Minimize to tray on close"), minimize_btn]
                    .spacing(theme::space::SM)
                    .align_y(iced::Alignment::Center),
                row![theme::muted("Start minimized to tray"), start_btn]
                    .spacing(theme::space::SM)
                    .align_y(iced::Alignment::Center),
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

        let controls = row![text("Port").size(theme::size::BODY), port_input, toggle_btn]
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

    fn cert_pins_card(&self) -> Element<Message> {
        let mut col = column![
            theme::label("TLS certificate pinning"),
            theme::muted("Pins are set on first connection to each relay (TOFU)"),
        ]
        .spacing(theme::space::SM);

        if self.certificate_pins.is_empty() {
            col = col.push(
                text("No pinned certificates")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );
        } else {
            for (hostname, hash) in &self.certificate_pins {
                let truncated = match hash.get(..16) {
                    Some(prefix) => format!("{prefix}..."),
                    None => hash.clone(),
                };

                let clear_btn = button(text("Clear").size(theme::size::TINY))
                    .on_press(Message::CertPinClear(hostname.clone()))
                    .style(theme::secondary_button)
                    .padding([theme::space::XS, theme::space::SM]);

                let pin_row = row![
                    column![
                        text(hostname).size(theme::size::BODY),
                        text(truncated)
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_MUTED),
                    ]
                    .spacing(2),
                    iced::widget::Space::new().width(Length::Fill),
                    clear_btn,
                ]
                .align_y(iced::Alignment::Center)
                .spacing(theme::space::SM);

                col = col.push(pin_row);
            }

            let clear_all_btn = button(text("Clear All Pins").size(theme::size::SMALL))
                .on_press(Message::CertPinClearAll)
                .style(theme::danger_button)
                .padding([theme::space::SM, theme::space::MD]);

            col = col.push(clear_all_btn);
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
                column![
                    theme::label("Third-party notices"),
                    theme::muted(
                        "This software is based in part on the work of the Independent JPEG Group.",
                    ),
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
