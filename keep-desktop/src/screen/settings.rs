// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length};
use zeroize::Zeroizing;

use crate::theme;

#[derive(Clone)]
pub enum Message {
    AutoLockChanged(u64),
    ClipboardClearChanged(u64),
    ProxyToggled(bool),
    ProxyPortChanged(String),
    MinimizeToTrayToggled(bool),
    StartMinimizedToggled(bool),
    KillSwitchRequestConfirm,
    KillSwitchCancelConfirm,
    KillSwitchActivate,
    KillSwitchPasswordChanged(Zeroizing<String>),
    KillSwitchDeactivate,
    CertPinClear(String),
    CertPinClearAllRequest,
    CertPinClearAllConfirm,
    CertPinClearAllCancel,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutoLockChanged(v) => f.debug_tuple("AutoLockChanged").field(v).finish(),
            Self::ClipboardClearChanged(v) => {
                f.debug_tuple("ClipboardClearChanged").field(v).finish()
            }
            Self::ProxyToggled(v) => f.debug_tuple("ProxyToggled").field(v).finish(),
            Self::ProxyPortChanged(v) => f.debug_tuple("ProxyPortChanged").field(v).finish(),
            Self::MinimizeToTrayToggled(v) => {
                f.debug_tuple("MinimizeToTrayToggled").field(v).finish()
            }
            Self::StartMinimizedToggled(v) => {
                f.debug_tuple("StartMinimizedToggled").field(v).finish()
            }
            Self::KillSwitchRequestConfirm => f.write_str("KillSwitchRequestConfirm"),
            Self::KillSwitchCancelConfirm => f.write_str("KillSwitchCancelConfirm"),
            Self::KillSwitchActivate => f.write_str("KillSwitchActivate"),
            Self::KillSwitchPasswordChanged(_) => f.write_str("KillSwitchPasswordChanged(***)"),
            Self::KillSwitchDeactivate => f.write_str("KillSwitchDeactivate"),
            Self::CertPinClear(h) => f.debug_tuple("CertPinClear").field(h).finish(),
            Self::CertPinClearAllRequest => f.write_str("CertPinClearAllRequest"),
            Self::CertPinClearAllConfirm => f.write_str("CertPinClearAllConfirm"),
            Self::CertPinClearAllCancel => f.write_str("CertPinClearAllCancel"),
        }
    }
}

pub enum Event {
    AutoLockChanged(u64),
    ClipboardClearChanged(u64),
    ProxyToggled(bool),
    ProxyPortChanged(u16),
    MinimizeToTrayToggled(bool),
    StartMinimizedToggled(bool),
    KillSwitchActivate,
    KillSwitchDeactivate(Zeroizing<String>),
    CertPinClear(String),
    CertPinClearAll,
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

pub struct SettingsScreen {
    pub auto_lock_secs: u64,
    pub clipboard_clear_secs: u64,
    pub vault_path: String,
    pub proxy_enabled: bool,
    pub proxy_port: u16,
    proxy_port_input: String,
    pub kill_switch_active: bool,
    kill_switch_confirm: bool,
    kill_switch_password: Zeroizing<String>,
    pub kill_switch_loading: bool,
    pub kill_switch_error: Option<String>,
    pub minimize_to_tray: bool,
    pub start_minimized: bool,
    pub has_tray: bool,
    pub certificate_pins: Vec<(String, String)>,
    clear_all_pins_confirm: bool,
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
            clear_all_pins_confirm: false,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::AutoLockChanged(secs) => Some(Event::AutoLockChanged(secs)),
            Message::ClipboardClearChanged(secs) => Some(Event::ClipboardClearChanged(secs)),
            Message::ProxyToggled(enabled) => Some(Event::ProxyToggled(enabled)),
            Message::ProxyPortChanged(port_str) => {
                self.proxy_port_input = port_str.clone();
                match port_str.parse::<u16>() {
                    Ok(port) if port > 0 => Some(Event::ProxyPortChanged(port)),
                    _ => None,
                }
            }
            Message::MinimizeToTrayToggled(v) => Some(Event::MinimizeToTrayToggled(v)),
            Message::StartMinimizedToggled(v) => Some(Event::StartMinimizedToggled(v)),
            Message::KillSwitchRequestConfirm => {
                self.kill_switch_confirm = true;
                None
            }
            Message::KillSwitchCancelConfirm => {
                self.kill_switch_confirm = false;
                None
            }
            Message::KillSwitchActivate => {
                self.kill_switch_confirm = false;
                Some(Event::KillSwitchActivate)
            }
            Message::KillSwitchPasswordChanged(p) => {
                self.kill_switch_password = p;
                None
            }
            Message::KillSwitchDeactivate => {
                if self.kill_switch_password.is_empty() {
                    self.kill_switch_error = Some("Password required".into());
                    return None;
                }
                self.kill_switch_loading = true;
                self.kill_switch_error = None;
                Some(Event::KillSwitchDeactivate(
                    self.kill_switch_password.clone(),
                ))
            }
            Message::CertPinClear(hostname) => Some(Event::CertPinClear(hostname)),
            Message::CertPinClearAllRequest => {
                self.clear_all_pins_confirm = true;
                None
            }
            Message::CertPinClearAllCancel => {
                self.clear_all_pins_confirm = false;
                None
            }
            Message::CertPinClearAllConfirm => Some(Event::CertPinClearAll),
        }
    }

    pub fn kill_switch_activated(&mut self) {
        self.kill_switch_confirm = false;
        self.kill_switch_active = true;
    }

    pub fn kill_switch_deactivated(&mut self) {
        self.kill_switch_loading = false;
        self.kill_switch_password = Zeroizing::new(String::new());
        self.kill_switch_active = false;
        self.kill_switch_error = None;
    }

    pub fn kill_switch_deactivate_failed(&mut self, error: String) {
        self.kill_switch_loading = false;
        self.kill_switch_password = Zeroizing::new(String::new());
        self.kill_switch_error = Some(error);
    }

    pub fn clear_all_pins_done(&mut self) {
        self.clear_all_pins_confirm = false;
    }

    pub fn sync_proxy_port(&mut self, port: u16) {
        self.proxy_port = port;
        let formatted = port.to_string();
        if self.proxy_port_input != formatted {
            self.proxy_port_input = formatted;
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
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

    fn kill_switch_card(&self) -> Element<'_, Message> {
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

    fn auto_lock_card(&self) -> Element<'_, Message> {
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
                            .on_press(Message::AutoLockChanged(secs))
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

    fn clipboard_card(&self) -> Element<'_, Message> {
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
                            .on_press(Message::ClipboardClearChanged(secs))
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

    fn tray_card(&self) -> Element<'_, Message> {
        let minimize_btn = toggle_button(
            self.minimize_to_tray,
            Message::MinimizeToTrayToggled(!self.minimize_to_tray),
        );
        let start_btn = toggle_button(
            self.start_minimized,
            Message::StartMinimizedToggled(!self.start_minimized),
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

    fn proxy_card(&self) -> Element<'_, Message> {
        let port_input = text_input("9050", &self.proxy_port_input)
            .on_input(Message::ProxyPortChanged)
            .size(theme::size::BODY)
            .width(Length::Fixed(100.0));

        let (btn_label, btn_style): (&str, fn(&iced::Theme, button::Status) -> button::Style) =
            if self.proxy_enabled {
                ("Deactivate", theme::danger_button)
            } else {
                ("Activate", theme::primary_button)
            };

        let toggle_btn = button(text(btn_label).size(theme::size::SMALL))
            .on_press(Message::ProxyToggled(!self.proxy_enabled))
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

    fn cert_pins_card(&self) -> Element<'_, Message> {
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
                let truncated = if hash.len() > 16 {
                    format!("{}...", &hash[..16])
                } else {
                    hash.clone()
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

            if self.clear_all_pins_confirm {
                let confirm_row = row![
                    text("Clear all pins?")
                        .size(theme::size::BODY)
                        .color(theme::color::ERROR),
                    iced::widget::Space::new().width(Length::Fill),
                    button(text("Yes").size(theme::size::BODY))
                        .on_press(Message::CertPinClearAllConfirm)
                        .style(theme::danger_button)
                        .padding([theme::space::XS, theme::space::MD]),
                    button(text("No").size(theme::size::BODY))
                        .on_press(Message::CertPinClearAllCancel)
                        .style(theme::secondary_button)
                        .padding([theme::space::XS, theme::space::MD]),
                ]
                .spacing(theme::space::SM)
                .align_y(iced::Alignment::Center);
                col = col.push(confirm_row);
            } else {
                let clear_all_btn = button(text("Clear All Pins").size(theme::size::SMALL))
                    .on_press(Message::CertPinClearAllRequest)
                    .style(theme::danger_button)
                    .padding([theme::space::SM, theme::space::MD]);
                col = col.push(clear_all_btn);
            }
        }

        container(col)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn info_card(&self) -> Element<'_, Message> {
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
