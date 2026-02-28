// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::message::{ConnectionStatus, PeerEntry, PendingSignRequest};
use crate::screen::shares::ShareEntry;
use crate::theme;

#[derive(Clone)]
pub enum Message {
    SelectShare(usize),
    RelayUrlChanged(String),
    PasswordChanged(Zeroizing<String>),
    AddRelay,
    RemoveRelay(usize),
    Connect,
    Disconnect,
    ApproveSign(String),
    RejectSign(String),
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectShare(i) => f.debug_tuple("SelectShare").field(i).finish(),
            Self::RelayUrlChanged(u) => f.debug_tuple("RelayUrlChanged").field(u).finish(),
            Self::PasswordChanged(_) => f.write_str("PasswordChanged(***)"),
            Self::AddRelay => f.write_str("AddRelay"),
            Self::RemoveRelay(i) => f.debug_tuple("RemoveRelay").field(i).finish(),
            Self::Connect => f.write_str("Connect"),
            Self::Disconnect => f.write_str("Disconnect"),
            Self::ApproveSign(id) => f.debug_tuple("ApproveSign").field(id).finish(),
            Self::RejectSign(id) => f.debug_tuple("RejectSign").field(id).finish(),
        }
    }
}

pub enum Event {
    AddRelay(String),
    RemoveRelay(usize),
    Connect,
    Disconnect,
    ApproveSignRequest(String),
    RejectSignRequest(String),
}

pub struct State {
    relay_url_input: String,
    pub relay_urls: Vec<String>,
    pub shares: Vec<ShareEntry>,
    pub selected_share: Option<usize>,
    pub connect_password: Zeroizing<String>,
    pub status: ConnectionStatus,
    pub peers: Vec<PeerEntry>,
    pub pending_requests: Vec<PendingSignRequest>,
}

impl State {
    pub fn new(
        shares: Vec<ShareEntry>,
        relay_urls: Vec<String>,
        status: ConnectionStatus,
        peers: Vec<PeerEntry>,
        pending_requests: Vec<PendingSignRequest>,
    ) -> Self {
        let selected = if shares.len() == 1 { Some(0) } else { None };
        Self {
            relay_url_input: String::new(),
            relay_urls,
            shares,
            selected_share: selected,
            connect_password: Zeroizing::new(String::new()),
            status,
            peers,
            pending_requests,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::SelectShare(i) => {
                self.selected_share = Some(i);
                None
            }
            Message::RelayUrlChanged(url) => {
                self.relay_url_input = url;
                None
            }
            Message::PasswordChanged(p) => {
                self.connect_password = p;
                None
            }
            Message::AddRelay => {
                let url = self.relay_url_input.trim().to_string();
                Some(Event::AddRelay(url))
            }
            Message::RemoveRelay(i) => Some(Event::RemoveRelay(i)),
            Message::Connect => Some(Event::Connect),
            Message::Disconnect => Some(Event::Disconnect),
            Message::ApproveSign(id) => Some(Event::ApproveSignRequest(id)),
            Message::RejectSign(id) => Some(Event::RejectSignRequest(id)),
        }
    }

    pub fn relay_added(&mut self, normalized: String) {
        self.relay_urls.push(normalized);
        self.relay_url_input.clear();
    }

    pub fn clear_input(&mut self) {
        self.relay_url_input.clear();
    }

    pub fn view(&self) -> Element<'_, Message> {
        let title_row = row![
            theme::heading("FROST Relay"),
            Space::new().width(Length::Fill),
            self.status_badge(),
        ]
        .align_y(Alignment::Center);

        let mut content = column![title_row].spacing(theme::space::MD);

        if self.shares.is_empty() {
            content = content.push(
                container(theme::muted(
                    "Import or create a share first to connect to relays",
                ))
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            );
        } else {
            content = content
                .push(self.share_selector())
                .push(self.relay_config())
                .push(self.connection_controls());

            if matches!(self.status, ConnectionStatus::Connected) {
                content = content.push(self.peers_section());
                if !self.pending_requests.is_empty() {
                    content = content.push(self.signing_requests_section());
                }
            }
        }

        container(scrollable(content).height(Length::Fill))
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn status_badge(&self) -> Element<'_, Message> {
        let (label, color) = match &self.status {
            ConnectionStatus::Disconnected => ("Disconnected", theme::color::TEXT_DIM),
            ConnectionStatus::Connecting => ("Connecting...", theme::color::WARNING),
            ConnectionStatus::Connected => ("Connected", theme::color::SUCCESS),
            ConnectionStatus::Error(_) => ("Error", theme::color::ERROR),
        };

        container(text(label).size(theme::size::SMALL).color(color))
            .style(move |_: &iced::Theme| iced::widget::container::Style {
                background: Some(iced::Background::Color(iced::Color { a: 0.15, ..color })),
                border: iced::Border {
                    color,
                    width: 1.0,
                    radius: 12.0.into(),
                },
                ..Default::default()
            })
            .padding([2.0, theme::space::SM])
            .into()
    }

    fn is_active(&self) -> bool {
        matches!(
            self.status,
            ConnectionStatus::Connected | ConnectionStatus::Connecting
        )
    }

    fn share_selector(&self) -> Element<'_, Message> {
        let mut share_buttons = row![].spacing(theme::space::SM);
        for (i, share) in self.shares.iter().enumerate() {
            let is_selected = self.selected_share == Some(i);
            let style: fn(
                &iced::Theme,
                iced::widget::button::Status,
            ) -> iced::widget::button::Style = if is_selected {
                theme::primary_button
            } else {
                theme::secondary_button
            };
            let btn = button(
                text(format!("{} #{}", share.name, share.identifier)).size(theme::size::SMALL),
            )
            .style(style)
            .on_press_maybe((!self.is_active()).then(|| Message::SelectShare(i)))
            .padding([theme::space::XS, theme::space::MD]);

            share_buttons = share_buttons.push(btn);
        }

        container(column![theme::label("Share"), share_buttons].spacing(theme::space::XS))
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn relay_config(&self) -> Element<'_, Message> {
        let active = self.is_active();

        let mut relay_list = column![].spacing(theme::space::XS);
        for (i, url) in self.relay_urls.iter().enumerate() {
            let mut relay_row = row![theme::muted(url), Space::new().width(Length::Fill),]
                .spacing(theme::space::SM)
                .align_y(Alignment::Center);

            if !active {
                relay_row = relay_row.push(
                    button(text("x").size(theme::size::SMALL))
                        .on_press(Message::RemoveRelay(i))
                        .style(theme::danger_button)
                        .padding([2.0, theme::space::SM]),
                );
            }

            relay_list = relay_list.push(relay_row);
        }

        let mut section = column![theme::label("Relay URLs"), relay_list].spacing(theme::space::SM);

        if !active {
            let can_add =
                self.relay_url_input.starts_with("wss://") && self.relay_url_input.len() > 6;
            let input_row = row![
                text_input("wss://relay.example.com", &self.relay_url_input)
                    .on_input(Message::RelayUrlChanged)
                    .size(theme::size::SMALL)
                    .width(Length::Fill),
                button(text("Add").size(theme::size::SMALL))
                    .style(theme::secondary_button)
                    .on_press_maybe(can_add.then(|| Message::AddRelay))
                    .padding([theme::space::XS, theme::space::MD]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            section = section.push(input_row);
        }

        container(section)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn connect_form(&self) -> Element<'_, Message> {
        let can_connect = self.selected_share.is_some()
            && !self.relay_urls.is_empty()
            && !self.connect_password.is_empty();
        let password_input = text_input("Vault password", &self.connect_password)
            .on_input(|s| Message::PasswordChanged(Zeroizing::new(s)))
            .secure(true)
            .size(theme::size::SMALL)
            .width(200);
        row![
            password_input,
            button(
                text("Connect")
                    .width(Length::Fill)
                    .align_x(Alignment::Center),
            )
            .style(theme::primary_button)
            .on_press_maybe(can_connect.then(|| Message::Connect))
            .padding(theme::space::MD)
            .width(200),
        ]
        .spacing(theme::space::SM)
        .align_y(Alignment::Center)
        .into()
    }

    fn connection_controls(&self) -> Element<'_, Message> {
        match &self.status {
            ConnectionStatus::Disconnected => self.connect_form(),
            ConnectionStatus::Connecting => theme::muted("Connecting to relay...").into(),
            ConnectionStatus::Connected => button(
                text("Disconnect")
                    .width(Length::Fill)
                    .align_x(Alignment::Center),
            )
            .on_press(Message::Disconnect)
            .style(theme::danger_button)
            .padding(theme::space::MD)
            .width(200)
            .into(),
            ConnectionStatus::Error(e) => column![theme::error_text(e), self.connect_form(),]
                .spacing(theme::space::SM)
                .into(),
        }
    }

    fn peers_section(&self) -> Element<'_, Message> {
        let online_count = self.peers.iter().filter(|p| p.online).count();

        let mut peer_list = column![].spacing(theme::space::XS);

        if self.peers.is_empty() {
            peer_list = peer_list.push(
                text("Waiting for peers...")
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_DIM),
            );
        } else {
            for peer in &self.peers {
                let (dot, color) = if peer.online {
                    ("●", theme::color::SUCCESS)
                } else {
                    ("○", theme::color::TEXT_DIM)
                };
                let name = peer.name.as_deref().unwrap_or("Unknown");

                peer_list = peer_list.push(
                    row![
                        text(dot).size(theme::size::SMALL).color(color),
                        text(format!("#{} {name}", peer.share_index))
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_MUTED),
                    ]
                    .spacing(theme::space::SM)
                    .align_y(Alignment::Center),
                );
            }
        }

        let label = text(format!("Peers ({online_count} online)"))
            .size(theme::size::BODY)
            .color(theme::color::TEXT);

        container(column![label, peer_list].spacing(theme::space::SM))
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn signing_requests_section(&self) -> Element<'_, Message> {
        let mut request_list = column![].spacing(theme::space::SM);

        for req in &self.pending_requests {
            let ts = chrono::DateTime::<chrono::Utc>::from_timestamp(req.timestamp as i64, 0)
                .map(|dt| dt.format("%H:%M:%S").to_string())
                .unwrap_or_default();

            let source = if req.from_peer == 0 {
                "Signing request".to_string()
            } else {
                format!("From peer #{}", req.from_peer)
            };

            let request_card = container(
                column![
                    row![
                        text(source)
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_MUTED),
                        Space::new().width(Length::Fill),
                        text(ts)
                            .size(theme::size::TINY)
                            .color(theme::color::TEXT_DIM),
                    ]
                    .align_y(Alignment::Center),
                    text(format!("Message: {}", req.message_preview))
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_DIM),
                    row![
                        button(text("Approve").size(theme::size::SMALL))
                            .on_press(Message::ApproveSign(req.id.clone()))
                            .style(theme::primary_button)
                            .padding([theme::space::XS, theme::space::MD]),
                        button(text("Reject").size(theme::size::SMALL))
                            .on_press(Message::RejectSign(req.id.clone()))
                            .style(theme::danger_button)
                            .padding([theme::space::XS, theme::space::MD]),
                    ]
                    .spacing(theme::space::SM),
                ]
                .spacing(theme::space::XS),
            )
            .style(theme::warning_style)
            .padding(theme::space::MD)
            .width(Length::Fill);

            request_list = request_list.push(request_card);
        }

        let count = self.pending_requests.len();
        let label = text(format!("Signing Requests ({count})"))
            .size(theme::size::BODY)
            .color(theme::color::TEXT);

        container(column![label, request_list].spacing(theme::space::SM))
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }
}
