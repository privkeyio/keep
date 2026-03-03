// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::VecDeque;

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};

use crate::theme;

#[derive(Debug, Clone)]
pub struct ConnectedClient {
    pub client_id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct PendingApprovalDisplay {
    pub app_name: String,
    pub method: String,
    pub event_kind: Option<u32>,
    pub event_content: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogDisplayEntry {
    pub app: String,
    pub action: String,
    pub success: bool,
}

#[derive(Clone, Debug)]
pub enum Message {
    Start,
    Stop,
    Approve,
    Reject,
    RevokeClient(usize),
    CopyPath,
}

pub enum Event {
    Start,
    Stop,
    Approve,
    Reject,
    RevokeClient(usize),
    CopyPath,
}

pub struct State {
    pub running: bool,
    pub starting: bool,
    pub socket_path: Option<String>,
    pub clients: Vec<ConnectedClient>,
    pub log: VecDeque<LogDisplayEntry>,
    pub pending_approval: Option<PendingApprovalDisplay>,
    pub error: Option<String>,
}

impl State {
    pub fn new() -> Self {
        Self {
            running: false,
            starting: false,
            socket_path: None,
            clients: Vec::new(),
            log: VecDeque::new(),
            pending_approval: None,
            error: None,
        }
    }

    pub fn with_state(
        running: bool,
        socket_path: Option<String>,
        clients: Vec<ConnectedClient>,
        log: VecDeque<LogDisplayEntry>,
        pending_approval: Option<PendingApprovalDisplay>,
    ) -> Self {
        Self {
            running,
            starting: false,
            socket_path,
            clients,
            log,
            pending_approval,
            error: None,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::Start => Some(Event::Start),
            Message::Stop => Some(Event::Stop),
            Message::Approve => Some(Event::Approve),
            Message::Reject => Some(Event::Reject),
            Message::RevokeClient(i) => Some(Event::RevokeClient(i)),
            Message::CopyPath => Some(Event::CopyPath),
        }
    }

    pub fn approval_cleared(&mut self) {
        self.pending_approval = None;
    }

    pub fn view(&self) -> Element<'_, Message> {
        let title = theme::heading("Local Signer");

        let mut content = column![title].spacing(theme::space::MD);

        if let Some(ref approval) = self.pending_approval {
            content = content.push(self.approval_card(approval));
        }

        content = content.push(self.status_card());

        if let Some(ref path) = self.socket_path {
            content = content.push(self.socket_card(path));
        }

        if self.running && !self.clients.is_empty() {
            content = content.push(self.clients_card());
        }

        if !self.log.is_empty() {
            content = content.push(self.log_card());
        }

        container(scrollable(content).height(Length::Fill))
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn status_card(&self) -> Element<'_, Message> {
        let status_text = if self.starting {
            "Starting..."
        } else if self.running {
            "Running"
        } else {
            "Stopped"
        };

        let status_color = if self.running {
            theme::color::SUCCESS
        } else if self.starting {
            theme::color::TEXT_MUTED
        } else {
            theme::color::TEXT_DIM
        };

        let badge = container(
            text(status_text)
                .size(theme::size::TINY)
                .color(status_color),
        )
        .style(if self.running {
            theme::badge_style
        } else {
            theme::card_style
        })
        .padding([2.0, theme::space::SM]);

        let action_btn = if self.running {
            button(
                text("Stop")
                    .width(Length::Shrink)
                    .align_x(Alignment::Center),
            )
            .on_press(Message::Stop)
            .style(theme::danger_button)
            .padding([theme::space::XS, theme::space::LG])
        } else {
            let mut btn = button(
                text("Start")
                    .width(Length::Shrink)
                    .align_x(Alignment::Center),
            )
            .style(theme::primary_button)
            .padding([theme::space::XS, theme::space::LG]);
            if !self.starting {
                btn = btn.on_press(Message::Start);
            }
            btn
        };

        let header = row![
            text("Local Signer")
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
            Space::new().width(theme::space::SM),
            badge,
            Space::new().width(Length::Fill),
            action_btn,
        ]
        .align_y(Alignment::Center);

        let mut card = column![header].spacing(theme::space::SM);

        let desc = text(
            "Unix socket signer for local Nostr clients. \
             Apps connect to the socket to request signatures without direct key access.",
        )
        .size(theme::size::SMALL)
        .color(theme::color::TEXT_MUTED);
        card = card.push(desc);

        if let Some(ref err) = self.error {
            card = card.push(theme::error_text(err));
        }

        container(card)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn socket_card<'a>(&'a self, path: &'a str) -> Element<'a, Message> {
        let path_display = text(path)
            .size(theme::size::TINY)
            .color(theme::color::TEXT_MUTED);

        let copy_btn = button(text("Copy Path").size(theme::size::SMALL))
            .on_press(Message::CopyPath)
            .style(theme::secondary_button)
            .padding([theme::space::XS, theme::space::MD]);

        let path_row = row![path_display, Space::new().width(Length::Fill), copy_btn]
            .align_y(Alignment::Center)
            .spacing(theme::space::SM);

        container(
            column![
                text("Socket")
                    .size(theme::size::HEADING)
                    .color(theme::color::TEXT),
                path_row,
            ]
            .spacing(theme::space::MD),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill)
        .into()
    }

    fn clients_card(&self) -> Element<'_, Message> {
        let mut client_list = column![].spacing(theme::space::SM);
        for (i, client) in self.clients.iter().enumerate() {
            let header = row![
                text(&client.name)
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT),
                Space::new().width(theme::space::SM),
                text(&client.client_id)
                    .size(theme::size::TINY)
                    .color(theme::color::TEXT_DIM),
                Space::new().width(Length::Fill),
                button(text("Revoke").size(theme::size::TINY))
                    .on_press(Message::RevokeClient(i))
                    .style(theme::danger_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .align_y(Alignment::Center);

            client_list = client_list.push(header);
        }

        container(
            column![
                text("Connected Clients")
                    .size(theme::size::HEADING)
                    .color(theme::color::TEXT),
                client_list,
            ]
            .spacing(theme::space::SM),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill)
        .into()
    }

    fn approval_card(&self, approval: &PendingApprovalDisplay) -> Element<'_, Message> {
        let mut details = column![text(format!(
            "{} requests: {}",
            approval.app_name, approval.method
        ))
        .size(theme::size::BODY)
        .color(theme::color::TEXT),]
        .spacing(theme::space::XS);

        if let Some(kind) = approval.event_kind {
            details = details.push(
                text(format!("Kind: {kind}"))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );
        }

        if let Some(ref content) = approval.event_content {
            let preview = if content.chars().count() > 200 {
                let truncated: String = content.chars().take(200).collect();
                format!("{truncated}...")
            } else {
                content.clone()
            };
            details = details.push(
                text(preview)
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );
        }

        let buttons = row![
            button(
                text("Approve")
                    .width(Length::Fill)
                    .align_x(Alignment::Center),
            )
            .on_press(Message::Approve)
            .style(theme::primary_button)
            .padding([theme::space::SM, theme::space::LG])
            .width(Length::FillPortion(1)),
            button(
                text("Reject")
                    .width(Length::Fill)
                    .align_x(Alignment::Center),
            )
            .on_press(Message::Reject)
            .style(theme::danger_button)
            .padding([theme::space::SM, theme::space::LG])
            .width(Length::FillPortion(1)),
        ]
        .spacing(theme::space::MD);

        container(
            column![
                text("Approval Request")
                    .size(theme::size::HEADING)
                    .color(theme::color::TEXT),
                details,
                buttons,
            ]
            .spacing(theme::space::MD),
        )
        .style(theme::warning_style)
        .padding(theme::space::LG)
        .width(Length::Fill)
        .into()
    }

    fn log_card(&self) -> Element<'_, Message> {
        let mut entries = column![].spacing(2.0);
        for entry in self.log.iter().rev().take(20) {
            let icon = if entry.success { "+" } else { "x" };
            let color = if entry.success {
                theme::color::TEXT_DIM
            } else {
                theme::color::ERROR
            };
            entries = entries.push(
                text(format!("{icon} {} {}", entry.app, entry.action))
                    .size(theme::size::TINY)
                    .color(color),
            );
        }

        container(
            column![
                text("Activity")
                    .size(theme::size::HEADING)
                    .color(theme::color::TEXT),
                entries,
            ]
            .spacing(theme::space::SM),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill)
        .into()
    }
}
