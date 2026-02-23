// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::VecDeque;

use iced::widget::{button, column, container, qr_code, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::theme;

#[derive(Debug, Clone)]
pub struct ConnectedClient {
    pub pubkey: String,
    pub name: String,
    pub permissions: u32,
    pub auto_approve_kinds: Vec<u16>,
    pub request_count: u64,
    pub duration: String,
}

impl ConnectedClient {
    pub fn truncated_pubkey(&self) -> String {
        if self.pubkey.len() <= 16 {
            return self.pubkey.clone();
        }
        format!(
            "{}...{}",
            &self.pubkey[..8],
            &self.pubkey[self.pubkey.len() - 6..]
        )
    }

    pub fn permission_labels(&self) -> Vec<&'static str> {
        let mut labels = Vec::new();
        if self.permissions & 0b00000001 != 0 {
            labels.push("get_public_key");
        }
        if self.permissions & 0b00000010 != 0 {
            labels.push("sign_event");
        }
        if self.permissions & 0b00000100 != 0 {
            labels.push("nip04_encrypt");
        }
        if self.permissions & 0b00001000 != 0 {
            labels.push("nip04_decrypt");
        }
        if self.permissions & 0b00010000 != 0 {
            labels.push("nip44_encrypt");
        }
        if self.permissions & 0b00100000 != 0 {
            labels.push("nip44_decrypt");
        }
        labels
    }
}

#[derive(Debug, Clone)]
pub struct PendingApprovalDisplay {
    pub app_pubkey: String,
    pub app_name: String,
    pub method: String,
    pub event_kind: Option<u32>,
    pub event_content: Option<String>,
    pub requested_permissions: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogDisplayEntry {
    pub app: String,
    pub action: String,
    pub success: bool,
}

pub const DURATION_OPTIONS: &[(&str, DurationChoice)] = &[
    ("This session", DurationChoice::JustThisTime),
    ("15 minutes", DurationChoice::Minutes(15)),
    ("1 hour", DurationChoice::Minutes(60)),
    ("1 day", DurationChoice::Minutes(1440)),
    ("1 week", DurationChoice::Minutes(10080)),
    ("Forever", DurationChoice::Forever),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationChoice {
    JustThisTime,
    Minutes(u64),
    Forever,
}

pub struct BunkerScreen {
    pub running: bool,
    pub url: Option<String>,
    pub qr_data: Option<qr_code::Data>,
    pub relays: Vec<String>,
    pub relay_input: String,
    pub clients: Vec<ConnectedClient>,
    pub log: VecDeque<LogDisplayEntry>,
    pub pending_approval: Option<PendingApprovalDisplay>,
    pub revoke_all_confirm: bool,
    pub starting: bool,
    pub error: Option<String>,
    pub expanded_client: Option<usize>,
    pub approval_duration: usize,
}

impl BunkerScreen {
    pub fn new(relays: Vec<String>) -> Self {
        Self {
            running: false,
            url: None,
            qr_data: None,
            relays,
            relay_input: String::new(),
            clients: Vec::new(),
            log: VecDeque::new(),
            pending_approval: None,
            revoke_all_confirm: false,
            starting: false,
            error: None,
            expanded_client: None,
            approval_duration: 0,
        }
    }

    pub fn with_state(
        running: bool,
        url: Option<String>,
        relays: Vec<String>,
        clients: Vec<ConnectedClient>,
        log: VecDeque<LogDisplayEntry>,
        pending_approval: Option<PendingApprovalDisplay>,
    ) -> Self {
        let qr_data = url.as_deref().and_then(|u| qr_code::Data::new(u).ok());
        Self {
            running,
            url,
            qr_data,
            relays,
            relay_input: String::new(),
            clients,
            log,
            pending_approval,
            revoke_all_confirm: false,
            starting: false,
            error: None,
            expanded_client: None,
            approval_duration: 0,
        }
    }

    pub fn view_content(&self) -> Element<'_, Message> {
        let title = theme::heading("Nostr Connect");

        let mut content = column![title].spacing(theme::space::MD);

        if let Some(ref approval) = self.pending_approval {
            content = content.push(self.approval_card(approval));
        }

        content = content.push(self.status_card());

        if let Some(ref url) = self.url {
            content = content.push(self.connection_card(url));
        }

        content = content.push(self.relay_card());

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
            .on_press(Message::BunkerStop)
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
            if !self.starting && !self.relays.is_empty() {
                btn = btn.on_press(Message::BunkerStart);
            }
            btn
        };

        let header = row![
            text("Bunker")
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
            Space::new().width(theme::space::SM),
            badge,
            Space::new().width(Length::Fill),
            action_btn,
        ]
        .align_y(Alignment::Center);

        let mut card = column![header].spacing(theme::space::SM);

        if let Some(ref err) = self.error {
            card = card.push(theme::error_text(err));
        }

        container(card)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn connection_card<'a>(&'a self, url: &'a str) -> Element<'a, Message> {
        let qr: Element<Message> = match self.qr_data {
            Some(ref data) => qr_code::<iced::Theme>(data).cell_size(4).into(),
            None => text("Failed to generate QR code")
                .size(theme::size::SMALL)
                .color(theme::color::ERROR)
                .into(),
        };

        let url_display = text(url)
            .size(theme::size::TINY)
            .color(theme::color::TEXT_MUTED);

        let copy_btn = button(text("Copy URL").size(theme::size::SMALL))
            .on_press(Message::BunkerCopyUrl)
            .style(theme::secondary_button)
            .padding([theme::space::XS, theme::space::MD]);

        let url_row = row![url_display, Space::new().width(Length::Fill), copy_btn]
            .align_y(Alignment::Center)
            .spacing(theme::space::SM);

        container(
            column![
                text("Connection")
                    .size(theme::size::HEADING)
                    .color(theme::color::TEXT),
                container(qr).center_x(Length::Fill),
                url_row,
            ]
            .spacing(theme::space::MD),
        )
        .style(theme::card_style)
        .padding(theme::space::LG)
        .width(Length::Fill)
        .into()
    }

    fn relay_card(&self) -> Element<'_, Message> {
        let mut relay_list = column![].spacing(theme::space::XS);
        for (i, relay) in self.relays.iter().enumerate() {
            let mut remove_btn = button(text("x").size(theme::size::SMALL))
                .style(theme::text_button)
                .padding([2.0, theme::space::SM]);
            if !self.running {
                remove_btn = remove_btn.on_press(Message::BunkerRemoveRelay(i));
            }

            relay_list = relay_list.push(
                row![
                    text(relay)
                        .size(theme::size::SMALL)
                        .color(theme::color::TEXT_MUTED),
                    Space::new().width(Length::Fill),
                    remove_btn,
                ]
                .align_y(Alignment::Center),
            );
        }

        let mut card = column![
            text("Relays")
                .size(theme::size::HEADING)
                .color(theme::color::TEXT),
            relay_list,
        ]
        .spacing(theme::space::SM);

        if !self.running {
            let can_add = !self.relay_input.is_empty()
                && self.relay_input.starts_with("wss://")
                && self.relays.len() < 5;

            let mut add_btn = button(text("Add").size(theme::size::SMALL))
                .style(theme::primary_button)
                .padding([theme::space::XS, theme::space::MD]);
            if can_add {
                add_btn = add_btn.on_press(Message::BunkerAddRelay);
            }

            let mut input = text_input("wss://relay.example.com", &self.relay_input)
                .on_input(Message::BunkerRelayInputChanged)
                .size(theme::size::SMALL)
                .width(Length::Fill);
            if can_add {
                input = input.on_submit(Message::BunkerAddRelay);
            }

            card = card.push(
                row![input, add_btn]
                    .spacing(theme::space::SM)
                    .align_y(Alignment::Center),
            );
        }

        container(card)
            .style(theme::card_style)
            .padding(theme::space::LG)
            .width(Length::Fill)
            .into()
    }

    fn clients_card(&self) -> Element<'_, Message> {
        let mut client_list = column![].spacing(theme::space::SM);
        for (i, client) in self.clients.iter().enumerate() {
            let is_expanded = self.expanded_client == Some(i);
            let perms_summary = client.permission_labels().join(", ");

            let header = row![
                button(
                    column![
                        row![
                            text(&client.name)
                                .size(theme::size::SMALL)
                                .color(theme::color::TEXT),
                            Space::new().width(theme::space::SM),
                            text(client.truncated_pubkey())
                                .size(theme::size::TINY)
                                .color(theme::color::TEXT_DIM),
                        ]
                        .align_y(Alignment::Center),
                        row![
                            text(perms_summary)
                                .size(theme::size::TINY)
                                .color(theme::color::TEXT_MUTED),
                            Space::new().width(theme::space::SM),
                            text(format!("{} req", client.request_count))
                                .size(theme::size::TINY)
                                .color(theme::color::TEXT_DIM),
                            Space::new().width(theme::space::SM),
                            text(&client.duration)
                                .size(theme::size::TINY)
                                .color(theme::color::TEXT_DIM),
                        ]
                        .align_y(Alignment::Center),
                    ]
                    .spacing(2.0),
                )
                .on_press(Message::BunkerToggleClient(i))
                .style(theme::text_button)
                .padding([theme::space::XS, 0.0])
                .width(Length::Fill),
                button(text("Revoke").size(theme::size::TINY))
                    .on_press(Message::BunkerRevokeClient(i))
                    .style(theme::danger_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .align_y(Alignment::Center);

            if is_expanded {
                let mut perm_toggles = column![].spacing(theme::space::XS);
                let perm_flags = [
                    ("get_public_key", 0b00000001u32),
                    ("sign_event", 0b00000010),
                    ("nip04_encrypt", 0b00000100),
                    ("nip04_decrypt", 0b00001000),
                    ("nip44_encrypt", 0b00010000),
                    ("nip44_decrypt", 0b00100000),
                ];
                for (label, flag) in perm_flags {
                    let enabled = client.permissions & flag != 0;
                    let badge_style = if enabled {
                        theme::badge_style
                    } else {
                        theme::card_style
                    };
                    let status_text = if enabled { "Allowed" } else { "Denied" };
                    let status_color = if enabled {
                        theme::color::SUCCESS
                    } else {
                        theme::color::TEXT_DIM
                    };

                    perm_toggles = perm_toggles.push(
                        row![
                            text(label)
                                .size(theme::size::TINY)
                                .color(theme::color::TEXT)
                                .width(Length::FillPortion(2)),
                            container(
                                text(status_text)
                                    .size(theme::size::TINY)
                                    .color(status_color),
                            )
                            .style(badge_style)
                            .padding([2.0, theme::space::SM]),
                            Space::new().width(theme::space::XS),
                            button(
                                text(if enabled { "Deny" } else { "Allow" })
                                    .size(theme::size::TINY),
                            )
                            .on_press(Message::BunkerTogglePermission(i, flag))
                            .style(if enabled {
                                theme::secondary_button
                            } else {
                                theme::primary_button
                            })
                            .padding([2.0, theme::space::SM]),
                        ]
                        .align_y(Alignment::Center),
                    );
                }

                if !client.auto_approve_kinds.is_empty() {
                    let kinds_str: Vec<String> = client
                        .auto_approve_kinds
                        .iter()
                        .map(|k| k.to_string())
                        .collect();
                    perm_toggles = perm_toggles.push(
                        text(format!("Auto-approve kinds: {}", kinds_str.join(", ")))
                            .size(theme::size::TINY)
                            .color(theme::color::TEXT_MUTED),
                    );
                }

                let detail = container(perm_toggles)
                    .padding([theme::space::XS, theme::space::LG])
                    .width(Length::Fill);

                client_list = client_list.push(column![header, detail].spacing(2.0));
            } else {
                client_list = client_list.push(header);
            }
        }

        let actions = if self.revoke_all_confirm {
            row![
                text("Revoke all clients?")
                    .size(theme::size::BODY)
                    .color(theme::color::ERROR),
                Space::new().width(Length::Fill),
                button(text("Yes").size(theme::size::BODY))
                    .on_press(Message::BunkerRevokeAll)
                    .style(theme::danger_button)
                    .padding([theme::space::XS, theme::space::MD]),
                button(text("No").size(theme::size::BODY))
                    .on_press(Message::BunkerCancelRevokeAll)
                    .style(theme::secondary_button)
                    .padding([theme::space::XS, theme::space::MD]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center)
        } else {
            row![
                Space::new().width(Length::Fill),
                button(text("Revoke All").size(theme::size::SMALL))
                    .on_press(Message::BunkerConfirmRevokeAll)
                    .style(theme::danger_button)
                    .padding([theme::space::XS, theme::space::MD]),
            ]
            .align_y(Alignment::Center)
        };

        container(
            column![
                text("Connected Clients")
                    .size(theme::size::HEADING)
                    .color(theme::color::TEXT),
                client_list,
                actions,
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

        if let Some(ref perms) = approval.requested_permissions {
            details = details.push(
                text(format!("Permissions: {perms}"))
                    .size(theme::size::SMALL)
                    .color(theme::color::TEXT_MUTED),
            );
        }

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

        let mut duration_row = row![
            text("Remember:")
                .size(theme::size::TINY)
                .color(theme::color::TEXT_MUTED),
            Space::new().width(theme::space::SM),
        ]
        .align_y(Alignment::Center);

        for (idx, (label, _)) in DURATION_OPTIONS.iter().enumerate() {
            let is_selected = self.approval_duration == idx;
            let style = if is_selected {
                theme::primary_button
            } else {
                theme::secondary_button
            };
            duration_row = duration_row.push(
                button(text(*label).size(theme::size::TINY))
                    .on_press(Message::BunkerSetApprovalDuration(idx))
                    .style(style)
                    .padding([2.0, theme::space::SM]),
            );
            duration_row = duration_row.push(Space::new().width(2.0));
        }

        let buttons = row![
            button(
                text("Approve")
                    .width(Length::Fill)
                    .align_x(Alignment::Center),
            )
            .on_press(Message::BunkerApprove)
            .style(theme::primary_button)
            .padding([theme::space::SM, theme::space::LG])
            .width(Length::FillPortion(1)),
            button(
                text("Reject")
                    .width(Length::Fill)
                    .align_x(Alignment::Center),
            )
            .on_press(Message::BunkerReject)
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
                scrollable(duration_row).direction(scrollable::Direction::Horizontal(
                    scrollable::Scrollbar::default(),
                )),
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
