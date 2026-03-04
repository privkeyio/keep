// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, VecDeque};

use iced::widget::{button, column, container, qr_code, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::theme;

#[derive(Debug, Clone)]
pub struct ConnectedClient {
    pub pubkey: String,
    pub name: String,
    pub permissions: u32,
    pub auto_approve_kinds: Vec<u16>,
    pub request_count: u64,
    pub duration: String,
    pub duration_seconds: Option<u64>,
    pub connected_at: u64,
}

const PERM_FLAGS: &[(&str, u32)] = &[
    (
        "get_public_key",
        keep_nip46::Permission::GET_PUBLIC_KEY.bits(),
    ),
    ("sign_event", keep_nip46::Permission::SIGN_EVENT.bits()),
    (
        "nip04_encrypt",
        keep_nip46::Permission::NIP04_ENCRYPT.bits(),
    ),
    (
        "nip04_decrypt",
        keep_nip46::Permission::NIP04_DECRYPT.bits(),
    ),
    (
        "nip44_encrypt",
        keep_nip46::Permission::NIP44_ENCRYPT.bits(),
    ),
    (
        "nip44_decrypt",
        keep_nip46::Permission::NIP44_DECRYPT.bits(),
    ),
];

impl ConnectedClient {
    pub fn truncated_pubkey(&self) -> String {
        keep_core::display::truncate_str(&self.pubkey, 8, 6)
    }

    pub fn permission_labels(&self) -> Vec<&'static str> {
        PERM_FLAGS
            .iter()
            .filter(|(_, flag)| self.permissions & flag != 0)
            .map(|(label, _)| *label)
            .collect()
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

impl DurationChoice {
    pub fn to_nip46(self) -> keep_nip46::PermissionDuration {
        match self {
            Self::JustThisTime => keep_nip46::PermissionDuration::Session,
            Self::Minutes(m) => keep_nip46::PermissionDuration::Seconds(m * 60),
            Self::Forever => keep_nip46::PermissionDuration::Forever,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Message {
    RelayInputChanged(String),
    AddRelay,
    RemoveRelay(usize),
    Start,
    Stop,
    Approve,
    Reject,
    RevokeClient(usize),
    ConfirmRevokeAll,
    CancelRevokeAll,
    RevokeAll,
    CopyUrl,
    ToggleClient(usize),
    TogglePermission(usize, u32),
    SetApprovalDuration(usize),
    KindInputChanged(String, String),
    AddKind(String),
    RemoveKind(usize, u16),
    SetClientDuration(usize, usize),
}

pub enum Event {
    AddRelay(String),
    RemoveRelay(usize),
    Start,
    Stop,
    Approve { duration_index: usize },
    Reject,
    RevokeClient(usize),
    RevokeAll,
    CopyUrl,
    TogglePermission(usize, u32),
    UpdateAutoApproveKinds(usize, Vec<u16>),
    SetClientDuration(usize, usize),
}

pub struct State {
    pub running: bool,
    pub url: Option<String>,
    pub qr_data: Option<qr_code::Data>,
    pub relays: Vec<String>,
    relay_input: String,
    pub clients: Vec<ConnectedClient>,
    pub log: VecDeque<LogDisplayEntry>,
    pub pending_approval: Option<PendingApprovalDisplay>,
    revoke_all_confirm: bool,
    pub starting: bool,
    pub error: Option<String>,
    expanded_client: Option<usize>,
    approval_duration: usize,
    kind_inputs: HashMap<String, String>,
}

impl State {
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
            kind_inputs: HashMap::new(),
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
            kind_inputs: HashMap::new(),
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::RelayInputChanged(input) => {
                self.relay_input = input;
                None
            }
            Message::AddRelay => {
                let url = self.relay_input.trim().to_string();
                Some(Event::AddRelay(url))
            }
            Message::RemoveRelay(i) => Some(Event::RemoveRelay(i)),
            Message::Start => Some(Event::Start),
            Message::Stop => Some(Event::Stop),
            Message::Approve => Some(Event::Approve {
                duration_index: self.approval_duration,
            }),
            Message::Reject => Some(Event::Reject),
            Message::RevokeClient(i) => Some(Event::RevokeClient(i)),
            Message::ConfirmRevokeAll => {
                self.revoke_all_confirm = true;
                None
            }
            Message::CancelRevokeAll => {
                self.revoke_all_confirm = false;
                None
            }
            Message::RevokeAll => {
                if self.revoke_all_confirm {
                    self.revoke_all_confirm = false;
                    Some(Event::RevokeAll)
                } else {
                    None
                }
            }
            Message::CopyUrl => Some(Event::CopyUrl),
            Message::ToggleClient(i) => {
                self.expanded_client = if self.expanded_client == Some(i) {
                    None
                } else {
                    Some(i)
                };
                None
            }
            Message::TogglePermission(client_idx, flag) => {
                Some(Event::TogglePermission(client_idx, flag))
            }
            Message::SetApprovalDuration(i) => {
                self.approval_duration = i;
                None
            }
            Message::KindInputChanged(pubkey, input) => {
                self.kind_inputs.insert(pubkey, input);
                None
            }
            Message::AddKind(pubkey) => {
                let input = self.kind_inputs.get(&pubkey).cloned().unwrap_or_default();
                let client_idx = self.clients.iter().position(|c| c.pubkey == pubkey);
                if let Ok(kind) = input.trim().parse::<u16>() {
                    if let Some(idx) = client_idx {
                        let client = &mut self.clients[idx];
                        if !client.auto_approve_kinds.contains(&kind) {
                            client.auto_approve_kinds.push(kind);
                            let kinds = client.auto_approve_kinds.clone();
                            self.kind_inputs.remove(&pubkey);
                            return Some(Event::UpdateAutoApproveKinds(idx, kinds));
                        }
                    }
                }
                self.kind_inputs.remove(&pubkey);
                None
            }
            Message::RemoveKind(client_idx, kind) => {
                if let Some(client) = self.clients.get_mut(client_idx) {
                    client.auto_approve_kinds.retain(|&k| k != kind);
                    let kinds = client.auto_approve_kinds.clone();
                    return Some(Event::UpdateAutoApproveKinds(client_idx, kinds));
                }
                None
            }
            Message::SetClientDuration(client_idx, duration_idx) => {
                Some(Event::SetClientDuration(client_idx, duration_idx))
            }
        }
    }

    pub fn relay_added(&mut self, normalized: String) {
        self.relays.push(normalized);
        self.relay_input.clear();
    }

    pub fn approval_cleared(&mut self) {
        self.pending_approval = None;
        self.approval_duration = 0;
    }

    pub fn view(&self) -> Element<'_, Message> {
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
            if !self.starting && !self.relays.is_empty() {
                btn = btn.on_press(Message::Start);
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
            .on_press(Message::CopyUrl)
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
                remove_btn = remove_btn.on_press(Message::RemoveRelay(i));
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
                add_btn = add_btn.on_press(Message::AddRelay);
            }

            let mut input = text_input("wss://relay.example.com", &self.relay_input)
                .on_input(Message::RelayInputChanged)
                .size(theme::size::SMALL)
                .width(Length::Fill);
            if can_add {
                input = input.on_submit(Message::AddRelay);
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
                .on_press(Message::ToggleClient(i))
                .style(theme::text_button)
                .padding([theme::space::XS, 0.0])
                .width(Length::Fill),
                button(text("Revoke").size(theme::size::TINY))
                    .on_press(Message::RevokeClient(i))
                    .style(theme::danger_button)
                    .padding([2.0, theme::space::SM]),
            ]
            .align_y(Alignment::Center);

            if is_expanded {
                let mut perm_toggles = column![].spacing(theme::space::XS);
                for &(label, flag) in PERM_FLAGS {
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
                            .on_press(Message::TogglePermission(i, flag))
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

                perm_toggles = perm_toggles.push(
                    text("Auto-approve kinds")
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT),
                );

                let mut kinds_row = row![].spacing(4.0).align_y(Alignment::Center);
                for &kind in &client.auto_approve_kinds {
                    kinds_row = kinds_row.push(
                        button(text(format!("{kind} x")).size(theme::size::TINY))
                            .on_press(Message::RemoveKind(i, kind))
                            .style(theme::secondary_button)
                            .padding([2.0, theme::space::SM]),
                    );
                }
                if client.auto_approve_kinds.is_empty() {
                    kinds_row = kinds_row.push(
                        text("None")
                            .size(theme::size::TINY)
                            .color(theme::color::TEXT_DIM),
                    );
                }
                perm_toggles = perm_toggles.push(kinds_row);

                let kind_input_val = self
                    .kind_inputs
                    .get(&client.pubkey)
                    .cloned()
                    .unwrap_or_default();
                let can_add = kind_input_val.trim().parse::<u16>().is_ok();
                let pk = client.pubkey.clone();
                let pk2 = client.pubkey.clone();
                let mut add_kind_btn = button(text("Add").size(theme::size::TINY))
                    .style(theme::primary_button)
                    .padding([2.0, theme::space::SM]);
                if can_add {
                    add_kind_btn = add_kind_btn.on_press(Message::AddKind(pk.clone()));
                }
                let mut kind_input = text_input("Kind number", &kind_input_val)
                    .on_input(move |s| Message::KindInputChanged(pk2.clone(), s))
                    .size(theme::size::TINY)
                    .width(100.0);
                if can_add {
                    kind_input = kind_input.on_submit(Message::AddKind(pk));
                }
                perm_toggles = perm_toggles.push(
                    row![kind_input, add_kind_btn]
                        .spacing(theme::space::SM)
                        .align_y(Alignment::Center),
                );

                let mut duration_row = row![
                    text("Duration:")
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT),
                    Space::new().width(theme::space::SM),
                ]
                .align_y(Alignment::Center);

                for (idx, (label, choice)) in DURATION_OPTIONS.iter().enumerate() {
                    let is_current = match choice {
                        DurationChoice::JustThisTime => client.duration == "Session",
                        DurationChoice::Forever => client.duration == "Forever",
                        DurationChoice::Minutes(m) => client.duration_seconds == Some(*m * 60),
                    };
                    let style = if is_current {
                        theme::primary_button
                    } else {
                        theme::secondary_button
                    };
                    duration_row = duration_row.push(
                        button(text(*label).size(theme::size::TINY))
                            .on_press(Message::SetClientDuration(i, idx))
                            .style(style)
                            .padding([2.0, theme::space::SM]),
                    );
                    duration_row = duration_row.push(Space::new().width(2.0));
                }
                perm_toggles = perm_toggles.push(scrollable(duration_row).direction(
                    scrollable::Direction::Horizontal(scrollable::Scrollbar::default()),
                ));

                if let Some(secs) = client.duration_seconds {
                    let expires_at = client.connected_at.saturating_add(secs);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if now < expires_at {
                        let remaining = expires_at - now;
                        let display = if remaining < 60 {
                            format!("Expires in {remaining}s")
                        } else if remaining < 3600 {
                            format!("Expires in {}m", remaining / 60)
                        } else if remaining < 86400 {
                            format!(
                                "Expires in {}h {}m",
                                remaining / 3600,
                                (remaining % 3600) / 60
                            )
                        } else {
                            format!("Expires in {}d", remaining / 86400)
                        };
                        perm_toggles = perm_toggles.push(
                            text(display)
                                .size(theme::size::TINY)
                                .color(theme::color::TEXT_MUTED),
                        );
                    } else {
                        perm_toggles = perm_toggles.push(
                            text("Expired")
                                .size(theme::size::TINY)
                                .color(theme::color::ERROR),
                        );
                    }
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
                    .on_press(Message::RevokeAll)
                    .style(theme::danger_button)
                    .padding([theme::space::XS, theme::space::MD]),
                button(text("No").size(theme::size::BODY))
                    .on_press(Message::CancelRevokeAll)
                    .style(theme::secondary_button)
                    .padding([theme::space::XS, theme::space::MD]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center)
        } else {
            row![
                Space::new().width(Length::Fill),
                button(text("Revoke All").size(theme::size::SMALL))
                    .on_press(Message::ConfirmRevokeAll)
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
            let sanitized: String = content
                .chars()
                .filter(|c| {
                    !matches!(c,
                        '\u{200B}'..='\u{200F}' |
                        '\u{202A}'..='\u{202E}' |
                        '\u{2066}'..='\u{2069}' |
                        '\u{FEFF}'
                    ) && (!c.is_control() || matches!(c, '\n' | '\t'))
                })
                .collect();
            let preview = if sanitized.chars().count() > 200 {
                let truncated: String = sanitized.chars().take(200).collect();
                format!("{truncated}...")
            } else {
                sanitized
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
                    .on_press(Message::SetApprovalDuration(idx))
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
