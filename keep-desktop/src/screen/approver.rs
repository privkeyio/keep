// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::collections::VecDeque;
use std::fmt;

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};
use keep_mobile::{ApprovalField, ApprovalRequest, ApproverStatus};

use crate::theme;

pub const MAX_LOG: usize = 100;

#[derive(Clone)]
pub enum Message {
    LinkChanged(String),
    Pair,
    Approve(String),
    Deny(String),
    FreezeAll,
    UnfreezeAll,
    Forget,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkChanged(_) => f.write_str("LinkChanged(***)"),
            Self::Pair => f.write_str("Pair"),
            Self::Approve(id) => f.debug_tuple("Approve").field(id).finish(),
            Self::Deny(id) => f.debug_tuple("Deny").field(id).finish(),
            Self::FreezeAll => f.write_str("FreezeAll"),
            Self::UnfreezeAll => f.write_str("UnfreezeAll"),
            Self::Forget => f.write_str("Forget"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Pair(String),
    Approve(String),
    Deny(String),
    FreezeAll,
    UnfreezeAll,
    Forget,
}

pub struct State {
    pub link: String,
    pub busy: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub status: Option<ApproverStatus>,
    pub waiting: Vec<ApprovalRequest>,
    pub log: VecDeque<String>,
}

impl State {
    pub fn new(
        status: Option<ApproverStatus>,
        waiting: Vec<ApprovalRequest>,
        log: VecDeque<String>,
    ) -> Self {
        Self {
            link: String::new(),
            busy: false,
            error: None,
            notice: None,
            status,
            waiting,
            log,
        }
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        let event = match message {
            Message::LinkChanged(link) => {
                self.link = link;
                return None;
            }
            Message::Pair => {
                let link = self.link.trim();
                if link.is_empty() {
                    return None;
                }
                Event::Pair(link.to_string())
            }
            Message::Approve(id) => Event::Approve(id),
            Message::Deny(id) => Event::Deny(id),
            Message::FreezeAll => Event::FreezeAll,
            Message::UnfreezeAll => Event::UnfreezeAll,
            Message::Forget => Event::Forget,
        };
        if self.busy {
            return None;
        }
        self.busy = true;
        self.error = None;
        self.notice = None;
        Some(event)
    }

    pub fn action_done(&mut self, result: Result<String, String>) {
        self.busy = false;
        match result {
            Ok(notice) => {
                self.link.clear();
                self.notice = Some(notice);
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn has_pairing(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.paired || s.pairing)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let banner = container(
            text("Test approver: pairs only with a gateway built for end-to-end tests. Not for real use.")
                .size(theme::size::SMALL)
                .color(iced::Color::WHITE),
        )
        .style(theme::kill_switch_banner_style)
        .padding(theme::space::SM)
        .width(Length::Fill);

        let mut content =
            column![theme::heading("Test Approver"), banner].spacing(theme::space::MD);

        if let Some(e) = &self.error {
            content = content.push(theme::error_text(e));
        }
        if let Some(n) = &self.notice {
            content = content.push(theme::success_text(n));
        }

        if self.has_pairing() {
            content = content.push(self.status_card());
            content = content.push(self.controls());
            if self.waiting.is_empty() {
                content = content.push(theme::muted("No requests waiting"));
            }
            for request in &self.waiting {
                content = content.push(self.request_card(request));
            }
        } else {
            content = content.push(self.pair_form());
        }

        content = content.push(self.log_view());

        scrollable(content.padding(theme::space::LG).width(Length::Fill))
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn pair_form(&self) -> Element<'_, Message> {
        let can_pair = !self.busy && !self.link.trim().is_empty();
        column![
            theme::label("Pairing link from `keep gateway approver pair`"),
            row![
                text_input("Pairing link", &self.link)
                    .on_input(Message::LinkChanged)
                    .on_submit(Message::Pair)
                    .size(theme::size::SMALL)
                    .width(Length::Fill),
                button(
                    text(if self.busy { "Pairing..." } else { "Pair" }).size(theme::size::SMALL)
                )
                .style(theme::primary_button)
                .on_press_maybe(can_pair.then_some(Message::Pair))
                .padding([theme::space::SM, theme::space::MD]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center),
        ]
        .spacing(theme::space::XS)
        .into()
    }

    fn status_card(&self) -> Element<'_, Message> {
        let Some(status) = &self.status else {
            return Space::new().into();
        };
        let mut col = column![
            text(format!(
                "Fingerprint: {}",
                status.fingerprint.as_deref().unwrap_or("unknown")
            ))
            .size(theme::size::BODY)
            .color(theme::color::TEXT),
            theme::muted("Compare it with what `keep gateway approver pair` prints."),
            text(status_line(status))
                .size(theme::size::SMALL)
                .color(theme::color::TEXT),
        ]
        .spacing(theme::space::XS);
        if status.all_frozen {
            col = col.push(
                text("Every agent is frozen")
                    .size(theme::size::SMALL)
                    .color(theme::color::DANGER),
            );
        }
        if let Some(e) = &status.last_error {
            col = col.push(theme::error_text(e));
        }
        if status.silent {
            col = col.push(
                text("No anchor from the gateway for an hour")
                    .size(theme::size::SMALL)
                    .color(theme::color::WARNING),
            );
        }
        for alert in &status.alerts {
            col = col.push(
                text(format!("Alert: {}", alert.message))
                    .size(theme::size::SMALL)
                    .color(theme::color::DANGER),
            );
        }
        container(col)
            .style(theme::card_style)
            .padding(theme::space::MD)
            .width(Length::Fill)
            .into()
    }

    fn controls(&self) -> Element<'_, Message> {
        let paired = self.status.as_ref().is_some_and(|s| s.paired);
        let idle = !self.busy;
        row![
            button(text("Freeze all").size(theme::size::SMALL))
                .style(theme::danger_button)
                .on_press_maybe((idle && paired).then_some(Message::FreezeAll))
                .padding([theme::space::SM, theme::space::MD]),
            button(text("Unfreeze all").size(theme::size::SMALL))
                .style(theme::secondary_button)
                .on_press_maybe((idle && paired).then_some(Message::UnfreezeAll))
                .padding([theme::space::SM, theme::space::MD]),
            Space::new().width(Length::Fill),
            button(text("Forget pairing").size(theme::size::SMALL))
                .style(theme::secondary_button)
                .on_press_maybe(idle.then_some(Message::Forget))
                .padding([theme::space::SM, theme::space::MD]),
        ]
        .spacing(theme::space::SM)
        .align_y(Alignment::Center)
        .into()
    }

    fn request_card<'a>(&self, request: &'a ApprovalRequest) -> Element<'a, Message> {
        let mut col = column![
            text(request_header(request))
                .size(theme::size::BODY)
                .color(theme::color::TEXT),
            text(&request.reason)
                .size(theme::size::SMALL)
                .color(theme::color::TEXT_MUTED),
        ]
        .spacing(theme::space::XS);
        for warning in &request.warnings {
            col = col.push(
                text(warning)
                    .size(theme::size::SMALL)
                    .color(theme::color::DANGER),
            );
        }
        for field in &request.fields {
            let color = if field.by_agent {
                theme::color::WARNING
            } else {
                theme::color::TEXT
            };
            col = col.push(
                text(field_line(field))
                    .size(theme::size::SMALL)
                    .color(color),
            );
        }
        let idle = !self.busy;
        col = col.push(
            row![
                button(text("Approve").size(theme::size::SMALL))
                    .style(theme::primary_button)
                    .on_press_maybe(idle.then(|| Message::Approve(request.request_id.clone())))
                    .padding([theme::space::SM, theme::space::MD]),
                button(text("Deny").size(theme::size::SMALL))
                    .style(theme::danger_button)
                    .on_press_maybe(idle.then(|| Message::Deny(request.request_id.clone())))
                    .padding([theme::space::SM, theme::space::MD]),
            ]
            .spacing(theme::space::SM),
        );
        container(col)
            .style(theme::warning_style)
            .padding(theme::space::MD)
            .width(Length::Fill)
            .into()
    }

    fn log_view(&self) -> Element<'_, Message> {
        let lines = self
            .log
            .iter()
            .rev()
            .fold(column![].spacing(2.0), |col, line| {
                col.push(
                    text(line)
                        .size(theme::size::TINY)
                        .color(theme::color::TEXT_MUTED),
                )
            });
        column![
            theme::label("Event log"),
            container(scrollable(lines).width(Length::Fill))
                .style(theme::card_style)
                .padding(theme::space::SM)
                .width(Length::Fill)
                .max_height(240.0),
        ]
        .spacing(theme::space::XS)
        .into()
    }
}

pub fn push_log(log: &mut VecDeque<String>, lines: Vec<String>) {
    log.extend(lines);
    while log.len() > MAX_LOG {
        log.pop_front();
    }
}

fn status_line(status: &ApproverStatus) -> String {
    let state = if status.paired {
        "paired"
    } else if status.pairing {
        "waiting for the gateway to answer the pairing"
    } else {
        "not paired"
    };
    let running = if status.running { "running" } else { "stopped" };
    let epoch = status
        .epoch
        .map_or_else(|| "no anchor yet".to_string(), |e| format!("epoch {e}"));
    format!("Status: {state}, {running}, {epoch}")
}

fn request_header(request: &ApprovalRequest) -> String {
    let credential = request.credential.as_deref().unwrap_or("no credential");
    format!(
        "{} from {credential}, {}s left",
        request.op, request.seconds_left
    )
}

fn field_line(field: &ApprovalField) -> String {
    let mut line = format!("{}: {}", field.label, field.value);
    if field.by_agent {
        line.push_str(" [written by the agent]");
    }
    if field.truncated {
        line.push_str(&format!(" [cut short, {} characters]", field.chars));
    }
    if field.removed > 0 {
        line.push_str(&format!(" [{} hidden characters removed]", field.removed));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State::new(None, Vec::new(), VecDeque::new())
    }

    #[test]
    fn pair_needs_a_link_and_trims_it() {
        let mut s = state();
        assert_eq!(s.update(Message::Pair), None);
        assert_eq!(s.update(Message::LinkChanged("  keep://x  ".into())), None);
        assert_eq!(
            s.update(Message::Pair),
            Some(Event::Pair("keep://x".into()))
        );
        assert!(s.busy);
    }

    #[test]
    fn busy_drops_actions_until_done() {
        let mut s = state();
        s.error = Some("old".into());
        assert_eq!(
            s.update(Message::Approve("a".into())),
            Some(Event::Approve("a".into()))
        );
        assert_eq!(s.error, None);
        assert_eq!(s.update(Message::Deny("a".into())), None);
        s.action_done(Err("no relay".into()));
        assert!(!s.busy);
        assert_eq!(s.error.as_deref(), Some("no relay"));
        assert_eq!(s.update(Message::FreezeAll), Some(Event::FreezeAll));
        s.action_done(Ok("sent".into()));
        assert_eq!(s.update(Message::UnfreezeAll), Some(Event::UnfreezeAll));
        s.action_done(Ok("sent".into()));
        assert_eq!(s.update(Message::Forget), Some(Event::Forget));
    }

    #[test]
    fn field_line_marks_agent_text_and_cuts() {
        let field = ApprovalField {
            label: "content".into(),
            value: "hi".into(),
            by_agent: true,
            chars: 900,
            removed: 2,
            truncated: true,
        };
        assert_eq!(
            field_line(&field),
            "content: hi [written by the agent] [cut short, 900 characters] [2 hidden characters removed]"
        );
        let plain = ApprovalField {
            by_agent: false,
            truncated: false,
            removed: 0,
            ..field
        };
        assert_eq!(field_line(&plain), "content: hi");
    }

    #[test]
    fn log_keeps_the_newest_lines() {
        let mut log = VecDeque::new();
        push_log(&mut log, (0..150).map(|i| i.to_string()).collect());
        assert_eq!(log.len(), MAX_LOG);
        assert_eq!(log.front().map(String::as_str), Some("50"));
    }
}
