// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::screen::layout::{self, NavItem};
use crate::theme;

pub struct CreateScreen {
    pub name: String,
    pub threshold: String,
    pub total: String,
    pub error: Option<String>,
    pub loading: bool,
}

impl CreateScreen {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            threshold: "2".into(),
            total: "3".into(),
            error: None,
            loading: false,
        }
    }

    pub fn view(&self) -> Element<Message> {
        let title = theme::heading("Create Keyset");

        let name_input = text_input("Keyset name (e.g. my-keyset)", &self.name)
            .on_input(Message::CreateNameChanged)
            .padding(10)
            .width(400);

        let threshold_input = text_input("2", &self.threshold)
            .on_input(Message::CreateThresholdChanged)
            .padding(10)
            .width(80);

        let total_input = text_input("3", &self.total)
            .on_input(Message::CreateTotalChanged)
            .padding(10)
            .width(80);

        let threshold_row = row![
            theme::label("Threshold:"),
            threshold_input,
            theme::label("of"),
            total_input,
            theme::label("shares"),
        ]
        .spacing(theme::space::SM)
        .align_y(Alignment::Center);

        let hint = theme::muted("A 2-of-3 keyset means any 2 of 3 devices can sign together.");

        let name_valid = !self.name.is_empty() && self.name.len() <= 64;
        let threshold_val: Option<u16> = self
            .threshold
            .parse()
            .ok()
            .filter(|v| (2..=255).contains(v));
        let total_val: Option<u16> = self.total.parse().ok().filter(|&v| v <= 255);
        let total_valid = matches!((threshold_val, total_val), (Some(t), Some(n)) if n >= t);
        let can_create = name_valid && threshold_val.is_some() && total_valid;

        let mut content = column![
            title,
            Space::new().height(theme::space::XL),
            theme::label("Name"),
            name_input,
            Space::new().height(theme::space::MD),
            threshold_row,
        ]
        .spacing(theme::space::XS);

        if self.name.len() > 64 {
            content = content.push(theme::error_text("Name must be 64 characters or fewer"));
        }
        if !self.threshold.is_empty() && threshold_val.is_none() {
            content = content.push(theme::error_text("Threshold must be between 2 and 255"));
        }
        if !self.total.is_empty() {
            let total_error = match (total_val, threshold_val) {
                (Some(n), Some(t)) if n < t => Some("Total must be >= threshold"),
                (None, _) if self.total.parse::<u16>().is_ok() => {
                    Some("Total must be 255 or fewer")
                }
                (None, _) => Some("Total must be a valid number"),
                _ => None,
            };
            if let Some(msg) = total_error {
                content = content.push(theme::error_text(msg));
            }
        }

        content = content.push(hint);
        content = content.push(Space::new().height(theme::space::MD));

        if self.loading {
            content = content.push(theme::label("Generating keyset..."));
        } else {
            let mut btn = button(text("Create Keyset").size(theme::size::BODY))
                .style(theme::primary_button)
                .padding(theme::space::MD);
            if can_create {
                btn = btn.on_press(Message::CreateKeyset);
            }
            content = content.push(btn);
        }

        if let Some(err) = &self.error {
            content = content.push(theme::error_text(err.as_str()));
        }

        let inner = container(content)
            .padding(theme::space::XL)
            .width(Length::Fill)
            .height(Length::Fill);

        layout::with_sidebar(NavItem::Create, inner.into())
    }
}
