// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;

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
        let back_btn = button(text("< Back")).on_press(Message::GoBack).padding(8);
        let title = text("Create Keyset").size(24);
        let header = row![back_btn, Space::with_width(10), title].align_y(Alignment::Center);

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
            text("Threshold:").size(14),
            threshold_input,
            text("of").size(14),
            total_input,
            text("shares").size(14),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let hint = text("A 2-of-3 keyset means any 2 of 3 devices can sign together.")
            .size(12)
            .color(iced::Color::from_rgb(0.5, 0.5, 0.5));

        let can_create =
            !self.name.is_empty() && !self.threshold.is_empty() && !self.total.is_empty();

        let mut content = column![
            header,
            Space::with_height(20),
            text("Name").size(14),
            name_input,
            Space::with_height(10),
            threshold_row,
            hint,
            Space::with_height(10),
        ]
        .spacing(5);

        if self.loading {
            content = content.push(text("Generating keyset...").size(14));
        } else {
            let mut btn = button(text("Create Keyset")).padding(10);
            if can_create {
                btn = btn.on_press(Message::CreateKeyset);
            }
            content = content.push(btn);
        }

        if let Some(err) = &self.error {
            content = content.push(
                text(err.as_str())
                    .size(14)
                    .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
            );
        }

        container(content)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
