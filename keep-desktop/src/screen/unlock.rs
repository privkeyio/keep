// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
use iced::widget::{button, column, container, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::message::Message;

pub struct UnlockScreen {
    pub password: Zeroizing<String>,
    pub confirm_password: Zeroizing<String>,
    pub error: Option<String>,
    pub loading: bool,
    pub vault_exists: bool,
    pub start_fresh_confirm: bool,
}

impl UnlockScreen {
    pub fn new(vault_exists: bool) -> Self {
        Self {
            password: Zeroizing::new(String::new()),
            confirm_password: Zeroizing::new(String::new()),
            error: None,
            loading: false,
            vault_exists,
            start_fresh_confirm: false,
        }
    }

    pub fn with_error(error: String) -> Self {
        let mut s = Self::new(false);
        s.error = Some(error);
        s
    }

    pub fn view(&self) -> Element<Message> {
        let title = text(if self.vault_exists {
            "Unlock Keep"
        } else {
            "Create Keep"
        })
        .size(28);

        let password_input = text_input("Password", &self.password)
            .on_input(Message::PasswordChanged)
            .on_submit(Message::Unlock)
            .secure(true)
            .padding(10)
            .width(300);

        let mut col = column![title, Space::with_height(20), password_input,]
            .align_x(Alignment::Center)
            .spacing(10)
            .width(350);

        if !self.vault_exists {
            let confirm_input = text_input("Confirm password", &self.confirm_password)
                .on_input(Message::ConfirmPasswordChanged)
                .on_submit(Message::Unlock)
                .secure(true)
                .padding(10)
                .width(300);
            col = col.push(confirm_input);
        }

        col = col.push(Space::with_height(10));

        if self.loading {
            col = col.push(text("Unlocking...").size(14));
        } else {
            let label = if self.vault_exists {
                "Unlock"
            } else {
                "Create"
            };
            let btn = button(text(label).width(300).align_x(Alignment::Center))
                .on_press(Message::Unlock)
                .padding(10);
            col = col.push(btn);
        }

        if let Some(err) = &self.error {
            col = col.push(
                text(err.as_str())
                    .size(14)
                    .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
            );
        }

        if self.vault_exists && !self.loading {
            col = col.push(Space::with_height(20));
            if self.start_fresh_confirm {
                col = col.push(
                    text("This will permanently delete all vault data.")
                        .size(13)
                        .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
                );
                col = col.push(
                    iced::widget::row![
                        button(text("Confirm Delete").size(13))
                            .on_press(Message::ConfirmStartFresh)
                            .padding(6),
                        button(text("Cancel").size(13))
                            .on_press(Message::CancelStartFresh)
                            .padding(6),
                    ]
                    .spacing(10),
                );
            } else {
                col = col.push(
                    button(
                        text("Start Fresh")
                            .size(13)
                            .color(iced::Color::from_rgb(0.5, 0.5, 0.5)),
                    )
                    .on_press(Message::StartFresh)
                    .style(button::text),
                );
            }
        }

        container(col)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
