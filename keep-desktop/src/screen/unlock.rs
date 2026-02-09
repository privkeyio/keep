// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Alignment, Element, Length};
use zeroize::Zeroizing;

use crate::message::Message;
use crate::theme;

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

    pub fn with_error(vault_exists: bool, error: String) -> Self {
        let mut s = Self::new(vault_exists);
        s.error = Some(error);
        s
    }

    pub fn view(&self) -> Element<Message> {
        let title = text(if self.vault_exists {
            "Unlock Keep"
        } else {
            "Create Keep"
        })
        .size(theme::size::TITLE)
        .color(theme::color::TEXT);

        let subtitle = text(if self.vault_exists {
            "Enter your password to access your FROST shares"
        } else {
            "Set a password to protect your FROST signing shares"
        })
        .size(theme::size::SMALL)
        .color(theme::color::TEXT_MUTED);

        let has_password = !self.password.is_empty();
        let submit_msg = if self.start_fresh_confirm {
            has_password.then_some(Message::ConfirmStartFresh)
        } else if !self.vault_exists {
            (has_password && !self.confirm_password.is_empty()).then_some(Message::Unlock)
        } else {
            has_password.then_some(Message::Unlock)
        };
        let password_input = text_input("Password", &self.password)
            .on_input(|s| Message::PasswordChanged(Zeroizing::new(s)))
            .on_submit_maybe(submit_msg.clone())
            .secure(true)
            .padding(theme::space::MD)
            .width(300);

        let mut col = column![title, subtitle, Space::new().height(theme::space::LG), password_input]
            .align_x(Alignment::Center)
            .spacing(theme::space::SM)
            .width(350);

        if !self.vault_exists {
            let confirm_input = text_input("Confirm password", &self.confirm_password)
                .on_input(|s| Message::ConfirmPasswordChanged(Zeroizing::new(s)))
                .on_submit_maybe(submit_msg)
                .secure(true)
                .padding(theme::space::MD)
                .width(300);
            col = col.push(confirm_input);
        }

        col = col.push(Space::new().height(theme::space::SM));

        if self.loading {
            let loading_text = if self.start_fresh_confirm {
                "Verifying password..."
            } else {
                "Unlocking..."
            };
            col = col.push(theme::muted(loading_text));
        } else if !self.start_fresh_confirm {
            let label = if self.vault_exists {
                "Unlock"
            } else {
                "Create"
            };
            let btn = button(
                text(label)
                    .width(300)
                    .align_x(Alignment::Center)
                    .size(theme::size::BODY),
            )
            .on_press(Message::Unlock)
            .style(theme::primary_button)
            .padding(theme::space::MD);
            col = col.push(btn);
        }

        if let Some(err) = &self.error {
            col = col.push(theme::error_text(err.as_str()));
        }

        if self.vault_exists && !self.loading {
            col = col.push(Space::new().height(theme::space::XL));
            if self.start_fresh_confirm {
                col = col.push(theme::error_text(
                    "Enter your vault password above to confirm deletion.",
                ));
                col = col.push(
                    row![
                        button(text("Confirm Delete").size(theme::size::SMALL))
                            .on_press_maybe(has_password.then_some(Message::ConfirmStartFresh))
                            .style(theme::danger_button)
                            .padding([theme::space::XS, theme::space::MD]),
                        button(text("Cancel").size(theme::size::SMALL))
                            .on_press(Message::CancelStartFresh)
                            .style(theme::secondary_button)
                            .padding([theme::space::XS, theme::space::MD]),
                    ]
                    .spacing(theme::space::SM),
                );
            } else {
                col = col.push(
                    button(
                        text("Start Fresh")
                            .size(theme::size::SMALL)
                            .color(theme::color::TEXT_DIM),
                    )
                    .on_press(Message::StartFresh)
                    .style(theme::text_button),
                );
            }
        }

        let card = container(col)
            .style(theme::card_style)
            .padding(theme::space::XXXL);

        container(card)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .style(theme::page_bg)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
