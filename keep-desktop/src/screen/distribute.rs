// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashSet;

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};

use crate::screen::shares::ShareEntry;
use crate::theme;

#[derive(Debug, Clone)]
pub enum Message {
    ExportQr(usize),
    Finish,
}

pub enum Event {
    ExportQr(ShareEntry),
    Finish,
}

pub struct State {
    shares: Vec<ShareEntry>,
    name: String,
    threshold: u16,
    total: u16,
    npub: String,
    exported: HashSet<u16>,
    error: Option<String>,
}

impl State {
    pub fn new(shares: Vec<ShareEntry>) -> Self {
        let (name, threshold, total, npub) = shares
            .first()
            .map(|s| {
                (
                    s.name.clone(),
                    s.threshold,
                    s.total_shares,
                    s.npub.clone(),
                )
            })
            .unwrap_or_default();
        Self {
            shares,
            name,
            threshold,
            total,
            npub,
            exported: HashSet::new(),
            error: None,
        }
    }

    pub fn mark_exported(&mut self, identifier: u16) {
        self.exported.insert(identifier);
    }

    pub fn set_error(&mut self, error: String) {
        self.error = Some(error);
    }

    pub fn update(&mut self, message: Message) -> Option<Event> {
        match message {
            Message::ExportQr(index) => self.shares.get(index).cloned().map(Event::ExportQr),
            Message::Finish => Some(Event::Finish),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let title = text("Distribute Shares")
            .size(theme::size::HEADING)
            .color(theme::color::TEXT);

        let truncated = crate::screen::truncate_npub(&self.npub);
        let info = text(format!(
            "{} | {}-of-{} | {}",
            self.name, self.threshold, self.total, truncated,
        ))
        .size(theme::size::SMALL)
        .color(theme::color::TEXT_MUTED);

        let warning = container(
            text("This is the only time all shares are shown together. Export each share to a separate device before finishing.")
                .size(theme::size::SMALL)
                .color(theme::color::WARNING),
        )
        .style(theme::warning_style)
        .padding(theme::space::MD)
        .width(theme::size::INPUT_WIDTH);

        let mut content = column![
            title,
            info,
            Space::new().height(theme::space::SM),
            warning,
            Space::new().height(theme::space::LG),
        ]
        .spacing(theme::space::XS);

        for (i, share) in self.shares.iter().enumerate() {
            let exported = self.exported.contains(&share.identifier);
            let status_text = if exported {
                "Exported"
            } else {
                "Not exported"
            };
            let status_color = if exported {
                theme::color::SUCCESS
            } else {
                theme::color::TEXT_MUTED
            };

            let share_row = row![
                text(format!("Share #{}", share.identifier))
                    .size(theme::size::BODY)
                    .color(theme::color::TEXT)
                    .width(Length::Fixed(100.0)),
                text(status_text)
                    .size(theme::size::SMALL)
                    .color(status_color)
                    .width(Length::Fill),
                button(text("Export QR").size(theme::size::BODY))
                    .on_press(Message::ExportQr(i))
                    .style(theme::secondary_button)
                    .padding([theme::space::XS, theme::space::MD]),
            ]
            .spacing(theme::space::SM)
            .align_y(Alignment::Center);

            content = content.push(
                container(share_row)
                    .style(theme::card_style)
                    .padding(theme::space::MD)
                    .width(theme::size::INPUT_WIDTH),
            );
            content = content.push(Space::new().height(theme::space::XS));
        }

        if let Some(err) = &self.error {
            content = content.push(
                text(err.as_str())
                    .size(theme::size::SMALL)
                    .color(theme::color::ERROR),
            );
        }

        content = content.push(Space::new().height(theme::space::MD));

        let exported_count = self.exported.len() as u16;
        let all_exported = self.shares.iter().all(|s| self.exported.contains(&s.identifier));
        let enough_exported = exported_count >= self.threshold;

        let finish_label = if all_exported {
            "Finish".to_string()
        } else if enough_exported {
            format!(
                "Finish ({} of {} exported — remaining shares will be lost)",
                exported_count, self.total
            )
        } else {
            format!(
                "Export at least {} shares to finish ({} of {} exported)",
                self.threshold, exported_count, self.total
            )
        };

        let mut finish_btn = button(text(finish_label).size(theme::size::BODY))
            .style(theme::primary_button)
            .padding(theme::space::MD);
        if enough_exported {
            finish_btn = finish_btn.on_press(Message::Finish);
        }

        content = content.push(finish_btn);

        container(scrollable(
            container(content)
                .padding(theme::space::XL)
                .width(Length::Fill),
        ))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
}
