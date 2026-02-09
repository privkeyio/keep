// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use iced::widget::{button, column, container, row, text, Space};
use iced::{Element, Length};

use crate::message::Message;
use crate::theme;

#[derive(PartialEq)]
pub enum NavItem {
    Shares,
    Create,
    Import,
}

pub fn with_sidebar<'a>(
    active: NavItem,
    content: Element<'a, Message>,
    share_count: Option<usize>,
) -> Element<'a, Message> {
    let nav_items = [
        ("Shares", Message::NavigateShares, NavItem::Shares),
        ("Create", Message::GoToCreate, NavItem::Create),
        ("Import", Message::GoToImport, NavItem::Import),
    ];

    let mut nav = column![].spacing(theme::space::XS);
    for (label, msg, item) in nav_items {
        let is_active = item == active;
        let style: fn(&iced::Theme, button::Status) -> button::Style = if is_active {
            theme::nav_button_active
        } else {
            theme::nav_button
        };
        let press = if is_active { None } else { Some(msg) };
        let nav_label: Element<'a, Message> =
            if let (NavItem::Shares, Some(count)) = (&item, share_count) {
                row![
                    text(label).size(theme::size::BODY),
                    Space::new().width(Length::Fill),
                    text(count.to_string())
                        .size(theme::size::SMALL)
                        .color(theme::color::TEXT_DIM),
                ]
                .width(Length::Fill)
                .align_y(iced::Alignment::Center)
                .into()
            } else {
                text(label)
                    .size(theme::size::BODY)
                    .width(Length::Fill)
                    .into()
            };
        nav = nav.push(
            button(nav_label)
                .on_press_maybe(press)
                .style(style)
                .padding([theme::space::SM, theme::space::MD])
                .width(Length::Fill),
        );
    }

    let lock_btn = button(text("Lock").size(theme::size::BODY).width(Length::Fill))
        .on_press(Message::Lock)
        .style(theme::text_button)
        .padding([theme::space::SM, theme::space::MD])
        .width(Length::Fill);

    let sidebar = container(
        column![
            text("Keep")
                .size(theme::size::TITLE)
                .color(theme::color::TEXT),
            Space::new().height(theme::space::LG),
            nav,
            Space::new().height(Length::Fill),
            lock_btn,
        ]
        .padding(theme::space::LG)
        .height(Length::Fill),
    )
    .style(theme::sidebar_style)
    .width(theme::size::SIDEBAR_WIDTH)
    .height(Length::Fill);

    let main = container(content)
        .style(theme::page_bg)
        .width(Length::Fill)
        .height(Length::Fill);

    row![sidebar, main].into()
}
