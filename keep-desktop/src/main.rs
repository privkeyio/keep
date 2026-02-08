// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod message;
mod screen;

use app::App;

fn main() -> iced::Result {
    tracing_subscriber::fmt::init();

    iced::application(App::new, App::update, App::view)
        .title("Keep")
        .subscription(App::subscription)
        .window_size((900.0, 600.0))
        .run()
}
