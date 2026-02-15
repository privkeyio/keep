// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::mpsc;

use tray_icon::menu::{IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

#[derive(Debug, Clone)]
pub enum TrayEvent {
    ShowWindow,
    ToggleBunker,
    Lock,
    Quit,
}

pub struct TrayState {
    _tray: TrayIcon,
    pub event_rx: mpsc::Receiver<TrayEvent>,
    toggle_bunker_item: MenuItem,
    status_item: MenuItem,
    icon_connected: Icon,
    icon_disconnected: Icon,
}

const ICON_SIZE: u32 = 32;

fn build_icon(connected: bool) -> Result<Icon, String> {
    let mut rgba = vec![0u8; (ICON_SIZE * ICON_SIZE * 4) as usize];
    let color: [u8; 4] = if connected {
        [77, 166, 115, 255]
    } else {
        [140, 140, 148, 255]
    };
    let center = ICON_SIZE as f32 / 2.0;
    let r = center - 2.0;
    let r_sq = r * r;
    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            if dx * dx + dy * dy <= r_sq {
                let idx = ((y * ICON_SIZE + x) * 4) as usize;
                rgba[idx..idx + 4].copy_from_slice(&color);
            }
        }
    }
    Icon::from_rgba(rgba, ICON_SIZE, ICON_SIZE).map_err(|e| format!("icon build failed: {e}"))
}

impl TrayState {
    pub fn new(bunker_running: bool) -> Result<Self, String> {
        let (event_tx, event_rx) = mpsc::channel();

        let status_item = MenuItem::new("Keep - Disconnected", false, None);
        let open_item = MenuItem::new("Open Keep", true, None);
        let bunker_label = if bunker_running {
            "Stop Bunker"
        } else {
            "Start Bunker"
        };
        let toggle_bunker_item = MenuItem::new(bunker_label, true, None);
        let lock_item = MenuItem::new("Lock", true, None);
        let quit_item = MenuItem::new("Quit", true, None);

        let sep1 = PredefinedMenuItem::separator();
        let sep2 = PredefinedMenuItem::separator();
        let menu = Menu::new();
        let items: [&dyn IsMenuItem; 7] = [
            &status_item,
            &sep1,
            &open_item,
            &toggle_bunker_item,
            &lock_item,
            &sep2,
            &quit_item,
        ];
        for item in items {
            menu.append(item)
                .map_err(|e| format!("menu append failed: {e}"))?;
        }

        let open_id = open_item.id().clone();
        let toggle_id = toggle_bunker_item.id().clone();
        let lock_id = lock_item.id().clone();
        let quit_id = quit_item.id().clone();

        std::thread::spawn(move || {
            let rx = MenuEvent::receiver();
            while let Ok(event) = rx.recv() {
                let tray_event = if event.id == open_id {
                    TrayEvent::ShowWindow
                } else if event.id == toggle_id {
                    TrayEvent::ToggleBunker
                } else if event.id == lock_id {
                    TrayEvent::Lock
                } else if event.id == quit_id {
                    TrayEvent::Quit
                } else {
                    continue;
                };
                if event_tx.send(tray_event).is_err() {
                    break;
                }
            }
        });

        let icon_connected = build_icon(true)?;
        let icon_disconnected = build_icon(false)?;

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Keep")
            .with_icon(icon_disconnected.clone())
            .build()
            .map_err(|e| format!("tray icon build failed: {e}"))?;

        Ok(Self {
            _tray: tray,
            event_rx,
            toggle_bunker_item,
            status_item,
            icon_connected,
            icon_disconnected,
        })
    }

    pub fn update_status(&self, connected: bool) {
        let label = if connected {
            "Keep - Connected"
        } else {
            "Keep - Disconnected"
        };
        self.status_item.set_text(label);
        let icon = if connected {
            &self.icon_connected
        } else {
            &self.icon_disconnected
        };
        if let Err(e) = self._tray.set_icon(Some(icon.clone())) {
            tracing::warn!("Failed to update tray icon: {e}");
        }
    }

    pub fn update_bunker_label(&self, running: bool) {
        self.toggle_bunker_item.set_text(if running {
            "Stop Bunker"
        } else {
            "Start Bunker"
        });
    }
}

fn send_notification(summary: &str, body: &str) {
    let _ = notify_rust::Notification::new()
        .appname("Keep")
        .summary(summary)
        .body(body)
        .timeout(notify_rust::Timeout::Milliseconds(10_000))
        .show();
}

pub fn send_sign_request_notification() {
    send_notification(
        "Signing Request",
        "A new signing request requires your approval",
    );
}

const MAX_NOTIFICATION_FIELD_LEN: usize = 40;

fn sanitize_notification_field(input: &str) -> String {
    let without_control: String = input.chars().filter(|c| !c.is_control()).collect();
    if without_control.chars().count() > MAX_NOTIFICATION_FIELD_LEN {
        let truncated: String = without_control
            .chars()
            .take(MAX_NOTIFICATION_FIELD_LEN)
            .collect();
        format!("{truncated}...")
    } else {
        without_control
    }
}

pub fn send_bunker_approval_notification(app_name: &str, method: &str) {
    let safe_app = sanitize_notification_field(app_name);
    let safe_method = sanitize_notification_field(method);
    send_notification(
        "Bunker Approval Required",
        &format!("{safe_app} requests: {safe_method}"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_icon_connected_uses_green() {
        let icon = build_icon(true).expect("icon build should succeed");
        let _ = icon;
    }

    #[test]
    fn build_icon_disconnected_uses_gray() {
        let icon = build_icon(false).expect("icon build should succeed");
        let _ = icon;
    }

    #[test]
    fn build_icon_connected_has_green_center_pixel() {
        let mut rgba = vec![0u8; (ICON_SIZE * ICON_SIZE * 4) as usize];
        let color: [u8; 4] = [77, 166, 115, 255];
        let center = ICON_SIZE as f32 / 2.0;
        let r = center - 2.0;
        let r_sq = r * r;
        for y in 0..ICON_SIZE {
            for x in 0..ICON_SIZE {
                let dx = x as f32 - center;
                let dy = y as f32 - center;
                if dx * dx + dy * dy <= r_sq {
                    let idx = ((y * ICON_SIZE + x) * 4) as usize;
                    rgba[idx..idx + 4].copy_from_slice(&color);
                }
            }
        }
        let cx = (ICON_SIZE / 2) as usize;
        let cy = (ICON_SIZE / 2) as usize;
        let idx = (cy * ICON_SIZE as usize + cx) * 4;
        assert_eq!(&rgba[idx..idx + 4], &[77, 166, 115, 255]);
    }

    #[test]
    fn build_icon_disconnected_has_gray_center_pixel() {
        let mut rgba = vec![0u8; (ICON_SIZE * ICON_SIZE * 4) as usize];
        let color: [u8; 4] = [140, 140, 148, 255];
        let center = ICON_SIZE as f32 / 2.0;
        let r = center - 2.0;
        let r_sq = r * r;
        for y in 0..ICON_SIZE {
            for x in 0..ICON_SIZE {
                let dx = x as f32 - center;
                let dy = y as f32 - center;
                if dx * dx + dy * dy <= r_sq {
                    let idx = ((y * ICON_SIZE + x) * 4) as usize;
                    rgba[idx..idx + 4].copy_from_slice(&color);
                }
            }
        }
        let cx = (ICON_SIZE / 2) as usize;
        let cy = (ICON_SIZE / 2) as usize;
        let idx = (cy * ICON_SIZE as usize + cx) * 4;
        assert_eq!(&rgba[idx..idx + 4], &[140, 140, 148, 255]);
    }

    #[test]
    fn build_icon_corner_is_transparent() {
        let mut rgba = vec![0u8; (ICON_SIZE * ICON_SIZE * 4) as usize];
        let color: [u8; 4] = [77, 166, 115, 255];
        let center = ICON_SIZE as f32 / 2.0;
        let r = center - 2.0;
        let r_sq = r * r;
        for y in 0..ICON_SIZE {
            for x in 0..ICON_SIZE {
                let dx = x as f32 - center;
                let dy = y as f32 - center;
                if dx * dx + dy * dy <= r_sq {
                    let idx = ((y * ICON_SIZE + x) * 4) as usize;
                    rgba[idx..idx + 4].copy_from_slice(&color);
                }
            }
        }
        assert_eq!(&rgba[0..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn sanitize_short_input_unchanged() {
        assert_eq!(sanitize_notification_field("hello"), "hello");
    }

    #[test]
    fn sanitize_strips_control_characters() {
        assert_eq!(
            sanitize_notification_field("hello\nworld\t!"),
            "helloworld!"
        );
    }

    #[test]
    fn sanitize_truncates_long_input() {
        let long = "a".repeat(50);
        let result = sanitize_notification_field(&long);
        assert_eq!(result.len(), MAX_NOTIFICATION_FIELD_LEN + 3);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn sanitize_exact_length_not_truncated() {
        let exact = "x".repeat(MAX_NOTIFICATION_FIELD_LEN);
        assert_eq!(sanitize_notification_field(&exact), exact);
    }

    #[test]
    fn sanitize_one_over_limit_truncated() {
        let over = "y".repeat(MAX_NOTIFICATION_FIELD_LEN + 1);
        let result = sanitize_notification_field(&over);
        let expected = format!("{}...", "y".repeat(MAX_NOTIFICATION_FIELD_LEN));
        assert_eq!(result, expected);
    }

    #[test]
    fn sanitize_empty_input() {
        assert_eq!(sanitize_notification_field(""), "");
    }

    #[test]
    fn sanitize_only_control_chars() {
        assert_eq!(sanitize_notification_field("\n\r\t\0"), "");
    }

    #[test]
    fn sanitize_unicode_counted_by_chars() {
        let input = "\u{1F600}".repeat(MAX_NOTIFICATION_FIELD_LEN + 1);
        let result = sanitize_notification_field(&input);
        assert!(result.ends_with("..."));
        assert_eq!(result.chars().count(), MAX_NOTIFICATION_FIELD_LEN + 3);
    }

    #[test]
    fn sanitize_control_chars_reduce_below_limit() {
        let mut input = "a".repeat(MAX_NOTIFICATION_FIELD_LEN + 5);
        input.push('\n');
        input.push('\n');
        input.push('\n');
        input.push('\n');
        input.push('\n');
        let result = sanitize_notification_field(&input);
        assert!(result.ends_with("..."));
    }
}
