// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT
use std::io::{self, stdout};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use keep_nip46::handler::sanitize_prompt_field;
use keep_nip46::types::HttpAuthDetails;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use std::sync::atomic::{AtomicBool, Ordering};

/// True only while the interactive TUI holds the alternate screen. The signal
/// handler (`main`) and the panic handler (`panic`) consult this so they emit the
/// LeaveAlternateScreen escape ONLY when the TUI actually entered it -- never on a
/// non-TUI command like `frost network oprf-unlock`, whose stdout is contractually
/// the 32-byte LUKS key and must carry no terminal control bytes (keep-node-95y).
pub(crate) static ALT_SCREEN_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Restore the terminal from a signal or panic handler. Always leaves raw mode (a
/// no-op if it was never set; also recovers an interrupted `dialoguer` prompt), but
/// leaves the alternate screen ONLY if the TUI entered it, so its escape never
/// pollutes a command's stdout.
pub(crate) fn restore_terminal() {
    let _ = disable_raw_mode();
    let active = ALT_SCREEN_ACTIVE.swap(false, Ordering::SeqCst);
    let _ = write_leave_alt_screen(&mut stdout(), active);
}

/// Write LeaveAlternateScreen to `w` iff the alternate screen was active. Split out
/// from `restore_terminal` so the stdout-hygiene contract is unit-testable without a
/// real terminal, a signal, or the global flag.
fn write_leave_alt_screen<W: io::Write>(w: &mut W, active: bool) -> io::Result<()> {
    if active {
        w.execute(LeaveAlternateScreen)?;
    }
    Ok(())
}

#[derive(Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub success: bool,
    pub app: String,
    pub action: String,
    pub detail: Option<String>,
}

impl LogEntry {
    pub fn new(app: &str, action: &str, success: bool) -> Self {
        Self {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            success,
            app: app.to_string(),
            action: action.to_string(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_string());
        self
    }
}

// How long an approval prompt must be on screen, with no key pressed, before
// [Y] takes effect. Input queued before it was drawn is discarded when it is
// first drawn, and any key in the window starts it again, so a burst of
// typing or a held key never approves a request nobody read.
const APPROVE_SETTLE: Duration = Duration::from_secs(1);

// The answer slot one prompt shares with the request waiting on it.
// Whichever side takes the sender first decides: the screen to answer, or the
// waiting request when it gives up. An answer therefore counts as delivered
// only when the request acts on it.
#[derive(Clone)]
pub struct ApprovalReply(Arc<Mutex<Option<Sender<bool>>>>);

impl ApprovalReply {
    pub fn new(tx: Sender<bool>) -> Self {
        Self(Arc::new(Mutex::new(Some(tx))))
    }

    pub fn answer(&self, approved: bool) -> bool {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        slot.take().is_some_and(|tx| tx.send(approved).is_ok())
    }

    fn close(&self) -> bool {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        slot.take().is_some()
    }

    // The operator's answer, or `None` once the request gives up. An answer
    // sent while it gave up is still taken: the screen sends with the slot
    // held, so if the slot is already empty the answer is in the channel.
    pub fn wait(&self, rx: &Receiver<bool>, timeout: Duration) -> Option<bool> {
        match rx.recv_timeout(timeout) {
            Ok(approved) => Some(approved),
            Err(_) if self.close() => None,
            Err(_) => rx.try_recv().ok(),
        }
    }
}

pub struct ApprovalRequest {
    pub id: u64,
    pub app: String,
    pub action: String,
    pub kind: Option<u16>,
    pub content_preview: Option<String>,
    /// NIP-98 (kind 27235) HTTP-auth target surfaced so the operator can see
    /// what a bearer-credential sign request authorizes.
    pub http_auth: Option<HttpAuthDetails>,
    pub response_tx: ApprovalReply,
}

#[allow(dead_code)]
pub enum TuiEvent {
    Log(LogEntry),
    Approval(ApprovalRequest),
    ApprovalTimeout(u64),
    Quit,
}

pub struct Tui {
    bunker_url: String,
    npub: String,
    relay: String,
    logs: Vec<LogEntry>,
    pending_approval: Option<ApprovalRequest>,
    approval_drawn_at: Option<Instant>,
    event_rx: Receiver<TuiEvent>,
    should_quit: bool,
}

impl Tui {
    pub fn new(bunker_url: String, npub: String, relay: String) -> (Self, Sender<TuiEvent>) {
        let (tx, rx) = mpsc::channel();
        (
            Self {
                bunker_url,
                npub,
                relay,
                logs: Vec::new(),
                pending_approval: None,
                approval_drawn_at: None,
                event_rx: rx,
                should_quit: false,
            },
            tx,
        )
    }

    pub fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        // Mark the alt screen active BEFORE entering it: a signal in the tiny window
        // before EnterAlternateScreen then still restores the terminal (an escape
        // emitted a hair early on a real TUI terminal is harmless), rather than
        // leaving it stuck in the alt screen.
        ALT_SCREEN_ACTIVE.store(true, Ordering::SeqCst);
        stdout().execute(EnterAlternateScreen)?;
        let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

        while !self.should_quit {
            terminal.draw(|f| self.draw(f))?;
            if self.approval_drawn() {
                while event::poll(Duration::ZERO)? {
                    let _ = event::read()?;
                }
            }
            self.handle_events()?;
        }

        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;
        ALT_SCREEN_ACTIVE.store(false, Ordering::SeqCst);
        Ok(())
    }

    // The settle time runs from the first frame that shows the prompt.
    // Returns whether this frame is that first one.
    fn approval_drawn(&mut self) -> bool {
        if self.pending_approval.is_some() && self.approval_drawn_at.is_none() {
            self.approval_drawn_at = Some(Instant::now());
            return true;
        }
        false
    }

    fn handle_events(&mut self) -> io::Result<()> {
        self.drain_events();

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    self.handle_key(key);
                }
            }
        }

        Ok(())
    }

    fn drain_events(&mut self) {
        while let Ok(evt) = self.event_rx.try_recv() {
            match evt {
                TuiEvent::Log(entry) => {
                    self.logs.push(entry);
                    if self.logs.len() > 100 {
                        self.logs.remove(0);
                    }
                }
                TuiEvent::Approval(req) => {
                    if let Some(prev) = self.take_approval() {
                        let detail = if prev.response_tx.answer(false) {
                            "superseded"
                        } else {
                            "timed out"
                        };
                        self.logs.push(
                            LogEntry::new(&prev.app, &prev.action, false).with_detail(detail),
                        );
                    }
                    self.pending_approval = Some(req);
                }
                TuiEvent::ApprovalTimeout(id) => {
                    // Only the prompt that timed out: the next request's prompt
                    // may already be pending.
                    if self.pending_approval.as_ref().map(|r| r.id) == Some(id) {
                        if let Some(req) = self.take_approval() {
                            self.logs.push(
                                LogEntry::new(&req.app, &req.action, false)
                                    .with_detail("timed out"),
                            );
                        }
                    }
                }
                TuiEvent::Quit => {
                    self.should_quit = true;
                }
            }
        }
    }

    fn take_approval(&mut self) -> Option<ApprovalRequest> {
        self.approval_drawn_at = None;
        self.pending_approval.take()
    }

    // Only a plain [Y] approves, and only once the prompt has been on screen
    // for `APPROVE_SETTLE` with no key pressed. Enter is not an answer: it is
    // the key most likely to be typed for something else just as a prompt
    // appears. Nor is Ctrl+Y or Alt+Y, which are typed as editing keys.
    fn handle_key(&mut self, key: KeyEvent) {
        let plain = (key.modifiers - KeyModifiers::SHIFT).is_empty();
        if self.pending_approval.is_some() {
            let settled = self
                .approval_drawn_at
                .is_some_and(|drawn| drawn.elapsed() >= APPROVE_SETTLE);
            let approve = plain && matches!(key.code, KeyCode::Char('y' | 'Y'));
            let reject = matches!(key.code, KeyCode::Char('n' | 'N'));
            if !(reject || approve && settled) {
                if self.approval_drawn_at.is_some() {
                    self.approval_drawn_at = Some(Instant::now());
                }
                return;
            }
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.pending_approval.is_none() {
                    self.should_quit = true;
                }
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Some(req) = self.take_approval() {
                    let delivered = req.response_tx.answer(true);
                    let entry = LogEntry::new(&req.app, &req.action, delivered);
                    self.logs.push(if delivered {
                        entry
                    } else {
                        entry.with_detail("timed out")
                    });
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                if let Some(req) = self.take_approval() {
                    // A refusal the request never took was the timeout's, not
                    // the operator's.
                    let detail = if req.response_tx.answer(false) {
                        "rejected"
                    } else {
                        "timed out"
                    };
                    self.logs
                        .push(LogEntry::new(&req.app, &req.action, false).with_detail(detail));
                }
            }
            _ => {}
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.draw_header(frame, chunks[0]);
        self.draw_logs(frame, chunks[1]);
        self.draw_footer(frame, chunks[2]);

        if let Some(ref req) = self.pending_approval {
            self.draw_approval_popup(frame, req);
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let text = vec![
            Line::from(vec![
                Span::styled("Key: ", Style::default().fg(Color::Gray)),
                Span::styled(&self.npub, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("Relay: ", Style::default().fg(Color::Gray)),
                Span::styled(&self.relay, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Bunker URL: ",
                Style::default().fg(Color::Gray),
            )]),
            Line::from(Span::styled(
                &self.bunker_url,
                Style::default().fg(Color::Cyan),
            )),
        ];

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Keep NIP-46 Signer ");
        let paragraph = Paragraph::new(text).block(block);
        frame.render_widget(paragraph, area);
    }

    fn draw_logs(&self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .logs
            .iter()
            .rev()
            .map(|entry| {
                let symbol = if entry.success { "✓" } else { "✗" };
                let color = if entry.success {
                    Color::Green
                } else {
                    Color::Red
                };
                // `app`/`action`/`detail` carry attacker-influenced strings (the
                // client's declared app name, the requested method). Sanitize
                // them like the approval prompt so a newline/bidi sequence cannot
                // corrupt or spoof a log line. Per-column caps keep one entry from
                // dominating the pane.
                let mut spans = vec![
                    Span::styled(
                        format!("[{}] ", entry.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(format!("{symbol} "), Style::default().fg(color)),
                    Span::styled(
                        sanitize_prompt_field(&entry.app, 32),
                        Style::default().fg(Color::White),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        sanitize_prompt_field(&entry.action, 48),
                        Style::default().fg(Color::Gray),
                    ),
                ];
                if let Some(ref detail) = entry.detail {
                    spans.push(Span::styled(
                        format!(" ({})", sanitize_prompt_field(detail, 64)),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let block = Block::default().borders(Borders::ALL).title(" Activity ");
        let list = List::new(items).block(block);
        frame.render_widget(list, area);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let text = if self.pending_approval.is_some() {
            "[Y] Approve  [N] Reject"
        } else {
            "[Q] Quit"
        };
        let paragraph = Paragraph::new(text)
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        frame.render_widget(paragraph, area);
    }

    fn draw_approval_popup(&self, frame: &mut Frame, req: &ApprovalRequest) {
        let area = centered_rect(60, 40, frame.area());

        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("App: ", Style::default().fg(Color::Gray)),
                Span::styled(&req.app, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Action: ", Style::default().fg(Color::Gray)),
                Span::styled(&req.action, Style::default().fg(Color::Yellow)),
            ]),
        ];

        if let Some(kind) = req.kind {
            lines.push(Line::from(vec![
                Span::styled("Kind: ", Style::default().fg(Color::Gray)),
                Span::styled(kind.to_string(), Style::default().fg(Color::Cyan)),
            ]));
        }

        if let Some(ref auth) = req.http_auth {
            // method/url are already bidi/control-sanitized at the keep-nip46
            // choke point; re-apply the shared sanitizer here only to enforce the
            // tighter per-surface display cap so a long value cannot push the
            // rest of the prompt off-screen.
            let method = sanitize_prompt_field(auth.method.as_deref().unwrap_or("<no method>"), 16);
            let url = sanitize_prompt_field(auth.url.as_deref().unwrap_or("<no url>"), 120);
            lines.push(Line::from(vec![
                Span::styled("HTTP auth: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{method} {url}"), Style::default().fg(Color::Red)),
            ]));
        }

        if let Some(ref content) = req.content_preview {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Content:",
                Style::default().fg(Color::Gray),
            )));
            let preview: String = content.chars().take(200).collect();
            lines.push(Line::from(Span::styled(
                preview,
                Style::default().fg(Color::White),
            )));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Press [Y] to approve, [N] to reject",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Approval Required ");

        let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });

        frame.render_widget(ratatui::widgets::Clear, area);
        frame.render_widget(paragraph, area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod terminal_restore_tests {
    use super::write_leave_alt_screen;

    // A non-TUI command (e.g. `frost network oprf-unlock`) never entered the
    // alternate screen, so a signal/panic exit must write NOTHING to the stream --
    // stdout stays contractually the 32-byte LUKS key, with no control bytes
    // (keep-node-95y).
    #[test]
    fn writes_nothing_when_alt_screen_inactive() {
        let mut buf: Vec<u8> = Vec::new();
        write_leave_alt_screen(&mut buf, false).unwrap();
        assert!(
            buf.is_empty(),
            "inactive alt-screen must emit no bytes, got {buf:?}"
        );
    }

    // A real TUI session must still be restored on exit: the exact 8-byte
    // LeaveAlternateScreen escape (ESC [ ? 1 0 4 9 l).
    #[test]
    fn emits_leave_alternate_screen_when_active() {
        let mut buf: Vec<u8> = Vec::new();
        write_leave_alt_screen(&mut buf, true).unwrap();
        assert_eq!(
            buf, b"\x1b[?1049l",
            "active alt-screen must emit LeaveAlternateScreen"
        );
    }
}

#[cfg(test)]
mod approval_tests {
    fn prompt(id: u64) -> (super::ApprovalRequest, std::sync::mpsc::Receiver<bool>) {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        (
            super::ApprovalRequest {
                id,
                app: format!("client-{id}"),
                action: "sign_event".into(),
                kind: Some(1),
                content_preview: None,
                http_auth: None,
                response_tx: super::ApprovalReply::new(response_tx),
            },
            response_rx,
        )
    }

    fn tui() -> (super::Tui, std::sync::mpsc::Sender<super::TuiEvent>) {
        super::Tui::new("bunker://x".into(), "npub".into(), "wss://r".into())
    }

    fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
        crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    fn settle(t: &mut super::Tui) {
        t.approval_drawn_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(2));
    }

    // A [Y] read before the prompt is drawn, or within the settle time after,
    // is dropped. [N] is taken at once.
    #[test]
    fn approve_waits_until_the_prompt_has_been_on_screen() {
        use crossterm::event::KeyCode;
        let (mut t, tx) = tui();
        let (req, rx) = prompt(1);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        t.drain_events();

        t.handle_key(key(KeyCode::Char('y')));
        assert!(rx.try_recv().is_err(), "approved before it was drawn");
        t.approval_drawn();
        t.handle_key(key(KeyCode::Char('y')));
        assert!(rx.try_recv().is_err(), "approved within the settle time");

        settle(&mut t);
        t.handle_key(key(KeyCode::Char('y')));
        assert_eq!(rx.try_recv(), Ok(true));
        assert!(t.pending_approval.is_none());

        let (req, rx) = prompt(2);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        t.drain_events();
        t.handle_key(key(KeyCode::Char('n')));
        assert_eq!(rx.try_recv(), Ok(false));
    }

    // A prompt that replaces another starts its own settle time, so keys
    // aimed at the old one do not approve it.
    #[test]
    fn a_replacing_prompt_starts_its_own_settle_time() {
        use crossterm::event::KeyCode;
        let (mut t, tx) = tui();
        let (first, _first_rx) = prompt(1);
        tx.send(super::TuiEvent::Approval(first)).unwrap();
        t.drain_events();
        t.approval_drawn();
        settle(&mut t);

        let (second, rx) = prompt(2);
        tx.send(super::TuiEvent::Approval(second)).unwrap();
        t.drain_events();
        t.handle_key(key(KeyCode::Char('y')));
        assert!(rx.try_recv().is_err(), "a key aimed at 1 approved 2");
    }

    #[test]
    fn enter_does_not_approve() {
        use crossterm::event::KeyCode;
        let (mut t, tx) = tui();
        let (req, rx) = prompt(1);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        t.drain_events();
        t.approval_drawn();
        settle(&mut t);
        t.handle_key(key(KeyCode::Enter));
        assert!(rx.try_recv().is_err());
        assert!(t.pending_approval.is_some());
    }

    // Ctrl+Y and Alt+Y are editing keys, not answers, and they restart the
    // settle time like any other key.
    #[test]
    fn modified_y_does_not_approve() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let (mut t, tx) = tui();
        let (req, rx) = prompt(1);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        t.drain_events();
        t.approval_drawn();
        for m in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            settle(&mut t);
            t.handle_key(KeyEvent::new(KeyCode::Char('y'), m));
            assert!(rx.try_recv().is_err(), "{m:?}+Y approved");
        }
        settle(&mut t);
        t.handle_key(KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::SHIFT));
        assert_eq!(rx.try_recv(), Ok(true));
    }

    // Any key while a prompt is open starts the settle time again, so typing
    // or a held key that runs past the window still does not approve.
    #[test]
    fn a_key_during_the_prompt_restarts_the_settle_time() {
        use crossterm::event::KeyCode;
        let (mut t, tx) = tui();
        let (req, rx) = prompt(1);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        t.drain_events();
        t.approval_drawn();
        settle(&mut t);
        t.handle_key(key(KeyCode::Char('a')));
        t.handle_key(key(KeyCode::Char('y')));
        assert!(rx.try_recv().is_err(), "approved right after another key");
        settle(&mut t);
        t.handle_key(key(KeyCode::Char('y')));
        t.handle_key(key(KeyCode::Char('y')));
        assert_eq!(rx.try_recv(), Ok(true));
    }

    // A prompt replaced by another is refused and logged, never left
    // waiting unseen.
    #[test]
    fn a_replaced_prompt_is_refused_and_logged() {
        let (mut t, tx) = tui();
        let (first, first_rx) = prompt(1);
        let (second, _second_rx) = prompt(2);
        tx.send(super::TuiEvent::Approval(first)).unwrap();
        tx.send(super::TuiEvent::Approval(second)).unwrap();
        t.drain_events();
        assert_eq!(first_rx.try_recv(), Ok(false));
        assert_eq!(t.logs.last().unwrap().detail.as_deref(), Some("superseded"));
        assert_eq!(t.pending_approval.as_ref().map(|r| r.id), Some(2));
    }

    // A refusal the request never took is logged as the timeout's.
    #[test]
    fn a_reject_nobody_receives_is_logged_as_timed_out() {
        use crossterm::event::KeyCode;
        let (mut t, tx) = tui();
        let (req, rx) = prompt(1);
        drop(rx);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        t.drain_events();
        t.handle_key(key(KeyCode::Char('n')));
        assert_eq!(t.logs.last().unwrap().detail.as_deref(), Some("timed out"));

        let (req, _rx) = prompt(2);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        t.drain_events();
        t.handle_key(key(KeyCode::Char('n')));
        assert_eq!(t.logs.last().unwrap().detail.as_deref(), Some("rejected"));
    }

    // A timeout takes down only its own prompt.
    #[test]
    fn a_timeout_clears_only_its_own_prompt() {
        let (mut t, tx) = tui();
        let (req, _rx) = prompt(2);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        tx.send(super::TuiEvent::ApprovalTimeout(1)).unwrap();
        t.drain_events();
        assert_eq!(t.pending_approval.as_ref().map(|r| r.id), Some(2));
        tx.send(super::TuiEvent::ApprovalTimeout(2)).unwrap();
        t.drain_events();
        assert!(t.pending_approval.is_none());
        assert!(t.approval_drawn_at.is_none());
    }

    // The screen sending as the request gives up: the request waits for the
    // send to finish and takes the answer.
    #[test]
    fn an_answer_sent_as_the_request_gives_up_is_taken() {
        let (tx, rx) = std::sync::mpsc::channel();
        let reply = super::ApprovalReply::new(tx);
        let screen = reply.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let sender = std::thread::spawn(move || {
            let mut slot = screen.0.lock().unwrap();
            locked_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            slot.take().unwrap().send(true).unwrap();
        });
        locked_rx.recv().unwrap();
        assert_eq!(
            reply.wait(&rx, std::time::Duration::from_millis(10)),
            Some(true)
        );
        sender.join().unwrap();
    }

    // A [Y] that reaches nobody is logged as timed out, not as approved.
    #[test]
    fn an_approval_nobody_receives_is_not_logged_as_approved() {
        use crossterm::event::KeyCode;
        let (mut t, tx) = tui();
        let (req, rx) = prompt(1);
        drop(rx);
        tx.send(super::TuiEvent::Approval(req)).unwrap();
        t.drain_events();
        t.approval_drawn();
        settle(&mut t);
        t.handle_key(key(KeyCode::Char('y')));
        let last = t.logs.last().unwrap();
        assert!(!last.success);
        assert_eq!(last.detail.as_deref(), Some("timed out"));
    }
}
