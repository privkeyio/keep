#![forbid(unsafe_code)]

use std::io::{self, stdout};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

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

pub struct ApprovalRequest {
    pub id: u64,
    pub app: String,
    pub action: String,
    pub kind: Option<u16>,
    pub content_preview: Option<String>,
    pub response_tx: Sender<bool>,
}

pub enum TuiEvent {
    Log(LogEntry),
    Approval(ApprovalRequest),
    Quit,
}

pub struct Tui {
    bunker_url: String,
    npub: String,
    relay: String,
    logs: Vec<LogEntry>,
    pending_approval: Option<ApprovalRequest>,
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
                event_rx: rx,
                should_quit: false,
            },
            tx,
        )
    }

    pub fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

        while !self.should_quit {
            terminal.draw(|f| self.draw(f))?;
            self.handle_events()?;
        }

        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;
        Ok(())
    }

    fn handle_events(&mut self) -> io::Result<()> {
        while let Ok(evt) = self.event_rx.try_recv() {
            match evt {
                TuiEvent::Log(entry) => {
                    self.logs.push(entry);
                    if self.logs.len() > 100 {
                        self.logs.remove(0);
                    }
                }
                TuiEvent::Approval(req) => {
                    self.pending_approval = Some(req);
                }
                TuiEvent::Quit => {
                    self.should_quit = true;
                }
            }
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            if self.pending_approval.is_none() {
                                self.should_quit = true;
                            }
                        }
                        KeyCode::Char('y') | KeyCode::Enter => {
                            if let Some(req) = self.pending_approval.take() {
                                let _ = req.response_tx.send(true);
                                self.logs.push(LogEntry::new(&req.app, &req.action, true));
                            }
                        }
                        KeyCode::Char('n') => {
                            if let Some(req) = self.pending_approval.take() {
                                let _ = req.response_tx.send(false);
                                self.logs.push(
                                    LogEntry::new(&req.app, &req.action, false)
                                        .with_detail("rejected"),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
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
            Line::from(vec![
                Span::styled("Bunker URL: ", Style::default().fg(Color::Gray)),
            ]),
            Line::from(Span::styled(&self.bunker_url, Style::default().fg(Color::Cyan))),
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
                let mut spans = vec![
                    Span::styled(
                        format!("[{}] ", entry.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(format!("{} ", symbol), Style::default().fg(color)),
                    Span::styled(&entry.app, Style::default().fg(Color::White)),
                    Span::raw(" "),
                    Span::styled(&entry.action, Style::default().fg(Color::Gray)),
                ];
                if let Some(ref detail) = entry.detail {
                    spans.push(Span::styled(
                        format!(" ({})", detail),
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

        if let Some(ref content) = req.content_preview {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Content:",
                Style::default().fg(Color::Gray),
            )));
            let preview: String = content.chars().take(200).collect();
            lines.push(Line::from(Span::styled(preview, Style::default().fg(Color::White))));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Press [Y] to approve, [N] to reject",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
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
