//! Terminal UI for the host session.
//!
//! Renders a fixed layout with session info, QR code, and a scrolling event log.
//! The host event loop pushes state updates; the TUI redraws on each tick.

use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::time::Instant;

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
    Frame, Terminal,
};

// ── Public state model ───────────────────────────────────────────────

/// Connection status shown in the session panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    WaitingForPeer,
    Handshaking,
    Secure,
    Disconnected,
}

impl PeerStatus {
    fn label(&self) -> &str {
        match self {
            Self::WaitingForPeer => "Waiting for peer",
            Self::Handshaking => "Handshaking...",
            Self::Secure => "Secure",
            Self::Disconnected => "Disconnected",
        }
    }

    fn color(&self) -> Color {
        match self {
            Self::WaitingForPeer => Color::Yellow,
            Self::Handshaking => Color::Cyan,
            Self::Secure => Color::Green,
            Self::Disconnected => Color::Red,
        }
    }

    fn indicator(&self) -> &str {
        match self {
            Self::Secure => "●",
            Self::Disconnected => "○",
            _ => "◌",
        }
    }
}

/// Immutable session info set at startup.
pub struct SessionInfo {
    pub tool_name: String,
    pub session_id: String,
    pub relay_url: String,
    pub fingerprint: String,
}

/// Mutable state that the host event loop updates.
pub struct TuiState {
    pub info: SessionInfo,
    pub status: PeerStatus,
    pub started_at: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub log: VecDeque<LogEntry>,
    /// Pre-rendered QR code lines (half-block unicode).
    pub qr_lines: Vec<String>,
}

pub struct LogEntry {
    pub timestamp: String,
    pub message: String,
    pub level: LogLevel,
}

#[derive(Clone, Copy)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl LogLevel {
    fn color(self) -> Color {
        match self {
            Self::Info => Color::DarkGray,
            Self::Success => Color::Green,
            Self::Warning => Color::Yellow,
            Self::Error => Color::Red,
        }
    }
}

const MAX_LOG_ENTRIES: usize = 200;

impl TuiState {
    pub fn new(info: SessionInfo, qr_lines: Vec<String>) -> Self {
        Self {
            info,
            status: PeerStatus::WaitingForPeer,
            started_at: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            log: VecDeque::new(),
            qr_lines,
        }
    }

    pub fn push_log(&mut self, level: LogLevel, message: impl Into<String>) {
        let elapsed = self.started_at.elapsed().as_secs();
        let mins = elapsed / 60;
        let secs = elapsed % 60;
        self.log.push_back(LogEntry {
            timestamp: format!("{mins:02}:{secs:02}"),
            message: message.into(),
            level,
        });
        while self.log.len() > MAX_LOG_ENTRIES {
            self.log.pop_front();
        }
    }
}

// ── Terminal setup / teardown ────────────────────────────────────────

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    pub fn new() -> anyhow::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    /// Restore the terminal to its original state.
    pub fn restore(&mut self) -> anyhow::Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    /// Draw the full UI from current state.
    pub fn draw(&mut self, state: &TuiState) -> anyhow::Result<()> {
        self.terminal.draw(|frame| {
            render(frame, state);
        })?;
        Ok(())
    }

    /// Poll for a terminal event with a timeout.
    /// Returns `TuiAction::Quit` if the user wants to quit,
    /// `TuiAction::Takeover` if they want to take over the PTY,
    /// or `TuiAction::None` otherwise.
    pub fn poll_action(&self, timeout: std::time::Duration) -> anyhow::Result<TuiAction> {
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q')
                    || key.code == KeyCode::Char('Q')
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    return Ok(TuiAction::Quit);
                }
                if key.code == KeyCode::Enter {
                    return Ok(TuiAction::Takeover);
                }
            }
        }
        Ok(TuiAction::None)
    }

    /// Suspend the TUI: leave alternate screen so the real terminal is visible.
    /// Call `resume()` to restore.
    pub fn suspend(&mut self) -> anyhow::Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    /// Resume the TUI: re-enter alternate screen and raw mode.
    pub fn resume(&mut self) -> anyhow::Result<()> {
        enable_raw_mode()?;
        execute!(self.terminal.backend_mut(), EnterAlternateScreen)?;
        self.terminal.clear()?;
        Ok(())
    }
}

/// Actions returned by `poll_action`.
pub enum TuiAction {
    None,
    Quit,
    Takeover,
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

// ── Rendering ────────────────────────────────────────────────────────

fn render(frame: &mut Frame, state: &TuiState) {
    let area = frame.area();

    // Outer border.
    let outer = Block::default()
        .title(Line::from(vec![Span::styled(
            " farwatch ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .padding(Padding::new(1, 1, 0, 0));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    // QR height is known: lines + 2 (blank + label) + 2 (border). Session info
    // panel needs ~10 rows. Use the larger of the two as the fixed top height,
    // and let the log panel fill the remaining space.
    let qr_content_height = state.qr_lines.len() as u16 + 2; // lines + blank + label
    let qr_panel_height = qr_content_height + 2; // + top/bottom border
    let top_height = qr_panel_height.max(12); // at least 12 for session info

    let v_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top_height), // top: session info + QR (fixed to QR height)
            Constraint::Length(1),          // spacer
            Constraint::Min(4),             // log: fills remaining space
            Constraint::Length(1),          // status bar
        ])
        .split(inner);

    // Top: horizontal split into session info (left) and QR code (right).
    let qr_width = state
        .qr_lines
        .first()
        .map(|l| l.len() as u16 + 4)
        .unwrap_or(20);
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(30), Constraint::Length(qr_width.max(28))])
        .split(v_chunks[0]);

    render_session_info(frame, top_chunks[0], state);
    render_qr(frame, top_chunks[1], state);
    render_log(frame, v_chunks[2], state);
    render_status_bar(frame, v_chunks[3], state);
}

fn render_session_info(frame: &mut Frame, area: Rect, state: &TuiState) {
    let elapsed = state.started_at.elapsed().as_secs();
    let mins = elapsed / 60;
    let secs = elapsed % 60;

    let status_color = state.status.color();
    let status_indicator = state.status.indicator();
    let status_label = state.status.label();

    let short_id = if state.info.session_id.len() > 12 {
        &state.info.session_id[..12]
    } else {
        &state.info.session_id
    };

    let bytes_label = format_bytes(state.bytes_sent + state.bytes_received);

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tool:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &state.info.tool_name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Session:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(short_id, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Status:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{status_indicator} "),
                Style::default().fg(status_color),
            ),
            Span::styled(status_label, Style::default().fg(status_color)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Relay:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(&state.info.relay_url, Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  Uptime:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{mins}m {secs:02}s"),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Traffic:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(bytes_label, Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let block = Block::default()
        .title(Span::styled(" Session ", Style::default().fg(Color::White)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

fn render_qr(frame: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .title(Span::styled(" QR Code ", Style::default().fg(Color::White)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    // Available height inside the block (minus borders).
    let inner_height = area.height.saturating_sub(2) as usize;
    // QR lines + 1 blank + 1 label = total needed.
    let qr_height = state.qr_lines.len() + 2;

    let mut lines: Vec<Line> = Vec::new();

    if !state.qr_lines.is_empty() && qr_height <= inner_height {
        lines.push(Line::from(""));
        for qr_line in &state.qr_lines {
            lines.push(Line::from(Span::styled(
                format!(" {qr_line}"),
                Style::default().fg(Color::White),
            )));
        }
        lines.push(Line::from(""));
        lines.push(
            Line::from(Span::styled(
                "Scan with phone app",
                Style::default().fg(Color::DarkGray),
            ))
            .alignment(Alignment::Center),
        );
    } else {
        // Terminal too small for QR — show fallback.
        lines.push(Line::from(""));
        lines.push(
            Line::from(Span::styled(
                "Terminal too small",
                Style::default().fg(Color::DarkGray),
            ))
            .alignment(Alignment::Center),
        );
        lines.push(
            Line::from(Span::styled(
                "for QR code.",
                Style::default().fg(Color::DarkGray),
            ))
            .alignment(Alignment::Center),
        );
        lines.push(Line::from(""));
        lines.push(
            Line::from(Span::styled(
                "Use pairing URI from",
                Style::default().fg(Color::DarkGray),
            ))
            .alignment(Alignment::Center),
        );
        lines.push(
            Line::from(Span::styled(
                "`farwatch sessions`",
                Style::default().fg(Color::Yellow),
            ))
            .alignment(Alignment::Center),
        );
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

fn render_log(frame: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .title(Span::styled(" Log ", Style::default().fg(Color::White)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .padding(Padding::new(1, 1, 0, 0));
    let inner = block.inner(area);

    // Show only the most recent entries that fit.
    let visible_count = inner.height as usize;
    let start = state.log.len().saturating_sub(visible_count);
    let lines: Vec<Line> = state
        .log
        .iter()
        .skip(start)
        .map(|entry| {
            Line::from(vec![
                Span::styled(
                    format!("  {}  ", entry.timestamp),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(&entry.message, Style::default().fg(entry.level.color())),
            ])
        })
        .collect();

    frame.render_widget(block, area);
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

fn render_status_bar(frame: &mut Frame, area: Rect, state: &TuiState) {
    let fingerprint_short = if state.info.fingerprint.len() > 16 {
        &state.info.fingerprint[..16]
    } else {
        &state.info.fingerprint
    };

    let left = Line::from(vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " Enter ",
            Style::default().fg(Color::Black).bg(Color::DarkGray),
        ),
        Span::styled(" takeover ", Style::default().fg(Color::DarkGray)),
    ]);

    let right = Line::from(vec![
        Span::styled(
            " fingerprint ",
            Style::default().fg(Color::Black).bg(Color::DarkGray),
        ),
        Span::styled(
            format!(" {fingerprint_short} "),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let left_widget = Paragraph::new(left);
    let right_widget = Paragraph::new(right).alignment(ratatui::layout::Alignment::Right);
    frame.render_widget(left_widget, area);
    frame.render_widget(right_widget, area);
}

// ── Helpers ──────────────────────────────────────────────────────────

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Render a QR code into half-block unicode lines.
/// Uses low error correction to minimize QR code size.
pub fn qr_to_lines(data: &str) -> anyhow::Result<Vec<String>> {
    use anyhow::Context;
    let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
        .context("failed generating QR code")?;
    let width = code.width();
    let modules: Vec<bool> = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();

    let get = |row: i32, col: i32| -> bool {
        if row < 0 || col < 0 || row >= width as i32 || col >= width as i32 {
            false
        } else {
            modules[row as usize * width + col as usize]
        }
    };

    let margin = 1i32;
    let mut lines = Vec::new();
    let mut row = -margin;
    while row < width as i32 + margin {
        let mut line = String::new();
        for col in -margin..width as i32 + margin {
            let top = get(row, col);
            let bottom = get(row + 1, col);
            line.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        lines.push(line);
        row += 2;
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_bytes ─────────────────────────────────────────────────

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn format_bytes_below_kb() {
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn format_bytes_boundary_1023() {
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_exact_kb() {
        assert_eq!(format_bytes(1024), "1.0 KB");
    }

    #[test]
    fn format_bytes_kb_range() {
        assert_eq!(format_bytes(5120), "5.0 KB");
    }

    #[test]
    fn format_bytes_boundary_just_under_mb() {
        let result = format_bytes(1024 * 1024 - 1);
        assert!(result.contains("KB"));
    }

    #[test]
    fn format_bytes_exact_mb() {
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn format_bytes_mb_range() {
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }

    // ── PeerStatus ───────────────────────────────────────────────────

    #[test]
    fn peer_status_labels() {
        assert_eq!(PeerStatus::WaitingForPeer.label(), "Waiting for peer");
        assert_eq!(PeerStatus::Handshaking.label(), "Handshaking...");
        assert_eq!(PeerStatus::Secure.label(), "Secure");
        assert_eq!(PeerStatus::Disconnected.label(), "Disconnected");
    }

    #[test]
    fn peer_status_indicators() {
        assert_eq!(PeerStatus::Secure.indicator(), "●");
        assert_eq!(PeerStatus::Disconnected.indicator(), "○");
        assert_eq!(PeerStatus::WaitingForPeer.indicator(), "◌");
        assert_eq!(PeerStatus::Handshaking.indicator(), "◌");
    }

    #[test]
    fn peer_status_colors_secure_is_green() {
        assert_eq!(PeerStatus::Secure.color(), Color::Green);
    }

    #[test]
    fn peer_status_colors_disconnected_is_red() {
        assert_eq!(PeerStatus::Disconnected.color(), Color::Red);
    }

    // ── qr_to_lines ─────────────────────────────────────────────────

    #[test]
    fn qr_to_lines_produces_output() {
        let lines = qr_to_lines("test").unwrap();
        assert!(!lines.is_empty());
    }

    #[test]
    fn qr_to_lines_deterministic() {
        let a = qr_to_lines("hello").unwrap();
        let b = qr_to_lines("hello").unwrap();
        assert_eq!(a, b);
    }

    // ── TuiState::push_log ──────────────────────────────────────────

    fn test_tui_state() -> TuiState {
        TuiState::new(
            SessionInfo {
                tool_name: "test".to_string(),
                session_id: "id".to_string(),
                relay_url: "ws://localhost".to_string(),
                fingerprint: "fp".to_string(),
            },
            vec![],
        )
    }

    #[test]
    fn push_log_adds_entry() {
        let mut state = test_tui_state();
        state.push_log(LogLevel::Info, "hello");
        assert_eq!(state.log.len(), 1);
        assert_eq!(state.log[0].message, "hello");
    }

    #[test]
    fn push_log_caps_at_max() {
        let mut state = test_tui_state();
        for i in 0..=MAX_LOG_ENTRIES {
            state.push_log(LogLevel::Info, format!("msg-{i}"));
        }
        assert_eq!(state.log.len(), MAX_LOG_ENTRIES);
    }

    #[test]
    fn push_log_evicts_oldest() {
        let mut state = test_tui_state();
        for i in 0..=MAX_LOG_ENTRIES {
            state.push_log(LogLevel::Info, format!("msg-{i}"));
        }
        // msg-0 should have been evicted, msg-1 is now first
        assert_eq!(state.log.front().unwrap().message, "msg-1");
    }
}
