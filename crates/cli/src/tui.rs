//! Terminal UI for the host session.
//!
//! Renders a fixed layout with session info, QR code, and a scrolling event log.
//! The host event loop pushes state updates; the TUI redraws on each tick.

use std::collections::VecDeque;
use std::io::{self, Stdout, Write};
use std::time::Instant;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseEventKind,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
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
            Self::WaitingForPeer => Color::Rgb(0xe5, 0xc0, 0x7b), // muted yellow
            Self::Handshaking => Color::Rgb(0x56, 0xb6, 0xc2),    // cyan
            Self::Secure => Color::Rgb(0x7f, 0xd8, 0x8f),         // green
            Self::Disconnected => Color::Rgb(0xe0, 0x6c, 0x75),   // red
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
    pub pairing_uri: String,
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
    /// Visible width of QR code in terminal columns.
    pub qr_visible_width: u16,
    /// Log scroll offset from the bottom (0 = pinned to newest).
    pub log_scroll: usize,
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
            Self::Info => TEXT_MUTED,
            Self::Success => Color::Rgb(0x7f, 0xd8, 0x8f),
            Self::Warning => Color::Rgb(0xf5, 0xa7, 0x42),
            Self::Error => Color::Rgb(0xe0, 0x6c, 0x75),
        }
    }
}

const MAX_LOG_ENTRIES: usize = 200;

impl TuiState {
    pub fn new(info: SessionInfo, qr: QrCode) -> Self {
        Self {
            info,
            status: PeerStatus::WaitingForPeer,
            started_at: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            log: VecDeque::new(),
            qr_visible_width: qr.visible_width,
            qr_lines: qr.lines,
            log_scroll: 0,
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
        // Auto-scroll to bottom on new entries if already near the bottom.
        if self.log_scroll <= 3 {
            self.log_scroll = 0;
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
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        // Clear the alternate screen buffer completely.
        execute!(
            stdout,
            crossterm::terminal::Clear(ClearType::All),
            crossterm::cursor::MoveTo(0, 0)
        )?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;
        Ok(Self { terminal })
    }

    /// Restore the terminal to its original state.
    pub fn restore(&mut self) -> anyhow::Result<()> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            DisableMouseCapture,
            LeaveAlternateScreen
        )?;
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
    pub fn poll_action(
        &self,
        timeout: std::time::Duration,
        state: &mut TuiState,
    ) -> anyhow::Result<TuiAction> {
        if !event::poll(timeout)? {
            return Ok(TuiAction::None);
        }
        // Drain all pending events — mouse events from EnableMouseCapture
        // must be consumed so they don't block key events.
        loop {
            if !event::poll(std::time::Duration::ZERO)? {
                break;
            }
            match event::read()? {
                Event::Key(key) => {
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
                    if key.code == KeyCode::Char('c') {
                        return Ok(TuiAction::CopyUri);
                    }
                }
                Event::Mouse(mouse) => match mouse.kind {
                    MouseEventKind::ScrollUp => {
                        let max_scroll = state.log.len();
                        state.log_scroll = (state.log_scroll + 3).min(max_scroll);
                    }
                    MouseEventKind::ScrollDown => {
                        state.log_scroll = state.log_scroll.saturating_sub(3);
                    }
                    _ => {}
                },
                _ => continue,
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
    CopyUri,
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

// ── Rendering ────────────────────────────────────────────────────────

// ── Color palette (inspired by OpenCode's dark theme) ────────────────
const BG: Color = Color::Rgb(0x0a, 0x0a, 0x0a); // #0a0a0a — app background
const TEXT: Color = Color::Rgb(0xee, 0xee, 0xee); // #eeeeee — primary text
const TEXT_MUTED: Color = Color::Rgb(0x60, 0x60, 0x60); // #606060 — secondary text
const DIM: Color = Color::Rgb(0x48, 0x48, 0x48); // #484848 — labels, dividers
const SURFACE: Color = Color::Rgb(0x1e, 0x1e, 0x1e); // #1e1e1e — pill/element bg
const PRIMARY: Color = Color::Rgb(0xfa, 0xb2, 0x83); // #fab283 — brand accent

fn render(frame: &mut Frame, state: &TuiState) {
    let area = frame.area();

    // Fill entire screen with background color.
    let bg = Block::default().style(Style::default().bg(BG));
    frame.render_widget(bg, area);

    // Outer margin — no borders, just padding.
    let outer = Block::default()
        .style(Style::default().bg(BG))
        .padding(Padding::new(2, 2, 1, 0));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    // Title line at top.
    let title = Line::from(vec![
        Span::styled(
            "farwatch",
            Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {}", state.info.tool_name),
            Style::default().fg(TEXT_MUTED),
        ),
    ]);
    // +1 for title, +1 for blank after title
    let title_height = 2u16;

    // QR section width: visible QR width + 2 padding on each side.
    let qr_width = if state.qr_visible_width > 0 {
        state.qr_visible_width + 4
    } else {
        0
    };
    let qr_height = state.qr_lines.len() as u16 + 3; // 1 blank + lines + 1 blank + 1 label
                                                     // Show QR beside session info if it fits.
    let available_width = inner.width;
    let available_height = inner.height.saturating_sub(7); // title(2)+spacer(1)+log(3)+status(1)
    let show_qr_beside =
        !state.qr_lines.is_empty() && available_width >= 110 && qr_height + 2 <= available_height;
    let top_height = if show_qr_beside {
        qr_height.max(12)
    } else {
        12
    };

    let v_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(title_height), // title
            Constraint::Length(top_height),   // session info (+ QR if beside)
            Constraint::Length(1),            // spacer
            Constraint::Min(3),               // log
            Constraint::Length(1),            // status bar
        ])
        .split(inner);

    // Render title.
    frame.render_widget(Paragraph::new(title), v_chunks[0]);

    if show_qr_beside {
        // Session info fills left, QR fixed-size on right.
        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(0),           // session info — takes all remaining space
                Constraint::Length(2),        // gap
                Constraint::Length(qr_width), // QR — fixed to content width
            ])
            .split(v_chunks[1]);

        render_session_info(frame, top_chunks[0], state, false);
        render_qr(frame, top_chunks[2], state);
    } else {
        // Not enough room for QR — session info gets full width, show URI inline.
        render_session_info(frame, v_chunks[1], state, true);
    }

    // Spacer between top row and log (background color provides separation).

    render_log(frame, v_chunks[3], state);
    render_status_bar(frame, v_chunks[4], state);
}

fn render_session_info(frame: &mut Frame, area: Rect, state: &TuiState, show_uri: bool) {
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

    let mut lines = vec![
        Line::from(Span::styled("Session", Style::default().fg(TEXT_MUTED))),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tool      ", Style::default().fg(DIM)),
            Span::styled(
                &state.info.tool_name,
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  ID        ", Style::default().fg(DIM)),
            Span::styled(short_id, Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Status    ", Style::default().fg(DIM)),
            Span::styled(
                format!("{status_indicator} "),
                Style::default().fg(status_color),
            ),
            Span::styled(status_label, Style::default().fg(status_color)),
        ]),
        Line::from(vec![
            Span::styled("  Relay     ", Style::default().fg(DIM)),
            Span::styled(&state.info.relay_url, Style::default().fg(DIM)),
        ]),
        Line::from(vec![
            Span::styled("  Uptime    ", Style::default().fg(DIM)),
            Span::styled(format!("{mins}m {secs:02}s"), Style::default().fg(DIM)),
        ]),
        Line::from(vec![
            Span::styled("  Traffic   ", Style::default().fg(DIM)),
            Span::styled(bytes_label, Style::default().fg(DIM)),
        ]),
    ];

    if show_uri {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  QR code hidden — resize terminal to show",
            Style::default().fg(DIM),
        )));
    }

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_qr(frame: &mut Frame, area: Rect, state: &TuiState) {
    // Fill the entire QR area with a black background.
    let bg_block = Block::default()
        .style(Style::default().bg(Color::Black))
        .padding(Padding::horizontal(2));
    let inner = bg_block.inner(area);
    frame.render_widget(bg_block, area);

    let qr_style = Style::default().fg(TEXT).bg(Color::Black);
    let dim_style = Style::default().fg(DIM).bg(Color::Black);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    for qr_line in &state.qr_lines {
        lines.push(Line::from(Span::styled(qr_line.as_str(), qr_style)));
    }
    lines.push(Line::from(""));
    lines.push(
        Line::from(Span::styled("Scan with phone app", dim_style)).alignment(Alignment::Center),
    );

    let paragraph = Paragraph::new(lines)
        .style(Style::default().bg(Color::Black))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

const LOG_BG: Color = Color::Rgb(0x0f, 0x0f, 0x0f); // #0f0f0f — slightly lighter than app bg

fn render_log(frame: &mut Frame, area: Rect, state: &TuiState) {
    // Fill log area with darker background.
    let block = Block::default()
        .style(Style::default().bg(LOG_BG))
        .padding(Padding::new(1, 1, 0, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Section header takes 1 line, then content below.
    let header_area = Rect { height: 1, ..inner };
    let content_area = Rect {
        y: inner.y + 1,
        height: inner.height.saturating_sub(1),
        ..inner
    };

    let header = Line::from(Span::styled(
        "Log",
        Style::default().fg(TEXT_MUTED).bg(LOG_BG),
    ));
    frame.render_widget(Paragraph::new(header), header_area);

    // Show entries based on scroll offset.
    let visible_count = content_area.height as usize;
    let end = state.log.len().saturating_sub(state.log_scroll);
    let start = end.saturating_sub(visible_count);
    let lines: Vec<Line> = state
        .log
        .iter()
        .skip(start)
        .take(visible_count)
        .map(|entry| {
            Line::from(vec![
                Span::styled(
                    format!("  {}  ", entry.timestamp),
                    Style::default().fg(DIM).bg(LOG_BG),
                ),
                Span::styled(
                    &entry.message,
                    Style::default().fg(entry.level.color()).bg(LOG_BG),
                ),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines)
        .style(Style::default().bg(LOG_BG))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, content_area);
}

fn render_status_bar(frame: &mut Frame, area: Rect, state: &TuiState) {
    let fingerprint_short = if state.info.fingerprint.len() > 16 {
        &state.info.fingerprint[..16]
    } else {
        &state.info.fingerprint
    };

    let left = Line::from(vec![
        Span::styled(" q ", Style::default().fg(TEXT).bg(SURFACE)),
        Span::styled(" quit  ", Style::default().fg(DIM)),
        Span::styled(" Enter ", Style::default().fg(TEXT).bg(SURFACE)),
        Span::styled(" takeover  ", Style::default().fg(DIM)),
        Span::styled(" c ", Style::default().fg(TEXT).bg(SURFACE)),
        Span::styled(" copy uri ", Style::default().fg(DIM)),
    ]);

    let right = Line::from(vec![
        Span::styled(" fingerprint ", Style::default().fg(TEXT).bg(SURFACE)),
        Span::styled(format!(" {fingerprint_short} "), Style::default().fg(DIM)),
    ]);

    let left_widget = Paragraph::new(left);
    let right_widget = Paragraph::new(right).alignment(Alignment::Right);
    frame.render_widget(left_widget, area);
    frame.render_widget(right_widget, area);
}

/// Copy text to the system clipboard via the OSC 52 escape sequence.
/// Works in most modern terminals (iTerm2, kitty, alacritty, WezTerm, ghostty).
pub fn copy_to_clipboard(text: &str) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let encoded = STANDARD.encode(text);
    // OSC 52: \x1b]52;c;<base64>\x07
    let _ = write!(io::stdout(), "\x1b]52;c;{encoded}\x07");
    let _ = io::stdout().flush();
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

/// QR code rendered as half-block unicode lines, with the visible width.
pub struct QrCode {
    pub lines: Vec<String>,
    /// The visible width in terminal columns (modules + margin, no trailing spaces).
    pub visible_width: u16,
}

/// Render a QR code into half-block unicode lines.
/// Uses low error correction to minimize QR code size.
pub fn qr_to_lines(data: &str) -> anyhow::Result<QrCode> {
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
    // Visible width: the modules that actually contain QR data + margin on each side.
    // This excludes trailing spaces that pad each line to full grid width.
    let visible_width = (width as i32 + 2 * margin) as u16;

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
    Ok(QrCode {
        lines,
        visible_width,
    })
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
        assert_eq!(PeerStatus::Secure.color(), Color::Rgb(0x7f, 0xd8, 0x8f));
    }

    #[test]
    fn peer_status_colors_disconnected_is_red() {
        assert_eq!(
            PeerStatus::Disconnected.color(),
            Color::Rgb(0xe0, 0x6c, 0x75)
        );
    }

    // ── qr_to_lines ─────────────────────────────────────────────────

    #[test]
    fn qr_to_lines_produces_output() {
        let qr = qr_to_lines("test").unwrap();
        assert!(!qr.lines.is_empty());
        assert!(qr.visible_width > 0);
    }

    #[test]
    fn qr_to_lines_deterministic() {
        let a = qr_to_lines("hello").unwrap();
        let b = qr_to_lines("hello").unwrap();
        assert_eq!(a.lines, b.lines);
        assert_eq!(a.visible_width, b.visible_width);
    }

    // ── TuiState::push_log ──────────────────────────────────────────

    fn test_tui_state() -> TuiState {
        TuiState::new(
            SessionInfo {
                tool_name: "test".to_string(),
                session_id: "id".to_string(),
                relay_url: "ws://localhost".to_string(),
                fingerprint: "fp".to_string(),
                pairing_uri: "farwatch://pair?test=1".to_string(),
            },
            QrCode {
                lines: vec![],
                visible_width: 0,
            },
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
