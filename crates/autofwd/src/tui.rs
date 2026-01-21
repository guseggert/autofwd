use anyhow::Result;
use crossterm::{
    event::{Event as CrosstermEvent, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use futures::StreamExt;
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
    },
};
use std::io::{stdout, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

use crate::events::Event as JsonEvent;
use crate::probe::Protocol;

const MAX_EVENTS: usize = 1000;

/// A forwarded port entry for display.
#[derive(Clone, Debug)]
pub struct ForwardedPort {
    pub remote_port: u16,
    pub local_port: u16,
    pub remote_host: String,
    pub forwarded_at: Instant,
    pub enabled: bool,
    pub protocol: Protocol,
    pub process_name: Option<String>,
}

/// Commands from TUI to monitor for toggling forwards.
#[derive(Debug)]
pub enum TuiCommand {
    ToggleForward { index: usize },
}

/// Channel for emitting JSON events in headless mode.
pub type EventSender = mpsc::UnboundedSender<JsonEvent>;

/// Monitor mode indicator for the TUI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum MonitorModeDisplay {
    #[default]
    Unknown,
    /// Using the deployed agent binary (with process names).
    Agent,
    /// Fallback to shell script (no process names).
    Shell,
}

/// Shared state between the monitor and the TUI.
#[derive(Debug, Default)]
pub struct TuiState {
    pub status: String,
    pub forwarded: Vec<ForwardedPort>,
    pub should_quit: bool,
    pub selected: usize,
    pub events: Vec<JsonEvent>,
    /// Current monitoring mode (agent or shell fallback).
    pub monitor_mode: MonitorModeDisplay,
    /// Optional channel for JSON events (headless mode)
    #[allow(dead_code)]
    event_tx: Option<EventSender>,
}

impl TuiState {
    /// Add an event to the log (keeps last MAX_EVENTS) and emit it.
    pub fn push_event(&mut self, event: JsonEvent) {
        // Also emit for headless mode JSON output
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event.clone());
        }
        self.events.push(event);
        if self.events.len() > MAX_EVENTS {
            self.events.remove(0);
        }
    }

    /// Emit a structured event (for headless mode JSON output only, not stored).
    pub fn emit(&self, event: JsonEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }
}

/// Local UI state (not shared with monitor).
#[derive(Debug, Default)]
struct UiState {
    show_help: bool,
    show_process: bool,
    show_quit_confirm: bool,
    table_state: TableState,
    // Events view state
    events_view: bool,
    events_list_state: ListState,
    events_filter: String,
    events_filter_active: bool,
    events_auto_follow: bool,
}

pub type SharedState = Arc<RwLock<TuiState>>;
pub type CommandSender = mpsc::Sender<TuiCommand>;
pub type CommandReceiver = mpsc::Receiver<TuiCommand>;

/// Notifier to trigger TUI redraws when state changes.
pub type RedrawNotify = Arc<tokio::sync::Notify>;

/// Unified event type for the TUI event loop.
/// All events (keyboard, resize, tick, state changes) flow through a single channel.
#[derive(Debug)]
pub enum TuiEvent {
    /// Keyboard input
    Key(KeyEvent),
    /// Terminal resize (triggers redraw)
    Resize,
    /// Periodic tick for updating time-based displays (age column)
    Tick,
    /// Monitor state changed (ports added/removed, status update)
    StateChanged,
}

pub fn new_shared_state(event_tx: Option<EventSender>) -> (SharedState, RedrawNotify) {
    let state = Arc::new(RwLock::new(TuiState {
        status: "connecting...".to_string(),
        forwarded: Vec::new(),
        should_quit: false,
        selected: 0,
        events: Vec::new(),
        monitor_mode: MonitorModeDisplay::Unknown,
        event_tx,
    }));
    let notify = Arc::new(tokio::sync::Notify::new());
    (state, notify)
}

pub fn new_command_channel() -> (CommandSender, CommandReceiver) {
    mpsc::channel(16)
}

/// Terminal wrapper that handles setup/teardown.
pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    pub fn new() -> Result<Self> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn restore(&mut self) -> Result<()> {
        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;
        Ok(())
    }

    fn draw(&mut self, state: &TuiState, ui: &mut UiState, target: &str) -> Result<()> {
        // Sync table selection with TuiState
        ui.table_state.select(if state.forwarded.is_empty() {
            None
        } else {
            Some(state.selected)
        });

        self.terminal.draw(|frame| {
            let area = frame.area();

            if ui.events_view {
                // Full-screen events view
                render_events_view(frame, area, state, ui);
            } else {
                // Main view
                render_main_view(frame, area, state, ui, target);

                // Render overlays on top
                if ui.show_help {
                    render_help_overlay(frame, area);
                }

                if ui.show_quit_confirm {
                    render_quit_confirm(frame, area);
                }
            }
        })?;
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Render the main ports view.
fn render_main_view(
    frame: &mut Frame,
    area: Rect,
    state: &TuiState,
    ui: &mut UiState,
    target: &str,
) {
    // Layout: header, main content, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // Table
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // Header with monitor mode indicator (right-aligned)
    let (mode_text, mode_style) = match state.monitor_mode {
        MonitorModeDisplay::Agent => ("[agent]", Style::default().fg(Color::Green)),
        MonitorModeDisplay::Shell => ("[shell]", Style::default().fg(Color::Yellow)),
        MonitorModeDisplay::Unknown => ("", Style::default()),
    };
    let left_text = format!(" {} - {}", target, state.status);
    let available_width = chunks[0].width.saturating_sub(2) as usize;
    let padding_len = available_width
        .saturating_sub(left_text.len())
        .saturating_sub(mode_text.len())
        .saturating_sub(1);
    let header_line = Line::from(vec![
        Span::raw(left_text),
        Span::raw(" ".repeat(padding_len)),
        Span::styled(mode_text, mode_style),
    ]);
    let header = Paragraph::new(header_line)
        .block(Block::default().borders(Borders::ALL).title(" autofwd "));
    frame.render_widget(header, chunks[0]);

    // Forwarded ports table
    let header_cells: Vec<Cell> = if ui.show_process {
        vec![
            Cell::from(" "),
            Cell::from("Remote"),
            Cell::from("Local"),
            Cell::from("Process"),
            Cell::from("Address"),
            Cell::from("Age"),
        ]
    } else {
        vec![
            Cell::from(" "),
            Cell::from("Remote"),
            Cell::from("Local"),
            Cell::from("Address"),
            Cell::from("Age"),
        ]
    };
    let header_row = Row::new(header_cells).style(Style::default().fg(Color::Yellow).bold());

    let rows: Vec<Row> = state
        .forwarded
        .iter()
        .map(|fwd| {
            let age = fwd.forwarded_at.elapsed();
            let age_str = format_duration(age);
            let status_icon = if fwd.enabled { "●" } else { "○" };
            let style = if fwd.enabled {
                Style::default()
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let address = if fwd.enabled {
                fwd.protocol.format_address(fwd.local_port)
            } else {
                "(disabled)".to_string()
            };
            let cells: Vec<Cell> = if ui.show_process {
                let process = fwd.process_name.as_deref().unwrap_or("-");
                vec![
                    Cell::from(status_icon),
                    Cell::from(format!(":{}", fwd.remote_port)),
                    Cell::from(format!(":{}", fwd.local_port)),
                    Cell::from(process),
                    Cell::from(address),
                    Cell::from(age_str),
                ]
            } else {
                vec![
                    Cell::from(status_icon),
                    Cell::from(format!(":{}", fwd.remote_port)),
                    Cell::from(format!(":{}", fwd.local_port)),
                    Cell::from(address),
                    Cell::from(age_str),
                ]
            };
            Row::new(cells).style(style)
        })
        .collect();

    let widths: Vec<Constraint> = if ui.show_process {
        vec![
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(15),
            Constraint::Min(25),
            Constraint::Length(10),
        ]
    } else {
        vec![
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(25),
            Constraint::Length(10),
        ]
    };
    let table = Table::new(rows, widths)
        .header(header_row)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Forwarded Ports "),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .highlight_symbol("→ ");
    frame.render_stateful_widget(table, chunks[1], &mut ui.table_state);

    // Footer
    let footer = Paragraph::new(" ↑/↓ navigate • space toggle • ? help • q quit")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);
}

/// Render the full-screen events view.
fn render_events_view(frame: &mut Frame, area: Rect, state: &TuiState, ui: &mut UiState) {
    // Layout: header with filter, events list, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header/filter
            Constraint::Min(5),    // Events list
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // Filter events
    let filtered_events: Vec<_> = if ui.events_filter.is_empty() {
        state.events.iter().collect()
    } else {
        let filter_lower = ui.events_filter.to_lowercase();
        state
            .events
            .iter()
            .filter(|e| format_event(e).to_lowercase().contains(&filter_lower))
            .collect()
    };

    let total_events = filtered_events.len();

    // Header with filter input and count
    let filter_display = if ui.events_filter.is_empty() {
        if ui.events_filter_active {
            "filter: _".to_string()
        } else {
            format!("{} events", total_events)
        }
    } else {
        format!(
            "filter: {}{} ({} matches)",
            ui.events_filter,
            if ui.events_filter_active { "_" } else { "" },
            total_events
        )
    };
    let header = Paragraph::new(format!(" {}", filter_display))
        .block(Block::default().borders(Borders::ALL).title(" Events "));
    frame.render_widget(header, chunks[0]);

    // Build list items
    let items: Vec<ListItem> = filtered_events
        .iter()
        .map(|e| {
            ListItem::new(format!(" {}", format_event(e))).style(Style::default().fg(Color::Cyan))
        })
        .collect();

    // Handle selection
    if total_events == 0 {
        ui.events_list_state.select(None);
    } else if ui.events_auto_follow {
        // Auto-follow: always select the last item
        ui.events_list_state.select(Some(total_events - 1));
    } else {
        // Clamp selection to valid range
        let selected = ui.events_list_state.selected().unwrap_or(0);
        if selected >= total_events {
            ui.events_list_state.select(Some(total_events - 1));
        }
    }

    // Show position indicator in title (with auto-follow indicator)
    let position_info = if total_events > 0 {
        let selected = ui.events_list_state.selected().unwrap_or(0) + 1;
        let follow_indicator = if ui.events_auto_follow { " auto" } else { "" };
        format!(" [{}/{}{}] ", selected, total_events, follow_indicator)
    } else {
        String::new()
    };

    let events_list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Log{}", position_info)),
        )
        .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .highlight_symbol("→ ");
    frame.render_stateful_widget(events_list, chunks[1], &mut ui.events_list_state);

    // Footer with controls
    let footer_text = if ui.events_filter_active {
        " Type to filter • Enter confirm • Esc cancel"
    } else {
        " ↑/↓ scroll • / filter • e/Esc close"
    };
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);
}

/// Render a centered popup.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}

/// Render the help overlay.
fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let help_text = vec![
        "",
        "  Keyboard Shortcuts",
        "  ──────────────────",
        "",
        "  ↑/k/^P   Move selection up",
        "  ↓/j/^N   Move selection down",
        "  Space    Toggle port forwarding",
        "  p        Toggle process column",
        "  e        Open events view",
        "  ?        Show/hide this help",
        "  q/Esc    Quit (with confirmation)",
        "",
        "  Press any key to close",
        "",
    ];

    let popup_area = centered_rect(42, help_text.len() as u16 + 2, area);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let help = Paragraph::new(help_text.join("\n"))
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Help "),
        );
    frame.render_widget(help, popup_area);
}

/// Render the quit confirmation dialog.
fn render_quit_confirm(frame: &mut Frame, area: Rect) {
    let lines = [
        "",
        "  Are you sure you want to quit?",
        "",
        "  This will close all port forwards.",
        "",
        "  [y] Yes    [n] No",
        "",
    ];
    let popup_area = centered_rect(42, lines.len() as u16 + 2, area);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let confirm = Paragraph::new(lines.join("\n"))
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" Quit? "),
        );
    frame.render_widget(confirm, popup_area);
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Format a JSON event for display in the TUI event log.
fn format_event(event: &JsonEvent) -> String {
    use crate::events::Event;

    match event {
        Event::ForwardAdded {
            ts,
            remote_port,
            local_port,
            ..
        } => {
            if remote_port == local_port {
                format!("{} + forwarded :{}", ts.to_rfc3339(), remote_port)
            } else {
                format!(
                    "{} + forwarded :{} → :{}",
                    ts.to_rfc3339(),
                    remote_port,
                    local_port
                )
            }
        }
        Event::ProtocolDetected {
            ts,
            local_port,
            protocol,
        } => format!(
            "{} ~ detected {} on :{}",
            ts.to_rfc3339(),
            protocol,
            local_port
        ),
        Event::ForwardRemoved { ts, remote_port } => {
            format!("{} - removed :{}", ts.to_rfc3339(), remote_port)
        }
        Event::ForwardDisabled { ts, remote_port } => {
            format!("{} ○ disabled :{}", ts.to_rfc3339(), remote_port)
        }
        Event::ForwardEnabled {
            ts,
            remote_port,
            local_port,
        } => {
            if remote_port == local_port {
                format!("{} ● enabled :{}", ts.to_rfc3339(), remote_port)
            } else {
                format!(
                    "{} ● enabled :{} → :{}",
                    ts.to_rfc3339(),
                    remote_port,
                    local_port
                )
            }
        }
        Event::ConnectionLost { ts } => {
            format!("{} ! connection lost", ts.to_rfc3339())
        }
        Event::Reconnecting { ts, delay_ms } => {
            format!("{} ! reconnecting in {}ms", ts.to_rfc3339(), delay_ms)
        }
        Event::Reconnected { ts } => {
            format!("{} ✓ reconnected", ts.to_rfc3339())
        }
        Event::ServiceRestarted { ts, remote_port } => {
            format!("{} ↻ service restarted :{}", ts.to_rfc3339(), remote_port)
        }
        Event::Error { ts, message } => {
            format!("{} ✗ {}", ts.to_rfc3339(), message)
        }
        Event::Ready { ts, target } => {
            format!("{} ✓ ready: {}", ts.to_rfc3339(), target)
        }
        Event::Shutdown { ts } => {
            format!("{} shutdown", ts.to_rfc3339())
        }
        Event::AgentDeploying { ts, arch } => {
            format!("{} deploying agent ({})", ts.to_rfc3339(), arch)
        }
        Event::AgentDeployed { ts, arch, .. } => {
            format!("{} ✓ agent deployed ({})", ts.to_rfc3339(), arch)
        }
        Event::AgentFallback { ts, reason } => {
            format!("{} ! {}", ts.to_rfc3339(), reason)
        }
        Event::Timing {
            ts,
            phase,
            duration_ms,
        } => {
            format!("{} [timing] {} {}ms", ts.to_rfc3339(), phase, duration_ms)
        }
    }
}

/// Spawn background tasks that feed events into a unified channel.
/// Returns a receiver for all TUI events.
fn spawn_event_handler(redraw_notify: RedrawNotify) -> mpsc::UnboundedReceiver<TuiEvent> {
    let (tx, rx) = mpsc::unbounded_channel();

    // Task 1: Crossterm terminal events (keyboard, resize)
    let tx_term = tx.clone();
    tokio::spawn(async move {
        let mut event_stream = EventStream::new();
        while let Some(event) = event_stream.next().await {
            let event = match event {
                Ok(CrosstermEvent::Key(key)) if key.kind == KeyEventKind::Press => {
                    TuiEvent::Key(key)
                }
                Ok(CrosstermEvent::Resize(_, _)) => TuiEvent::Resize,
                Ok(_) => continue, // Ignore mouse, focus, paste events
                Err(_) => break,   // Stream error, exit
            };
            if tx_term.send(event).is_err() {
                break; // Receiver dropped
            }
        }
    });

    // Task 2: Tick timer for age column updates (1 second)
    let tx_tick = tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if tx_tick.send(TuiEvent::Tick).is_err() {
                break; // Receiver dropped
            }
        }
    });

    // Task 3: State change notifications from monitor
    let tx_state = tx;
    tokio::spawn(async move {
        loop {
            redraw_notify.notified().await;
            if tx_state.send(TuiEvent::StateChanged).is_err() {
                break; // Receiver dropped
            }
        }
    });

    rx
}

/// Run the TUI event loop.
pub async fn run_tui(
    state: SharedState,
    target: String,
    cmd_tx: CommandSender,
    redraw_notify: RedrawNotify,
) -> Result<()> {
    let mut tui = Tui::new()?;
    let mut ui = UiState {
        show_help: false,
        show_process: false, // Process column hidden by default
        show_quit_confirm: false,
        table_state: TableState::default(),
        events_view: false,
        events_list_state: ListState::default(),
        events_filter: String::new(),
        events_filter_active: false,
        events_auto_follow: true,
    };

    // Unified event channel - all events flow through here
    let mut events = spawn_event_handler(redraw_notify);

    // Initial draw
    {
        let s = state.read().await;
        tui.draw(&s, &mut ui, &target)?;
    }

    // Main event loop - simple recv from unified channel
    while let Some(event) = events.recv().await {
        // Check for quit (set by Ctrl+C signal handler)
        if state.read().await.should_quit {
            break;
        }

        match event {
            TuiEvent::Key(key) => {
                handle_key_event(key, &state, &mut ui, &cmd_tx).await;
            }
            TuiEvent::Resize | TuiEvent::Tick | TuiEvent::StateChanged => {
                // Just redraw below
            }
        }

        // Redraw after every event
        let s = state.read().await;
        if s.should_quit {
            break;
        }
        tui.draw(&s, &mut ui, &target)?;
    }

    Ok(())
}

/// Handle keyboard input, updating UI and shared state as needed.
async fn handle_key_event(
    key: KeyEvent,
    state: &SharedState,
    ui: &mut UiState,
    cmd_tx: &CommandSender,
) {
    // Ctrl+C quits immediately from anywhere
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.write().await.should_quit = true;
        return;
    }

    // Handle quit confirmation dialog
    if ui.show_quit_confirm {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                state.write().await.should_quit = true;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                ui.show_quit_confirm = false;
            }
            _ => {}
        }
        return;
    }

    // Help overlay - any key closes it
    if ui.show_help {
        ui.show_help = false;
        return;
    }

    // Events view has its own key handling
    if ui.events_view {
        handle_events_view_keys(key, state, ui).await;
        return;
    }

    // Normal key handling (main view)
    let is_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    if is_ctrl {
        match key.code {
            KeyCode::Char('p') => {
                let mut s = state.write().await;
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            KeyCode::Char('n') => {
                let mut s = state.write().await;
                let len = s.forwarded.len();
                if len > 0 && s.selected < len - 1 {
                    s.selected += 1;
                }
            }
            _ => {}
        }
    } else {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                ui.show_quit_confirm = true;
            }
            KeyCode::Char('?') => {
                ui.show_help = true;
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                // Open events view with auto-follow enabled
                ui.events_view = true;
                ui.events_auto_follow = true;
                // Selection will be set to last event by render_events_view
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                ui.show_process = !ui.show_process;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let mut s = state.write().await;
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let mut s = state.write().await;
                let len = s.forwarded.len();
                if len > 0 && s.selected < len - 1 {
                    s.selected += 1;
                }
            }
            KeyCode::Char(' ') => {
                let s = state.read().await;
                if !s.forwarded.is_empty() {
                    let _ = cmd_tx
                        .send(TuiCommand::ToggleForward { index: s.selected })
                        .await;
                }
            }
            _ => {}
        }
    }
}

/// Handle keyboard input in the events view.
async fn handle_events_view_keys(key: KeyEvent, state: &SharedState, ui: &mut UiState) {
    // If filter is active, handle text input
    if ui.events_filter_active {
        match key.code {
            KeyCode::Esc => {
                // Cancel filter, clear it
                ui.events_filter_active = false;
                ui.events_filter.clear();
                // Re-enable auto-follow when clearing filter
                ui.events_auto_follow = true;
            }
            KeyCode::Enter => {
                // Confirm filter
                ui.events_filter_active = false;
            }
            KeyCode::Backspace => {
                ui.events_filter.pop();
                // Reset to auto-follow when filter changes
                ui.events_auto_follow = true;
            }
            KeyCode::Char(c) => {
                ui.events_filter.push(c);
                // Reset to auto-follow when filter changes
                ui.events_auto_follow = true;
            }
            _ => {}
        }
        return;
    }

    let total = get_filtered_event_count(state, ui).await;

    // Normal events view navigation
    match key.code {
        KeyCode::Esc | KeyCode::Char('e') | KeyCode::Char('E') | KeyCode::Char('q') => {
            // Close events view
            ui.events_view = false;
            ui.events_filter.clear();
            ui.events_list_state.select(None);
            ui.events_auto_follow = true; // Reset for next open
        }
        KeyCode::Char('/') => {
            // Start filtering
            ui.events_filter_active = true;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            // Moving up disables auto-follow
            ui.events_auto_follow = false;
            let selected = ui.events_list_state.selected().unwrap_or(0);
            if selected > 0 {
                ui.events_list_state.select(Some(selected - 1));
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let selected = ui.events_list_state.selected().unwrap_or(0);
            if total > 0 && selected < total - 1 {
                ui.events_list_state.select(Some(selected + 1));
                // If we reached the last item, re-enable auto-follow
                if selected + 1 == total - 1 {
                    ui.events_auto_follow = true;
                }
            }
        }
        KeyCode::PageUp => {
            // Moving up disables auto-follow
            ui.events_auto_follow = false;
            let selected = ui.events_list_state.selected().unwrap_or(0);
            ui.events_list_state
                .select(Some(selected.saturating_sub(10)));
        }
        KeyCode::PageDown => {
            let selected = ui.events_list_state.selected().unwrap_or(0);
            if total > 0 {
                let new_selected = (selected + 10).min(total - 1);
                ui.events_list_state.select(Some(new_selected));
                // If we reached the last item, re-enable auto-follow
                if new_selected == total - 1 {
                    ui.events_auto_follow = true;
                }
            }
        }
        KeyCode::Home | KeyCode::Char('g') => {
            // Moving to start disables auto-follow
            ui.events_auto_follow = false;
            if total > 0 {
                ui.events_list_state.select(Some(0));
            }
        }
        KeyCode::End | KeyCode::Char('G') => {
            // Moving to end enables auto-follow
            ui.events_auto_follow = true;
            if total > 0 {
                ui.events_list_state.select(Some(total - 1));
            }
        }
        _ => {}
    }
}

/// Get the count of events matching the current filter.
async fn get_filtered_event_count(state: &SharedState, ui: &UiState) -> usize {
    let s = state.read().await;
    if ui.events_filter.is_empty() {
        s.events.len()
    } else {
        let filter_lower = ui.events_filter.to_lowercase();
        s.events
            .iter()
            .filter(|e| format_event(e).to_lowercase().contains(&filter_lower))
            .count()
    }
}
