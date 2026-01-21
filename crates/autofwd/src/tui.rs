use anyhow::Result;
use crossterm::{
    event::{Event as CrosstermEvent, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use futures::StreamExt;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState},
};
use std::io::{stdout, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

use crate::events::Event as JsonEvent;
use crate::probe::Protocol;

const MAX_EVENTS: usize = 5;

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
    pub quit_requested: bool, // Set by Ctrl+C to trigger confirmation
    pub selected: usize,
    pub events: Vec<String>,
    /// Current monitoring mode (agent or shell fallback).
    pub monitor_mode: MonitorModeDisplay,
    /// Optional channel for JSON events (headless mode)
    #[allow(dead_code)]
    event_tx: Option<EventSender>,
}

impl TuiState {
    /// Add an event to the log (keeps last MAX_EVENTS).
    pub fn push_event(&mut self, event: String) {
        use chrono::Local;

        let timestamp = Local::now().format("%H:%M:%S").to_string();
        self.events.push(format!("{} {}", timestamp, event));
        if self.events.len() > MAX_EVENTS {
            self.events.remove(0);
        }
    }

    /// Emit a structured event (for headless mode JSON output).
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
    show_events: bool,
    show_quit_confirm: bool,
    table_state: TableState,
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
        quit_requested: false,
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

            // Calculate events height (only show if toggled on and there are events)
            let events_height = if ui.show_events && !state.events.is_empty() {
                (state.events.len() as u16 + 2).min(MAX_EVENTS as u16 + 2)
            } else {
                0
            };

            // Layout: header, main content, events (optional), footer
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),             // Header
                    Constraint::Min(5),                // Table
                    Constraint::Length(events_height), // Events (0 if hidden)
                    Constraint::Length(3),             // Footer
                ])
                .split(area);

            // Header with monitor mode indicator
            let mode_indicator = match state.monitor_mode {
                MonitorModeDisplay::Agent => {
                    Span::styled(" [agent] ", Style::default().fg(Color::Green))
                }
                MonitorModeDisplay::Shell => {
                    Span::styled(" [shell] ", Style::default().fg(Color::Yellow))
                }
                MonitorModeDisplay::Unknown => Span::raw(""),
            };
            let header_line = Line::from(vec![
                Span::raw(format!(" {} - {}", target, state.status)),
                mode_indicator,
            ]);
            let header = Paragraph::new(header_line)
                .block(Block::default().borders(Borders::ALL).title(" autofwd "));
            frame.render_widget(header, chunks[0]);

            // Forwarded ports table
            let header_row = Row::new(vec![
                Cell::from(" "),
                Cell::from("Remote"),
                Cell::from("Local"),
                Cell::from("Process"),
                Cell::from("Address"),
                Cell::from("Age"),
            ])
            .style(Style::default().fg(Color::Yellow).bold());

            let rows: Vec<Row> = state
                .forwarded
                .iter()
                .map(|fwd| {
                    let age = fwd.forwarded_at.elapsed();
                    let age_str = format_duration(age);
                    let status_icon = if fwd.enabled { "●" } else { "○" };
                    let process = fwd.process_name.as_deref().unwrap_or("-");
                    let style = if fwd.enabled {
                        Style::default()
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    Row::new(vec![
                        Cell::from(status_icon),
                        Cell::from(format!(":{}", fwd.remote_port)),
                        Cell::from(format!(":{}", fwd.local_port)),
                        Cell::from(process),
                        Cell::from(if fwd.enabled {
                            fwd.protocol.format_address(fwd.local_port)
                        } else {
                            "(disabled)".to_string()
                        }),
                        Cell::from(age_str),
                    ])
                    .style(style)
                })
                .collect();

            let table = Table::new(
                rows,
                [
                    Constraint::Length(3),
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Length(15),
                    Constraint::Min(25),
                    Constraint::Length(10),
                ],
            )
            .header(header_row)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Forwarded Ports "),
            )
            .row_highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
            .highlight_symbol("→ ");
            frame.render_stateful_widget(table, chunks[1], &mut ui.table_state);

            // Events log (only if toggled on and there are events)
            if ui.show_events && !state.events.is_empty() {
                let items: Vec<ListItem> = state
                    .events
                    .iter()
                    .map(|e| {
                        ListItem::new(format!(" {}", e)).style(Style::default().fg(Color::Cyan))
                    })
                    .collect();
                let events_list = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title(" Events "));
                frame.render_widget(events_list, chunks[2]);
            }

            // Footer
            let events_indicator = if ui.show_events {
                "e:events ✓"
            } else {
                "e:events"
            };
            let footer = Paragraph::new(format!(
                " ↑/↓ navigate • space toggle • {} • ?:help • q quit",
                events_indicator
            ))
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(footer, chunks[3]);

            // Render overlays on top
            if ui.show_help {
                render_help_overlay(frame, area);
            }

            if ui.show_quit_confirm {
                render_quit_confirm(frame, area);
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
        "  e        Toggle events log",
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
        show_events: false, // Events hidden by default
        show_quit_confirm: false,
        table_state: TableState::default(),
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
        // Check for quit/quit_requested from monitor
        {
            let s = state.read().await;
            if s.should_quit {
                break;
            }
            if s.quit_requested {
                drop(s);
                state.write().await.quit_requested = false;
                ui.show_quit_confirm = true;
            }
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

    // Normal key handling
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
                ui.show_events = !ui.show_events;
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
