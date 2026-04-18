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
use std::collections::VecDeque;
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
    /// When the local port was last verified to be listening (TCP connect ok).
    pub last_verified_at: Option<Instant>,
    /// Whether the last verification attempt succeeded.
    pub last_verified_ok: bool,
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
#[derive(Debug)]
pub struct TuiState {
    pub status: String,
    pub forwarded: Vec<ForwardedPort>,
    pub should_quit: bool,
    pub selected: usize,
    pub events: VecDeque<JsonEvent>,
    /// Current monitoring mode (agent or shell fallback).
    pub monitor_mode: MonitorModeDisplay,
    /// Optional channel for JSON events (headless mode)
    #[allow(dead_code)]
    event_tx: Option<EventSender>,
    /// Optional channel for log-file output (always on unless disabled).
    log_tx: Option<EventSender>,
    pub snapshots_processed: u64,
    pub ssh_ops: u64,
    pub active_probes: u32,
    /// Number of reconnect cycles since startup.
    pub reconnect_count: u32,
    /// Most recent time we saw data from the remote (heartbeat / snapshot).
    pub last_agent_activity: Option<Instant>,
    /// Most recent time the SSH ControlMaster was (re)started.
    pub last_master_start: Option<Instant>,
    /// Path to the persistent event log file, if enabled.
    pub log_file_path: Option<String>,
}

impl TuiState {
    /// Add an event to the log (keeps last MAX_EVENTS) and emit it.
    pub fn push_event(&mut self, event: JsonEvent) {
        // Also emit for headless mode JSON output
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event.clone());
        }
        if let Some(tx) = &self.log_tx {
            let _ = tx.send(event.clone());
        }
        self.events.push_back(event);
        if self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    /// Emit a structured event (for headless mode JSON output only, not stored).
    pub fn emit(&self, event: JsonEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event.clone());
        }
        if let Some(tx) = &self.log_tx {
            let _ = tx.send(event);
        }
    }
}

/// Local UI state (not shared with monitor).
struct UiState {
    show_help: bool,
    show_process: bool,
    show_quit_confirm: bool,
    show_debug: bool,
    show_status: bool,
    table_state: TableState,
    events_view: bool,
    events_list_state: ListState,
    events_filter: String,
    events_filter_active: bool,
    events_auto_follow: bool,
    render_stats: RenderStats,
}

struct RenderStats {
    start_time: Instant,
    frame_count: u64,
    last_frame_time: Duration,
    fps_window_start: Instant,
    fps_window_frames: u64,
    current_fps: f64,
    key_events: u64,
    tick_events: u64,
    state_change_events: u64,
    resize_events: u64,
    coalesced_events: u64,
}

impl RenderStats {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            frame_count: 0,
            last_frame_time: Duration::ZERO,
            fps_window_start: now,
            fps_window_frames: 0,
            current_fps: 0.0,
            key_events: 0,
            tick_events: 0,
            state_change_events: 0,
            resize_events: 0,
            coalesced_events: 0,
        }
    }

    fn record_event(&mut self, event: &TuiEvent) {
        match event {
            TuiEvent::Key(_) => self.key_events += 1,
            TuiEvent::Tick => self.tick_events += 1,
            TuiEvent::StateChanged => self.state_change_events += 1,
            TuiEvent::Resize => self.resize_events += 1,
        }
    }

    fn record_frame(&mut self, frame_time: Duration) {
        self.frame_count += 1;
        self.last_frame_time = frame_time;
        self.fps_window_frames += 1;
        let elapsed = self.fps_window_start.elapsed();
        if elapsed >= Duration::from_secs(1) {
            self.current_fps = self.fps_window_frames as f64 / elapsed.as_secs_f64();
            self.fps_window_frames = 0;
            self.fps_window_start = Instant::now();
        }
    }

    fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
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

pub fn new_shared_state(
    event_tx: Option<EventSender>,
    log_tx: Option<EventSender>,
    log_file_path: Option<String>,
) -> (SharedState, RedrawNotify) {
    let state = Arc::new(RwLock::new(TuiState {
        status: "connecting...".to_string(),
        forwarded: Vec::new(),
        should_quit: false,
        selected: 0,
        events: VecDeque::new(),
        monitor_mode: MonitorModeDisplay::Unknown,
        event_tx,
        log_tx,
        snapshots_processed: 0,
        ssh_ops: 0,
        active_probes: 0,
        reconnect_count: 0,
        last_agent_activity: None,
        last_master_start: None,
        log_file_path,
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
                render_events_view(frame, area, state, ui);
            } else {
                render_main_view(frame, area, state, ui, target);

                if ui.show_help {
                    render_help_overlay(frame, area);
                }

                if ui.show_quit_confirm {
                    render_quit_confirm(frame, area);
                }
            }

            if ui.show_debug {
                render_debug_overlay(frame, area, state, &ui.render_stats);
            }

            if ui.show_status {
                render_status_overlay(frame, area, state);
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
    let footer =
        Paragraph::new(" ↑/↓ navigate • space toggle • s status • d debug • ? help • q quit")
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
        "  s        Toggle status / diagnostics",
        "  d        Toggle debug stats",
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

fn render_debug_overlay(frame: &mut Frame, area: Rect, state: &TuiState, stats: &RenderStats) {
    let uptime = stats.uptime();
    let uptime_str = format_duration(uptime);
    let fwd_active = state.forwarded.iter().filter(|f| f.enabled).count();
    let fwd_total = state.forwarded.len();

    let mode_str = match state.monitor_mode {
        MonitorModeDisplay::Agent => "agent",
        MonitorModeDisplay::Shell => "shell",
        MonitorModeDisplay::Unknown => "?",
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Render  ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(format!(
                "fps {:.1}  frame {:.1}ms",
                stats.current_fps,
                stats.last_frame_time.as_secs_f64() * 1000.0
            )),
        ]),
        Line::from(vec![
            Span::raw("          "),
            Span::raw(format!(
                "total {}  coalesced {}",
                stats.frame_count, stats.coalesced_events
            )),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Events  ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(format!(
                "key {}  tick {}  state {}",
                stats.key_events, stats.tick_events, stats.state_change_events
            )),
        ]),
        Line::from(vec![
            Span::raw("          "),
            Span::raw(format!(
                "resize {}  buf {}/{}",
                stats.resize_events,
                state.events.len(),
                MAX_EVENTS
            )),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Monitor ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(format!(
                "{}  fwds {}/{}  snaps {}",
                mode_str, fwd_active, fwd_total, state.snapshots_processed
            )),
        ]),
        Line::from(vec![
            Span::raw("          "),
            Span::raw(format!(
                "probes {}  ssh_ops {}",
                state.active_probes, state.ssh_ops
            )),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Uptime  ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(uptime_str),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("                        "),
            Span::styled("[d] close", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let popup_width = 44;
    let popup_height = lines.len() as u16 + 2;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);
    let debug = Paragraph::new(lines)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta))
                .title(" Debug Stats "),
        );
    frame.render_widget(debug, popup_area);
}

/// Render the session-health status overlay ('s' key).
///
/// Designed for diagnosing "tunnels not restored after sleep" — shows idle
/// time since last remote activity, reconnect history, master age, log file
/// location, and per-forward verification status.
fn render_status_overlay(frame: &mut Frame, area: Rect, state: &TuiState) {
    fn idle_str(t: Option<Instant>) -> String {
        match t {
            Some(i) => format!("{}s ago", i.elapsed().as_secs()),
            None => "—".to_string(),
        }
    }

    let mode_str = match state.monitor_mode {
        MonitorModeDisplay::Agent => "agent",
        MonitorModeDisplay::Shell => "shell",
        MonitorModeDisplay::Unknown => "unknown",
    };

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("  Status     ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(state.status.clone()),
        ]),
        Line::from(vec![
            Span::styled("  Mode       ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(mode_str.to_string()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Last data  ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(idle_str(state.last_agent_activity)),
        ]),
        Line::from(vec![
            Span::styled("  Master age ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(idle_str(state.last_master_start)),
        ]),
        Line::from(vec![
            Span::styled("  Reconnects ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(state.reconnect_count.to_string()),
        ]),
        Line::from(vec![
            Span::styled("  Snapshots  ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(state.snapshots_processed.to_string()),
        ]),
        Line::from(vec![
            Span::styled("  SSH ops    ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(state.ssh_ops.to_string()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Log file   ", Style::default().fg(Color::Yellow).bold()),
            Span::raw(
                state
                    .log_file_path
                    .clone()
                    .unwrap_or_else(|| "(disabled)".to_string()),
            ),
        ]),
    ];

    // Per-forward verification summary (enabled forwards only).
    let enabled: Vec<&ForwardedPort> = state.forwarded.iter().filter(|f| f.enabled).collect();
    let disabled_count = state.forwarded.len() - enabled.len();

    if !enabled.is_empty() || disabled_count > 0 {
        lines.push(Line::from(""));
        let header = if disabled_count > 0 {
            format!(
                "  Forwards  ({} active, {} disabled hidden)",
                enabled.len(),
                disabled_count
            )
        } else {
            format!("  Forwards  ({})", enabled.len())
        };
        lines.push(Line::from(Span::styled(
            header,
            Style::default().fg(Color::Yellow).bold(),
        )));
    }

    // Reserve space for header/footer/borders so we know how many forward
    // rows will actually fit. If more exist than fit, truncate with a count.
    // Rough budget: current lines + 1 (footer spacer) + 1 (footer) + 2 (borders).
    let fixed_below = 3;
    let fixed_above = lines.len() as u16 + 2; // +2 for borders top/bottom
    let available_for_rows = area.height.saturating_sub(fixed_above + fixed_below);

    let capacity = available_for_rows as usize;
    let to_show = enabled.len().min(capacity);
    for fwd in &enabled[..to_show] {
        let verify = match (fwd.last_verified_at, fwd.last_verified_ok) {
            (Some(t), true) => format!("verified {}s ago", t.elapsed().as_secs()),
            (Some(t), false) => format!("BROKEN (checked {}s ago)", t.elapsed().as_secs()),
            (None, _) => "pending verification".to_string(),
        };
        let line = format!(
            "    :{:<6} → :{:<6} {}",
            fwd.remote_port, fwd.local_port, verify
        );
        let style = if fwd.last_verified_at.is_some() && !fwd.last_verified_ok {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(line, style)));
    }
    let hidden_by_size = enabled.len().saturating_sub(to_show);
    if hidden_by_size > 0 {
        lines.push(Line::from(format!(
            "    … and {} more (terminal too small)",
            hidden_by_size
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("                        "),
        Span::styled("[s] close", Style::default().fg(Color::DarkGray)),
    ]));

    // Grow popup to fit content, capped by the available area.
    let popup_width = 66.min(area.width.saturating_sub(2));
    let popup_height = (lines.len() as u16 + 2).min(area.height);
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);
    let status = Paragraph::new(lines)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Status "),
        );
    frame.render_widget(status, popup_area);
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
        Event::AgentDiagnostics {
            ts,
            backend,
            phase,
            sleep_ms,
            min_ms,
            max_ms,
        } => format!(
            "{} [agent] {} {} sleep={}ms (min={}ms max={}ms)",
            ts.to_rfc3339(),
            backend,
            phase,
            sleep_ms,
            min_ms,
            max_ms
        ),
        Event::StaleDetected { ts, idle_ms } => {
            format!("{} ⚠ stale detected (idle {}ms)", ts.to_rfc3339(), idle_ms)
        }
        Event::MasterTerminated {
            ts,
            summary,
            killed_pid,
        } => match killed_pid {
            Some(pid) => format!(
                "{} ✗ killed old master pid {} ({})",
                ts.to_rfc3339(),
                pid,
                summary
            ),
            None => format!("{} terminated old master: {}", ts.to_rfc3339(), summary),
        },
        Event::MasterStarted { ts, duration_ms } => {
            format!("{} ✓ master started ({}ms)", ts.to_rfc3339(), duration_ms)
        }
        Event::RestoreAttempt {
            ts,
            remote_port,
            local_port,
            attempt,
            max_attempts,
        } => format!(
            "{} → restore :{} → :{} (attempt {}/{})",
            ts.to_rfc3339(),
            remote_port,
            local_port,
            attempt,
            max_attempts
        ),
        Event::ForwardRestored {
            ts,
            remote_port,
            local_port,
            attempts,
        } => format!(
            "{} ✓ restored :{} → :{} ({} attempts)",
            ts.to_rfc3339(),
            remote_port,
            local_port,
            attempts
        ),
        Event::RestoreFailed {
            ts,
            remote_port,
            local_port,
            attempts,
            reason,
        } => format!(
            "{} ✗ restore :{} → :{} failed after {} attempts: {}",
            ts.to_rfc3339(),
            remote_port,
            local_port,
            attempts,
            reason
        ),
        Event::ForwardVerified {
            ts,
            remote_port,
            local_port,
            alive,
        } => {
            if *alive {
                format!(
                    "{} ✓ verified :{} → :{}",
                    ts.to_rfc3339(),
                    remote_port,
                    local_port
                )
            } else {
                format!(
                    "{} ✗ verify failed :{} → :{}",
                    ts.to_rfc3339(),
                    remote_port,
                    local_port
                )
            }
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
        show_process: false,
        show_quit_confirm: false,
        show_debug: false,
        show_status: false,
        table_state: TableState::default(),
        events_view: false,
        events_list_state: ListState::default(),
        events_filter: String::new(),
        events_filter_active: false,
        events_auto_follow: true,
        render_stats: RenderStats::new(),
    };

    // Unified event channel - all events flow through here
    let mut events = spawn_event_handler(redraw_notify);

    // Initial draw
    {
        let s = state.read().await;
        tui.draw(&s, &mut ui, &target)?;
    }

    // Main event loop with event coalescing.
    // Drains all pending events before drawing once per batch,
    // preventing redundant redraws when multiple events arrive between frames.
    while let Some(event) = events.recv().await {
        if state.read().await.should_quit {
            break;
        }

        ui.render_stats.record_event(&event);
        if let TuiEvent::Key(key) = event {
            handle_key_event(key, &state, &mut ui, &cmd_tx).await;
        }

        while let Ok(ev) = events.try_recv() {
            ui.render_stats.record_event(&ev);
            ui.render_stats.coalesced_events += 1;
            if let TuiEvent::Key(key) = ev {
                handle_key_event(key, &state, &mut ui, &cmd_tx).await;
            }
        }

        let s = state.read().await;
        if s.should_quit {
            break;
        }
        let draw_start = Instant::now();
        tui.draw(&s, &mut ui, &target)?;
        ui.render_stats.record_frame(draw_start.elapsed());
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
            KeyCode::Char('d') | KeyCode::Char('D') => {
                ui.show_debug = !ui.show_debug;
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                ui.show_status = !ui.show_status;
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
            ui.events_auto_follow = true;
            if total > 0 {
                ui.events_list_state.select(Some(total - 1));
            }
        }
        KeyCode::Char('d') | KeyCode::Char('D') => {
            ui.show_debug = !ui.show_debug;
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
