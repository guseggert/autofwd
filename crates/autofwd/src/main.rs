mod deploy;
mod embedded;
mod events;
mod monitor;
mod ports;
mod probe;
mod proc_net;
mod ssh;
mod tui;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::events::Event;
use crate::monitor::run_monitor;
use crate::ports::PortFilter;
use crate::ssh::{control_path_for, ssh_master_exit, ssh_master_start, SshContext};
use crate::tui::{new_command_channel, new_shared_state, run_tui};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "autofwd",
    about = "Cursor-style auto port forwarding for SSH sessions (baseline-diff + ssh ControlMaster)"
)]
pub struct Args {
    /// SSH target, e.g. user@host or host
    #[arg(value_name = "TARGET")]
    pub target: String,

    /// Poll interval for checking remote ports (lower = faster detection, slightly more CPU on remote)
    #[arg(long, default_value = "200ms", value_parser = humantime::parse_duration)]
    pub interval: Duration,

    /// Only forward ports in this allowlist: e.g. "3000,5173,8000-9000".
    /// By default, infrastructure ports are excluded (SSH, DNS, databases, Redis, etc.).
    /// Using --allow overrides the denylist entirely.
    #[arg(long)]
    pub allow: Option<String>,

    /// If the desired local port is taken, try the next N ports
    #[arg(long, default_value_t = 50)]
    pub collision_tries: u16,

    /// Run without TUI, output events as JSON lines (for testing/scripting)
    #[arg(long)]
    pub headless: bool,

    /// Assume all forwarded ports are HTTP (skip protocol detection)
    #[arg(long)]
    pub assume_http: bool,

    /// Write all events as JSON lines to this file. Defaults to
    /// ~/Library/Logs/autofwd/<target>.log on macOS or
    /// $XDG_STATE_HOME/autofwd/<target>.log on Linux. Pass /dev/null to disable.
    #[arg(long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Disable persistent event log file.
    #[arg(long, conflicts_with = "log_file")]
    pub no_log_file: bool,

    /// Extra args to pass to ssh (put them after `--`), e.g. -i key -p 2222 -J jump
    #[arg(last = true, value_name = "SSH_ARGS")]
    pub ssh_args: Vec<String>,
}

/// Compute the default log file path for the given SSH target.
///
/// macOS: `~/Library/Logs/autofwd/<safe-target>.log`
/// Linux: `$XDG_STATE_HOME/autofwd/<safe-target>.log` (or `~/.local/state/autofwd/`)
fn default_log_path(target: &str) -> Option<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Logs/autofwd"))
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state"))
            })
            .map(|p| p.join("autofwd"))
    };

    let base = base?;
    // Sanitize target: replace characters that aren't filesystem-safe.
    let safe: String = target
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect();
    Some(base.join(format!("{}.log", safe)))
}

/// Spawn a task that writes incoming events as JSON lines to the given file.
/// Returns a sender the rest of the app should clone.
///
/// Errors on open are printed to stderr (best effort) and logging is disabled.
fn spawn_log_writer(path: PathBuf) -> Option<tokio::sync::mpsc::UnboundedSender<Event>> {
    use tokio::io::AsyncWriteExt;

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "autofwd: could not create log directory {}: {}",
                parent.display(),
                e
            );
            return None;
        }
    }

    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("autofwd: could not open log file {}: {}", path.display(), e);
            return None;
        }
    };

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let mut writer = tokio::fs::File::from_std(file);

    tokio::spawn(async move {
        // Write a session marker so we can find where this run started.
        let _ = writer
            .write_all(
                format!(
                    "{{\"event\":\"session_start\",\"ts\":\"{}\",\"pid\":{}}}\n",
                    chrono::Utc::now().to_rfc3339(),
                    std::process::id()
                )
                .as_bytes(),
            )
            .await;
        let _ = writer.flush().await;

        while let Some(event) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&event) {
                if writer.write_all(json.as_bytes()).await.is_err() {
                    break;
                }
                if writer.write_all(b"\n").await.is_err() {
                    break;
                }
                // Flush each event so crashes don't lose recent lines.
                let _ = writer.flush().await;
            }
        }
    });

    Some(tx)
}

/// Guard that ensures SSH cleanup runs even on panic/early return.
struct CleanupGuard {
    ctx: SshContext,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        // Use a blocking runtime to run the async cleanup
        // This is safe because we're in Drop and need to ensure cleanup
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(ssh_master_exit(&ctx));
        })
        .join()
        .ok();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    use std::time::Instant;

    let args = Args::parse();
    let control_path: PathBuf = control_path_for(&args.target);

    let filter = PortFilter::new(args.allow.as_deref())?;

    let ctx = SshContext {
        target: args.target.clone(),
        ssh_args: args.ssh_args.clone(),
        control_path: control_path.clone(),
    };

    // Start SSH control master
    let ssh_start = Instant::now();
    ssh_master_start(&ctx, true).await?;
    let ssh_duration = ssh_start.elapsed();

    // Emit timing in headless mode
    if args.headless {
        Event::timing("ssh_master_start", ssh_duration.as_millis() as u64).emit();
    }

    // Set up cleanup guard - ensures cleanup even on panic
    let _cleanup = CleanupGuard { ctx: ctx.clone() };

    // Create event channel for headless mode
    let event_tx = if args.headless {
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        // Spawn task to print events as JSON
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                event.emit();
            }
        });
        Some(tx)
    } else {
        None
    };

    // Set up persistent log file (default: ~/Library/Logs/autofwd/<target>.log on macOS)
    let log_path = if args.no_log_file {
        None
    } else {
        args.log_file
            .clone()
            .or_else(|| default_log_path(&args.target))
    };
    let log_tx = log_path.as_ref().and_then(|p| spawn_log_writer(p.clone()));
    let log_file_path_for_tui = log_path
        .as_ref()
        .filter(|_| log_tx.is_some())
        .map(|p| p.display().to_string());
    if let Some(p) = &log_path {
        if log_tx.is_some() && !args.headless {
            eprintln!("autofwd: logging to {}", p.display());
        }
    }

    // Create shared state, redraw notifier, and command channel
    let (tui_state, redraw_notify) = new_shared_state(event_tx, log_tx, log_file_path_for_tui);
    let (cmd_tx, cmd_rx) = new_command_channel();

    // Spawn monitor task
    let monitor_handle = {
        let monitor_ctx = ctx.clone();
        let monitor_filter = filter.clone();
        let monitor_state = tui_state.clone();
        let monitor_notify = redraw_notify.clone();
        let interval = args.interval;
        let collision_tries = args.collision_tries;
        let assume_http = args.assume_http;
        tokio::spawn(async move {
            let _ = run_monitor(
                monitor_ctx,
                monitor_filter,
                interval,
                collision_tries,
                assume_http,
                monitor_state,
                monitor_notify,
                cmd_rx,
            )
            .await;
        })
    };

    if args.headless {
        // Headless mode: wait for signals
        // Note: ready event is emitted by run_monitor after agent deployment

        // Wait for Ctrl+C or SIGTERM
        let signal_state = tui_state.clone();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                #[cfg(unix)]
                {
                    let mut term = tokio::signal::unix::signal(
                        tokio::signal::unix::SignalKind::terminate()
                    ).unwrap();
                    term.recv().await
                }
                #[cfg(not(unix))]
                std::future::pending::<()>().await
            } => {}
        }

        // Emit shutdown event
        signal_state.read().await.emit(Event::shutdown());
        signal_state.write().await.should_quit = true;
    } else {
        // TUI mode: spawn signal handler and run TUI
        let signal_state = tui_state.clone();
        let signal_notify = redraw_notify.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    signal_state.write().await.should_quit = true;
                    signal_notify.notify_one(); // Wake up TUI to check should_quit
                }
                _ = async {
                    #[cfg(unix)]
                    {
                        let mut term = tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::terminate()
                        ).unwrap();
                        term.recv().await
                    }
                    #[cfg(not(unix))]
                    std::future::pending::<()>().await
                } => {
                    signal_state.write().await.should_quit = true;
                    signal_notify.notify_one(); // Wake up TUI to check should_quit
                }
            }
        });

        // Run TUI (blocks until quit confirmed)
        run_tui(
            tui_state.clone(),
            args.target.clone(),
            cmd_tx,
            redraw_notify,
        )
        .await?;

        // Signal monitor to stop
        tui_state.write().await.should_quit = true;
    }

    // Wait for monitor to finish
    let _ = tokio::time::timeout(Duration::from_secs(2), monitor_handle).await;

    // Note: CleanupGuard will call ssh_master_exit when dropped
    Ok(())
}
