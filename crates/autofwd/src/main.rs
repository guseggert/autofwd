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

    /// Extra args to pass to ssh (put them after `--`), e.g. -i key -p 2222 -J jump
    #[arg(last = true, value_name = "SSH_ARGS")]
    pub ssh_args: Vec<String>,
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
    ssh_master_start(&ctx).await?;
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

    // Create shared state, redraw notifier, and command channel
    let (tui_state, redraw_notify) = new_shared_state(event_tx);
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
