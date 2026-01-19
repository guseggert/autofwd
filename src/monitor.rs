use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::events::Event;
use crate::ports::{find_free_local_port, PortFilter};
use crate::proc_net::{parse_proc_net_output, remote_host_for, HostPref};
use crate::ssh::{
    ssh_forward_add, ssh_forward_cancel, ssh_master_check, ssh_master_start, SshContext,
};
use crate::tui::{CommandReceiver, ForwardedPort, SharedState, TuiCommand};

const END_MARKER: &str = "__AUTOFWD_END__";
const UID_PREFIX: &str = "__AUTOFWD_UID__:";

/// Generate the remote monitoring script that reads /proc/net/tcp directly.
/// Only sends LISTEN state entries (state 0A) to minimize data transfer.
fn remote_monitor_script(interval: Duration) -> String {
    let sleep_secs = interval.as_secs_f64();

    format!(
        r#"
set -eu

# Check if /proc/net/tcp exists (Linux)
if [ ! -f /proc/net/tcp ]; then
    echo "autofwd: /proc/net/tcp not found - Linux required" >&2
    exit 2
fi

# Output our UID first so client can filter by user
echo "{UID_PREFIX}$(id -u)"

while :; do
    # Only send LISTEN state (0A) entries to minimize bandwidth
    # Format: sl local_address rem_address st ...
    # State is the 4th field, we want 0A (LISTEN)
    awk '$4 == "0A" {{ print }}' /proc/net/tcp 2>/dev/null || true
    awk '$4 == "0A" {{ print }}' /proc/net/tcp6 2>/dev/null || true
    echo "{END_MARKER}"
    sleep {sleep_secs:.3}
done
"#,
        END_MARKER = END_MARKER,
        UID_PREFIX = UID_PREFIX,
        sleep_secs = sleep_secs
    )
}

/// Info about an active forward (no process to manage - handled by ControlMaster).
struct ForwardInfo {
    local_port: u16,
    remote_host: String,
}

/// State tracked during monitoring.
struct MonitorState {
    /// Active forwards: remote_port -> ForwardInfo.
    forwards: HashMap<u16, ForwardInfo>,
    /// Last known host preferences for each port.
    host_prefs: HashMap<u16, HostPref>,
    /// Lines accumulated for the current snapshot.
    snapshot_lines: Vec<String>,
    /// Whether we've done the first scan.
    initialized: bool,
    /// The remote user's UID (for filtering).
    user_uid: Option<u32>,
    /// Ports seen in the previous snapshot (to detect restarts).
    last_seen: HashSet<u16>,
}

impl MonitorState {
    fn new() -> Self {
        Self {
            forwards: HashMap::new(),
            host_prefs: HashMap::new(),
            snapshot_lines: Vec::new(),
            initialized: false,
            user_uid: None,
            last_seen: HashSet::new(),
        }
    }
}

/// Process a completed snapshot of /proc/net/tcp output.
async fn process_snapshot(
    state: &mut MonitorState,
    ctx: &SshContext,
    filter: &PortFilter,
    collision_tries: u16,
    tui_state: &SharedState,
) {
    // Parse the accumulated output
    let output = state.snapshot_lines.join("\n");
    state.snapshot_lines.clear();

    // Filter by user UID to only see ports owned by our user
    let snapshot = parse_proc_net_output(&output, state.user_uid);

    // Update host preferences
    for (port, pref) in &snapshot {
        state.host_prefs.insert(*port, *pref);
    }

    let current_ports: HashSet<u16> = snapshot.keys().copied().collect();

    // Update status on first scan
    if !state.initialized {
        state.initialized = true;
        tui_state.write().await.status = "scanning...".to_string();
    }

    // Detect restarted services: ports we've forwarded that disappeared and came back
    // With -O forward, we don't need to re-establish - the forward persists.
    // But we should update the TUI to show reconnection.
    let forwarded_ports: Vec<u16> = state.forwards.keys().copied().collect();
    for remote_port in forwarded_ports {
        let was_gone = !state.last_seen.contains(&remote_port);
        let is_back = current_ports.contains(&remote_port);

        if was_gone && is_back {
            // Port restarted - forward should still be active via ControlMaster
            let mut tui = tui_state.write().await;
            if let Some(fwd) = tui
                .forwarded
                .iter_mut()
                .find(|f| f.remote_port == remote_port)
            {
                fwd.forwarded_at = Instant::now();
            }
            tui.push_event(format!("↻ service restarted :{}", remote_port));
            tui.emit(Event::service_restarted(remote_port));
        }
    }

    // Forward any new ports that pass the filter
    for &remote_port in &current_ports {
        // Skip if already forwarded
        if state.forwards.contains_key(&remote_port) {
            continue;
        }

        // Skip if user has disabled this port (it's in TUI state but not enabled)
        {
            let tui = tui_state.read().await;
            if tui
                .forwarded
                .iter()
                .any(|f| f.remote_port == remote_port && !f.enabled)
            {
                continue;
            }
        }

        // Skip if not allowed by filter
        if !filter.allows(remote_port) {
            continue;
        }

        // Determine remote host based on address family
        let pref = state
            .host_prefs
            .get(&remote_port)
            .copied()
            .unwrap_or_default();
        let remote_host = remote_host_for(&pref);

        // Find a free local port
        let Some(local_port) = find_free_local_port(remote_port, collision_tries) else {
            continue;
        };

        // Attempt to forward via ControlMaster
        match ssh_forward_add(ctx, local_port, remote_host, remote_port).await {
            Ok(()) => {
                state.forwards.insert(
                    remote_port,
                    ForwardInfo {
                        local_port,
                        remote_host: remote_host.to_string(),
                    },
                );

                // Update TUI state
                let mut tui = tui_state.write().await;
                tui.forwarded.push(ForwardedPort {
                    remote_port,
                    local_port,
                    remote_host: remote_host.to_string(),
                    forwarded_at: Instant::now(),
                    enabled: true,
                });
                tui.status = format!("watching ({} forwarded)", tui.forwarded.len());
                if local_port == remote_port {
                    tui.push_event(format!("+ forwarded :{}", remote_port));
                } else {
                    tui.push_event(format!("+ forwarded :{} → :{}", remote_port, local_port));
                }
                tui.emit(Event::forward_added(remote_port, local_port, remote_host));
            }
            Err(e) => {
                let mut tui = tui_state.write().await;
                tui.push_event(format!("✗ forward :{} failed: {}", remote_port, e));
                tui.emit(Event::error(format!(
                    "forward :{} failed: {}",
                    remote_port, e
                )));
            }
        }
    }

    // Detect ports that have disappeared and clean them up
    let gone_ports: Vec<u16> = state
        .forwards
        .keys()
        .filter(|p| !current_ports.contains(p))
        .copied()
        .collect();

    for remote_port in gone_ports {
        if let Some(info) = state.forwards.remove(&remote_port) {
            // Cancel the SSH forward
            let _ = ssh_forward_cancel(ctx, info.local_port, &info.remote_host, remote_port).await;

            // Remove from TUI
            let mut tui = tui_state.write().await;
            tui.forwarded.retain(|f| f.remote_port != remote_port);

            // Update status
            if tui.forwarded.is_empty() {
                tui.status = "watching...".to_string();
            } else {
                let active = tui.forwarded.iter().filter(|f| f.enabled).count();
                let total = tui.forwarded.len();
                tui.status = format!("watching ({}/{} active)", active, total);
            }

            tui.push_event(format!("- removed :{}", remote_port));
            tui.emit(Event::forward_removed(remote_port));
        }
    }

    // Remember what we saw for next time
    state.last_seen = current_ports;
}

/// Handle a toggle command from the TUI.
async fn handle_toggle(
    ctx: &SshContext,
    tui_state: &SharedState,
    state: &mut MonitorState,
    index: usize,
) {
    let (port, local_port, remote_host, is_enabled) = {
        let tui = tui_state.read().await;
        if index >= tui.forwarded.len() {
            return;
        }
        let fwd = &tui.forwarded[index];
        (
            fwd.remote_port,
            fwd.local_port,
            fwd.remote_host.clone(),
            fwd.enabled,
        )
    };

    if is_enabled {
        // Disable: cancel the forward via ControlMaster
        match ssh_forward_cancel(ctx, local_port, &remote_host, port).await {
            Ok(()) => {
                state.forwards.remove(&port);
                let mut tui = tui_state.write().await;
                if let Some(fwd) = tui.forwarded.iter_mut().find(|f| f.remote_port == port) {
                    fwd.enabled = false;
                }
                tui.push_event(format!("○ disabled :{}", port));
                tui.emit(Event::forward_disabled(port));

                let active = tui.forwarded.iter().filter(|f| f.enabled).count();
                let total = tui.forwarded.len();
                tui.status = format!("watching ({}/{} active)", active, total);
            }
            Err(e) => {
                let mut tui = tui_state.write().await;
                tui.push_event(format!("✗ failed to disable :{}: {}", port, e));
                tui.emit(Event::error(format!("failed to disable :{}: {}", port, e)));
            }
        }
    } else {
        // Enable: add the forward via ControlMaster
        match ssh_forward_add(ctx, local_port, &remote_host, port).await {
            Ok(()) => {
                state.forwards.insert(
                    port,
                    ForwardInfo {
                        local_port,
                        remote_host,
                    },
                );

                let mut tui = tui_state.write().await;
                if let Some(fwd) = tui.forwarded.iter_mut().find(|f| f.remote_port == port) {
                    fwd.enabled = true;
                }
                tui.push_event(format!("● enabled :{}", port));
                tui.emit(Event::forward_enabled(port, local_port));

                let active = tui.forwarded.iter().filter(|f| f.enabled).count();
                let total = tui.forwarded.len();
                tui.status = format!("watching ({}/{} active)", active, total);
            }
            Err(e) => {
                let mut tui = tui_state.write().await;
                tui.push_event(format!("✗ failed to enable :{}: {}", port, e));
                tui.emit(Event::error(format!("failed to enable :{}: {}", port, e)));
            }
        }
    }
}

/// Spawn the monitor SSH session and return the child process and line reader.
async fn spawn_monitor_session(
    ctx: &SshContext,
    interval: Duration,
) -> Result<(
    tokio::process::Child,
    tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
)> {
    let script = remote_monitor_script(interval);

    let mut child = Command::new("ssh")
        .args(&ctx.ssh_args)
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg("-T")
        .arg(&ctx.target)
        .arg("sh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("failed to spawn ssh monitor session: {e}"))?;

    // Write the script to stdin
    {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to capture monitor stdin"))?;
        stdin.write_all(script.as_bytes()).await?;
        stdin.shutdown().await?;
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture monitor stdout"))?;

    let lines = BufReader::new(stdout).lines();
    Ok((child, lines))
}

/// Re-establish all active forwards after a reconnection.
async fn reestablish_forwards(ctx: &SshContext, state: &mut MonitorState, tui_state: &SharedState) {
    let forwards_to_restore: Vec<_> = state.forwards.drain().collect();

    for (remote_port, info) in forwards_to_restore {
        match ssh_forward_add(ctx, info.local_port, &info.remote_host, remote_port).await {
            Ok(()) => {
                state.forwards.insert(
                    remote_port,
                    ForwardInfo {
                        local_port: info.local_port,
                        remote_host: info.remote_host,
                    },
                );
            }
            Err(e) => {
                let mut tui = tui_state.write().await;
                tui.push_event(format!("✗ restore :{} failed: {}", remote_port, e));
                tui.emit(Event::error(format!(
                    "restore :{} failed: {}",
                    remote_port, e
                )));
                // Mark as disabled in TUI
                if let Some(fwd) = tui
                    .forwarded
                    .iter_mut()
                    .find(|f| f.remote_port == remote_port)
                {
                    fwd.enabled = false;
                }
            }
        }
    }
}

/// Run the monitoring loop that detects new ports and forwards them.
pub async fn run_monitor(
    ctx: SshContext,
    filter: PortFilter,
    interval: Duration,
    collision_tries: u16,
    tui_state: SharedState,
    mut cmd_rx: CommandReceiver,
) -> Result<()> {
    let mut state = MonitorState::new();
    let mut reconnect_delay = Duration::from_secs(1);
    const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

    // Outer loop handles reconnection
    'reconnect: loop {
        if tui_state.read().await.should_quit {
            break;
        }

        // Spawn monitor session
        let (mut child, mut lines) = match spawn_monitor_session(&ctx, interval).await {
            Ok(result) => result,
            Err(e) => {
                // Check if ControlMaster is dead
                if !ssh_master_check(&ctx).await {
                    {
                        let mut tui = tui_state.write().await;
                        tui.status = "reconnecting...".to_string();
                        tui.push_event("! connection lost, reconnecting...".to_string());
                        tui.emit(Event::connection_lost());
                    }

                    // Try to restart the ControlMaster
                    if let Err(e) = ssh_master_start(&ctx).await {
                        let mut tui = tui_state.write().await;
                        tui.push_event(format!("✗ reconnect failed: {}", e));
                        tui.emit(Event::error(format!("reconnect failed: {}", e)));
                        tui.emit(Event::reconnecting(reconnect_delay.as_millis() as u64));

                        // Exponential backoff
                        tokio::time::sleep(reconnect_delay).await;
                        reconnect_delay = (reconnect_delay * 2).min(MAX_RECONNECT_DELAY);
                        continue 'reconnect;
                    }

                    // Re-establish forwards
                    reestablish_forwards(&ctx, &mut state, &tui_state).await;

                    {
                        let mut tui = tui_state.write().await;
                        tui.push_event("✓ reconnected".to_string());
                        tui.emit(Event::reconnected());
                    }
                    continue 'reconnect;
                }

                let mut tui = tui_state.write().await;
                tui.push_event(format!("✗ monitor error: {}", e));
                tui.emit(Event::error(format!("monitor error: {}", e)));
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = (reconnect_delay * 2).min(MAX_RECONNECT_DELAY);
                continue 'reconnect;
            }
        };

        // Reset monitor state for new session (keep forwards info)
        state.snapshot_lines.clear();
        state.user_uid = None;
        state.initialized = false;

        // Inner loop processes the monitor output
        loop {
            if tui_state.read().await.should_quit {
                let _ = child.kill().await;
                let _ = child.wait().await;
                break 'reconnect;
            }

            tokio::select! {
                result = lines.next_line() => {
                    match result {
                        Ok(Some(line)) => {
                            let trimmed = line.trim();
                            if trimmed == END_MARKER {
                                process_snapshot(&mut state, &ctx, &filter, collision_tries, &tui_state).await;
                                // Reset backoff only after successful data - proves stable connection
                                reconnect_delay = Duration::from_secs(1);
                            } else if let Some(uid_str) = trimmed.strip_prefix(UID_PREFIX) {
                                if let Ok(uid) = uid_str.parse::<u32>() {
                                    state.user_uid = Some(uid);
                                }
                            } else {
                                state.snapshot_lines.push(line);
                            }
                        }
                        Ok(None) => {
                            // EOF - connection likely died
                            let mut tui = tui_state.write().await;
                            tui.status = "connection lost...".to_string();
                            tui.push_event("! monitor session ended".to_string());
                            tui.emit(Event::connection_lost());
                            tui.emit(Event::reconnecting(reconnect_delay.as_millis() as u64));
                            drop(tui);
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            tokio::time::sleep(reconnect_delay).await;
                            reconnect_delay = (reconnect_delay * 2).min(MAX_RECONNECT_DELAY);
                            continue 'reconnect;
                        }
                        Err(e) => {
                            let mut tui = tui_state.write().await;
                            tui.push_event(format!("! read error: {}", e));
                            tui.emit(Event::error(format!("read error: {}", e)));
                            tui.emit(Event::reconnecting(reconnect_delay.as_millis() as u64));
                            drop(tui);
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            tokio::time::sleep(reconnect_delay).await;
                            reconnect_delay = (reconnect_delay * 2).min(MAX_RECONNECT_DELAY);
                            continue 'reconnect;
                        }
                    }
                }
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        TuiCommand::ToggleForward { index } => {
                            handle_toggle(&ctx, &tui_state, &mut state, index).await;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    }

    // Clean up: cancel all active forwards
    for (remote_port, info) in &state.forwards {
        let _ = ssh_forward_cancel(&ctx, info.local_port, &info.remote_host, *remote_port).await;
    }

    Ok(())
}
