use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::deploy::{ensure_agent_deployed, DeployResult};
use crate::events::Event;
use crate::ports::{find_free_local_port, PortFilter};
use crate::probe::{detect_protocol, Protocol};
use crate::proc_net::{parse_agent_output, parse_proc_net_output, remote_host_for, PortInfo};
use crate::ssh::{
    ssh_forward_add, ssh_forward_cancel, ssh_master_check, ssh_master_start, SshContext,
};
use crate::tui::{CommandReceiver, ForwardedPort, MonitorModeDisplay, SharedState, TuiCommand};

const END_MARKER: &str = "__AUTOFWD_END__";
const HEARTBEAT_MARKER: &str = "__AUTOFWD_HEARTBEAT__";

/// Monitoring mode: agent binary or fallback shell script.
#[derive(Debug, Clone)]
pub enum MonitorMode {
    /// Use the deployed agent binary.
    Agent { path: String },
    /// Fallback to shell script (no process names).
    Shell,
}

/// Generate the fallback shell script that uses /proc/net/tcp.
/// This is used when the agent can't be deployed.
/// Note: This doesn't include process names.
fn fallback_shell_script(interval: Duration) -> String {
    let sleep_secs = interval.as_secs_f64();
    let heartbeat_threshold = (5.0 / sleep_secs).ceil() as u32;

    format!(
        r#"
set -eu

# Check if /proc/net/tcp exists (Linux)
if [ ! -f /proc/net/tcp ]; then
    echo "autofwd: /proc/net/tcp not found - Linux required" >&2
    exit 2
fi

prev=""
heartbeat=0

while :; do
    # Get current listening ports for comparison
    curr=$(awk '$4 == "0A" {{ print $2 }}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | sort)
    
    if [ "$curr" != "$prev" ]; then
        # State changed - send raw /proc/net/tcp data for listening sockets
        awk '$4 == "0A"' /proc/net/tcp /proc/net/tcp6 2>/dev/null
        echo "{END_MARKER}"
        prev="$curr"
        heartbeat=0
    else
        heartbeat=$((heartbeat + 1))
        if [ $heartbeat -ge {heartbeat_threshold} ]; then
            echo "{HEARTBEAT_MARKER}"
            heartbeat=0
        fi
    fi
    
    sleep {sleep_secs:.3}
done
"#,
        END_MARKER = END_MARKER,
        HEARTBEAT_MARKER = HEARTBEAT_MARKER,
        heartbeat_threshold = heartbeat_threshold,
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
    /// Last known port info (host preferences and process name) for each port.
    port_info: HashMap<u16, PortInfo>,
    /// Lines accumulated for the current snapshot.
    snapshot_lines: Vec<String>,
    /// Whether we've done the first scan.
    initialized: bool,
    /// Ports seen in the previous snapshot (to detect restarts).
    last_seen: HashSet<u16>,
    /// Current monitoring mode.
    mode: MonitorMode,
}

impl MonitorState {
    fn new(mode: MonitorMode) -> Self {
        Self {
            forwards: HashMap::new(),
            port_info: HashMap::new(),
            snapshot_lines: Vec::new(),
            initialized: false,
            last_seen: HashSet::new(),
            mode,
        }
    }
}

/// Process a completed snapshot of port data.
async fn process_snapshot(
    state: &mut MonitorState,
    ctx: &SshContext,
    filter: &PortFilter,
    collision_tries: u16,
    assume_http: bool,
    tui_state: &SharedState,
) {
    // Parse the accumulated output
    let output = state.snapshot_lines.join("\n");
    state.snapshot_lines.clear();

    // Parse based on monitoring mode
    let snapshot = match &state.mode {
        MonitorMode::Agent { .. } => parse_agent_output(&output),
        MonitorMode::Shell => parse_proc_net_output(&output),
    };

    // Update port info (host preferences and process names)
    for (port, info) in &snapshot {
        state.port_info.insert(*port, info.clone());
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
            let local_port = {
                let mut tui = tui_state.write().await;
                let local_port = if let Some(fwd) = tui
                    .forwarded
                    .iter_mut()
                    .find(|f| f.remote_port == remote_port)
                {
                    fwd.forwarded_at = Instant::now();
                    fwd.protocol = Protocol::Unknown; // Reset for re-probing
                    Some(fwd.local_port)
                } else {
                    None
                };
                tui.push_event(format!("↻ service restarted :{}", remote_port));
                tui.emit(Event::service_restarted(remote_port));
                local_port
            };

            // Re-probe protocol on restart if not assume_http
            if !assume_http {
                if let Some(local_port) = local_port {
                    let tui_state_clone = tui_state.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let detected = detect_protocol(local_port).await;
                        let mut tui = tui_state_clone.write().await;
                        if let Some(fwd) = tui
                            .forwarded
                            .iter_mut()
                            .find(|f| f.local_port == local_port && f.enabled)
                        {
                            fwd.protocol = detected;
                        }
                        tui.emit(Event::protocol_detected(local_port, detected.as_str()));
                    });
                }
            }
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

        // Get port info (host preferences and process name)
        let info = state
            .port_info
            .get(&remote_port)
            .cloned()
            .unwrap_or_default();
        let remote_host = remote_host_for(&info.host_pref);
        let process_name = info.process_name.clone();

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

                // Determine initial protocol
                let protocol = if assume_http {
                    Protocol::Http
                } else {
                    Protocol::Unknown
                };

                // Update TUI state
                let mut tui = tui_state.write().await;
                tui.forwarded.push(ForwardedPort {
                    remote_port,
                    local_port,
                    remote_host: remote_host.to_string(),
                    forwarded_at: Instant::now(),
                    enabled: true,
                    protocol,
                    process_name: process_name.clone(),
                });
                tui.status = format!("watching ({} forwarded)", tui.forwarded.len());
                if local_port == remote_port {
                    tui.push_event(format!("+ forwarded :{}", remote_port));
                } else {
                    tui.push_event(format!("+ forwarded :{} → :{}", remote_port, local_port));
                }
                tui.emit(Event::forward_added(
                    remote_port,
                    local_port,
                    remote_host,
                    protocol.as_str(),
                    process_name,
                ));
                drop(tui);

                // Spawn protocol detection task if not assume_http
                if !assume_http {
                    let tui_state_clone = tui_state.clone();
                    tokio::spawn(async move {
                        // Delay to let the forward establish and service respond
                        tokio::time::sleep(Duration::from_millis(500)).await;

                        // Try detection multiple times with increasing delays
                        let mut detected = Protocol::Unknown;
                        for attempt in 0..3 {
                            if attempt > 0 {
                                tokio::time::sleep(Duration::from_millis(500)).await;
                            }
                            detected = detect_protocol(local_port).await;
                            if detected != Protocol::Unknown {
                                break;
                            }
                        }

                        // Update the ForwardedPort with detected protocol
                        let mut tui = tui_state_clone.write().await;
                        if let Some(fwd) = tui
                            .forwarded
                            .iter_mut()
                            .find(|f| f.local_port == local_port && f.enabled)
                        {
                            fwd.protocol = detected;
                        }
                        // Emit updated event with detected protocol
                        tui.emit(Event::protocol_detected(local_port, detected.as_str()));
                    });
                }
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
    mode: &MonitorMode,
) -> Result<(
    tokio::process::Child,
    tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
)> {
    let (command, use_stdin) = match mode {
        MonitorMode::Agent { path } => {
            // Run the agent binary directly
            let cmd = format!("{} --interval {}", path, interval.as_millis());
            (cmd, false)
        }
        MonitorMode::Shell => {
            // Use shell script via stdin
            ("sh".to_string(), true)
        }
    };

    let mut child = Command::new("ssh")
        .args(&ctx.ssh_args)
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg("-T")
        .arg(&ctx.target)
        .arg(&command)
        .stdin(if use_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("failed to spawn ssh monitor session: {e}"))?;

    // Write the fallback script to stdin if using shell mode
    if use_stdin {
        use tokio::io::AsyncWriteExt;
        let script = fallback_shell_script(interval);
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
#[allow(clippy::too_many_arguments)]
pub async fn run_monitor(
    ctx: SshContext,
    filter: PortFilter,
    interval: Duration,
    collision_tries: u16,
    assume_http: bool,
    tui_state: SharedState,
    redraw_notify: crate::tui::RedrawNotify,
    mut cmd_rx: CommandReceiver,
) -> Result<()> {
    // Try to deploy agent, fall back to shell script if unavailable
    let mode = {
        let start = Instant::now();

        // Check for forced shell mode (for testing)
        if std::env::var("AUTOFWD_FORCE_SHELL").is_ok() {
            let mut tui = tui_state.write().await;
            tui.status = "connecting (shell mode)...".to_string();
            tui.monitor_mode = MonitorModeDisplay::Shell;
            tui.push_event("! shell mode forced via AUTOFWD_FORCE_SHELL".to_string());
            tui.emit(Event::agent_fallback("forced via AUTOFWD_FORCE_SHELL"));
            MonitorMode::Shell
        } else {
        tui_state.write().await.status = "deploying agent...".to_string();
        redraw_notify.notify_one(); // Show "deploying agent..." immediately

        // Emit timing for agent deployment
        let deploy_start = Instant::now();
        let result = ensure_agent_deployed(&ctx).await;
        let deploy_duration = deploy_start.elapsed().as_millis() as u64;
        tui_state.read().await.emit(Event::timing("ensure_agent_deployed", deploy_duration));

        match result {
            Ok(DeployResult::Ready { path }) => {
                let mut tui = tui_state.write().await;
                tui.status = "connecting...".to_string();
                tui.monitor_mode = MonitorModeDisplay::Agent;
                MonitorMode::Agent { path }
            }
            Ok(DeployResult::Deployed { path, arch }) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let mut tui = tui_state.write().await;
                tui.status = "connecting...".to_string();
                tui.monitor_mode = MonitorModeDisplay::Agent;
                tui.push_event(format!("✓ agent deployed ({})", arch));
                tui.emit(Event::agent_deployed(&arch, duration_ms));
                MonitorMode::Agent { path }
            }
            Ok(DeployResult::Unsupported { arch }) => {
                let mut tui = tui_state.write().await;
                tui.status = "connecting (shell fallback)...".to_string();
                tui.monitor_mode = MonitorModeDisplay::Shell;
                tui.push_event(format!("! unsupported arch {}, using shell fallback", arch));
                tui.emit(Event::agent_fallback(&format!("unsupported arch: {}", arch)));
                MonitorMode::Shell
            }
            Ok(DeployResult::NotAvailable) => {
                let mut tui = tui_state.write().await;
                tui.status = "connecting (shell fallback)...".to_string();
                tui.monitor_mode = MonitorModeDisplay::Shell;
                tui.push_event("! agent not available, using shell fallback".to_string());
                tui.emit(Event::agent_fallback("agent binaries not embedded"));
                MonitorMode::Shell
            }
            Err(e) => {
                let mut tui = tui_state.write().await;
                tui.status = "connecting (shell fallback)...".to_string();
                tui.monitor_mode = MonitorModeDisplay::Shell;
                tui.push_event(format!("! agent deploy failed: {:#}, using shell fallback", e));
                tui.emit(Event::agent_fallback(&format!("deploy failed: {:#}", e)));
                MonitorMode::Shell
            }
        }
        }
    };
    redraw_notify.notify_one(); // Show deployment result

    // Emit ready event now that agent deployment is complete
    tui_state.read().await.emit(Event::ready(&ctx.target));

    let mut state = MonitorState::new(mode.clone());
    let mut reconnect_delay = Duration::from_secs(1);
    const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

    // Outer loop handles reconnection
    'reconnect: loop {
        if tui_state.read().await.should_quit {
            break;
        }

        // Spawn monitor session
        let spawn_start = Instant::now();
        let (mut child, mut lines) = match spawn_monitor_session(&ctx, interval, &state.mode).await
        {
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

        // Emit timing for monitor session spawn
        let spawn_duration = spawn_start.elapsed().as_millis() as u64;
        tui_state.read().await.emit(Event::timing("spawn_monitor_session", spawn_duration));

        // Reset monitor state for new session (keep forwards info)
        state.snapshot_lines.clear();
        state.initialized = false;

        // Track time to first data
        let first_data_start = Instant::now();
        let mut first_data_received = false;

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
                                // Emit timing for first data
                                if !first_data_received {
                                    first_data_received = true;
                                    let first_data_duration = first_data_start.elapsed().as_millis() as u64;
                                    tui_state.read().await.emit(Event::timing("first_data", first_data_duration));
                                }
                                process_snapshot(&mut state, &ctx, &filter, collision_tries, assume_http, &tui_state).await;
                                redraw_notify.notify_one(); // Trigger TUI redraw
                                // Reset backoff only after successful data - proves stable connection
                                reconnect_delay = Duration::from_secs(1);
                            } else if trimmed == HEARTBEAT_MARKER {
                                // Connection is alive, reset backoff
                                reconnect_delay = Duration::from_secs(1);
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
                            redraw_notify.notify_one(); // Refresh toggle state
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
