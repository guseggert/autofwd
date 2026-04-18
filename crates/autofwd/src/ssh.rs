use anyhow::{bail, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

const CONNECT_TIMEOUT_SECS: u32 = 5;
/// How long to wait for `ssh -O exit` to gracefully terminate an existing master.
const GRACEFUL_EXIT_TIMEOUT: Duration = Duration::from_secs(2);

/// Context for SSH operations, shared across the application.
#[derive(Clone, Debug)]
pub struct SshContext {
    pub target: String,
    pub ssh_args: Vec<String>,
    pub control_path: PathBuf,
}

/// Generate a unique control socket path for the given target.
pub fn control_path_for(target: &str) -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);

    let hash = blake3::hash(target.as_bytes()).to_hex();
    let pid = std::process::id();
    runtime.join(format!("autofwd-{}-{}.sock", &hash[..16], pid))
}

/// Query the PID of the running ControlMaster, if any.
///
/// Uses `ssh -O check` which on success prints `Master running (pid=NNN)` to
/// stderr. Returns `None` if the master isn't running or we couldn't parse
/// the PID.
async fn ssh_master_pid(ctx: &SshContext) -> Option<u32> {
    if !ctx.control_path.exists() {
        return None;
    }

    let output = Command::new("ssh")
        .args(&ctx.ssh_args)
        .arg("-o")
        .arg(format!("ConnectTimeout={}", CONNECT_TIMEOUT_SECS))
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg("-O")
        .arg("check")
        .arg(&ctx.target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Parse `Master running (pid=12345)`
    let start = stderr.find("pid=")?;
    let rest = &stderr[start + 4..];
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse::<u32>().ok()
}

/// Try to terminate an existing ControlMaster that may still be holding
/// local port bindings. Returns `true` if we successfully cleaned up, or
/// `false` if nothing was running.
///
/// Strategy:
///   1. If the control socket doesn't exist, nothing to do.
///   2. Try `ssh -O exit` with a short timeout (graceful shutdown).
///   3. If graceful exit fails or times out, look up the master PID via
///      `ssh -O check` and send SIGKILL.
///   4. Finally, remove the stale socket file.
///
/// This is essential during reconnection after sleep/wake: the old master
/// process may still be alive and holding the local ports that the new
/// master needs to rebind for forward restoration.
pub async fn ssh_master_terminate_existing(ctx: &SshContext) -> TerminationResult {
    let socket_existed = ctx.control_path.exists();
    if !socket_existed {
        return TerminationResult {
            socket_existed: false,
            graceful: false,
            killed_pid: None,
        };
    }

    // Record PID before graceful exit so we can fall back to SIGKILL.
    let pid_before = ssh_master_pid(ctx).await;

    // Try graceful `ssh -O exit`.
    let graceful = tokio::time::timeout(
        GRACEFUL_EXIT_TIMEOUT,
        Command::new("ssh")
            .args(&ctx.ssh_args)
            .arg("-o")
            .arg(format!("ConnectTimeout={}", CONNECT_TIMEOUT_SECS))
            .arg("-S")
            .arg(ctx.control_path.to_string_lossy().to_string())
            .arg("-O")
            .arg("exit")
            .arg(&ctx.target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await;

    let graceful_ok = matches!(graceful, Ok(Ok(status)) if status.success());

    // Re-check if the master is still alive. If so, SIGKILL by PID.
    let mut killed_pid = None;
    if let Some(pid) = ssh_master_pid(ctx).await.or(pid_before) {
        // Small grace period for graceful exit to actually tear down.
        if graceful_ok {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if process_is_alive(pid) {
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            // Give kernel a moment to release socket/ports.
            tokio::time::sleep(Duration::from_millis(100)).await;
            killed_pid = Some(pid);
        }
    }

    // Remove the socket file (may already be gone).
    let _ = std::fs::remove_file(&ctx.control_path);

    TerminationResult {
        socket_existed: true,
        graceful: graceful_ok,
        killed_pid,
    }
}

/// Result of terminating an existing ControlMaster.
#[derive(Debug, Clone)]
pub struct TerminationResult {
    pub socket_existed: bool,
    pub graceful: bool,
    pub killed_pid: Option<u32>,
}

impl TerminationResult {
    /// Human-readable summary suitable for logging.
    pub fn summary(&self) -> String {
        if !self.socket_existed {
            "no prior master".to_string()
        } else if let Some(pid) = self.killed_pid {
            format!("SIGKILL pid {}", pid)
        } else if self.graceful {
            "graceful exit".to_string()
        } else {
            "socket removed".to_string()
        }
    }
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    // kill(pid, 0) returns 0 if the process exists and we can signal it.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    false
}

/// Start the SSH ControlMaster in the background.
///
/// Before spawning, any pre-existing master (identified by the control
/// socket file) is gracefully shut down and, if still alive, SIGKILL'd.
/// This prevents the new master from failing to bind local forward ports
/// that the old master is still holding — the most common failure mode
/// after laptop sleep/wake.
pub async fn ssh_master_start(ctx: &SshContext, inherit_stderr: bool) -> Result<()> {
    // Terminate any leftover master from a prior session (e.g. after sleep/wake).
    let _ = ssh_master_terminate_existing(ctx).await;

    let mut cmd = Command::new("ssh");
    cmd.args(&ctx.ssh_args)
        .arg("-M") // ControlMaster mode
        .arg("-N") // No remote command
        .arg("-f") // Background after auth
        .arg("-o")
        .arg("ControlPersist=yes") // Keep master alive
        .arg("-o")
        .arg(format!("ConnectTimeout={}", CONNECT_TIMEOUT_SECS))
        .arg("-o")
        .arg("ServerAliveInterval=5")
        .arg("-o")
        .arg("ServerAliveCountMax=3")
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg(&ctx.target)
        .stdin(Stdio::null())
        .stdout(Stdio::null());

    if inherit_stderr {
        // At startup (before TUI), let the user see SSH auth prompts and errors directly.
        cmd.stderr(Stdio::inherit());
        let status = cmd
            .status()
            .await
            .map_err(|e| anyhow::anyhow!("failed to start ssh master: {e}"))?;

        if !status.success() {
            bail!("ssh master exited with status {status}");
        }
    } else {
        // During reconnection (while TUI is active), capture stderr to avoid polluting
        // the terminal's scrollback buffer. With `-f`, SSH forks into the background after
        // auth — the forked process inherits the pipe fd whose read end is closed, so its
        // writes are silently discarded (SIGPIPE/EPIPE). This prevents the long-running
        // master process from continuously writing to the terminal and causing iTerm lag.
        cmd.stderr(Stdio::piped());
        let output = cmd
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("failed to start ssh master: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = stderr.trim();
            if msg.is_empty() {
                bail!("ssh master exited with status {}", output.status);
            } else {
                bail!("ssh master failed: {msg}");
            }
        }
    }
    Ok(())
}

/// Add a port forward via the ControlMaster.
/// Uses `-O forward` to dynamically add a forward to the existing master connection.
pub async fn ssh_forward_add(
    ctx: &SshContext,
    local_port: u16,
    remote_host: &str,
    remote_port: u16,
) -> Result<()> {
    let spec = format!("127.0.0.1:{local_port}:{remote_host}:{remote_port}");

    let output = Command::new("ssh")
        .args(&ctx.ssh_args)
        .arg("-o")
        .arg(format!("ConnectTimeout={}", CONNECT_TIMEOUT_SECS))
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg("-O")
        .arg("forward")
        .arg("-L")
        .arg(&spec)
        .arg(&ctx.target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run ssh forward command: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("ssh forward failed: {}", stderr.trim());
    }

    Ok(())
}

/// Cancel a port forward via the ControlMaster.
/// Uses `-O cancel` to remove a forward from the existing master connection.
pub async fn ssh_forward_cancel(
    ctx: &SshContext,
    local_port: u16,
    remote_host: &str,
    remote_port: u16,
) -> Result<()> {
    let spec = format!("127.0.0.1:{local_port}:{remote_host}:{remote_port}");

    let output = Command::new("ssh")
        .args(&ctx.ssh_args)
        .arg("-o")
        .arg(format!("ConnectTimeout={}", CONNECT_TIMEOUT_SECS))
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg("-O")
        .arg("cancel")
        .arg("-L")
        .arg(&spec)
        .arg(&ctx.target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run ssh cancel command: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("ssh cancel failed: {}", stderr.trim());
    }

    Ok(())
}

/// Check if the ControlMaster is still alive.
pub async fn ssh_master_check(ctx: &SshContext) -> bool {
    if !ctx.control_path.exists() {
        return false;
    }

    Command::new("ssh")
        .args(&ctx.ssh_args)
        .arg("-o")
        .arg(format!("ConnectTimeout={}", CONNECT_TIMEOUT_SECS))
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg("-O")
        .arg("check")
        .arg(&ctx.target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Gracefully exit the ControlMaster and clean up the socket.
/// Falls back to SIGKILL if graceful exit hangs.
pub async fn ssh_master_exit(ctx: &SshContext) {
    let _ = ssh_master_terminate_existing(ctx).await;
}
