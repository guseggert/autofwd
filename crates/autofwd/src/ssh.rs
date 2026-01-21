use anyhow::{bail, Result};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

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

/// Start the SSH ControlMaster in the background.
pub async fn ssh_master_start(ctx: &SshContext) -> Result<()> {
    let mut cmd = Command::new("ssh");
    cmd.args(&ctx.ssh_args)
        .arg("-M") // ControlMaster mode
        .arg("-N") // No remote command
        .arg("-f") // Background after auth
        .arg("-o")
        .arg("ControlPersist=yes") // Keep master alive
        .arg("-o")
        .arg("ServerAliveInterval=5")
        .arg("-o")
        .arg("ServerAliveCountMax=3")
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg(&ctx.target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());

    let status = cmd
        .status()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start ssh master: {e}"))?;

    if !status.success() {
        bail!("ssh master exited with status {status}");
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
    Command::new("ssh")
        .args(&ctx.ssh_args)
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
pub async fn ssh_master_exit(ctx: &SshContext) {
    let _ = Command::new("ssh")
        .args(&ctx.ssh_args)
        .arg("-S")
        .arg(ctx.control_path.to_string_lossy().to_string())
        .arg("-O")
        .arg("exit")
        .arg(&ctx.target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    let _ = std::fs::remove_file(&ctx.control_path);
}
