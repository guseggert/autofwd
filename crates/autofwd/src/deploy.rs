//! Agent deployment to remote servers.
//!
//! Handles deploying the embedded agent binary to remote servers via SSH.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::embedded::{agent_for_arch, EmbeddedAgent};
use crate::ssh::SshContext;

/// Remote path where agents are deployed.
const AGENT_DIR: &str = "/tmp";

/// Result of agent deployment.
#[derive(Debug)]
pub enum DeployResult {
    /// Agent is ready (already installed with correct version).
    Ready { path: String },
    /// Agent was just deployed.
    Deployed { path: String, arch: String },
    /// Architecture not supported, should fall back to shell script.
    Unsupported { arch: String },
    /// Agent binaries not available (development build with stubs).
    NotAvailable,
}

/// Run an SSH command and return stdout.
/// Uses the existing ControlMaster connection (no redundant checks).
async fn ssh_run(ctx: &SshContext, command: &str) -> Result<String> {
    let output = Command::new("ssh")
        .args(&ctx.ssh_args)
        .arg("-S")
        .arg(&ctx.control_path)
        .arg(&ctx.target)
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to run SSH command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "SSH command failed (status {}): stderr='{}' stdout='{}'",
            output.status,
            stderr.trim(),
            stdout.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Deploy agent binary to remote via SSH stdin.
async fn deploy_agent(ctx: &SshContext, agent: &EmbeddedAgent, remote_path: &str) -> Result<()> {
    let binary = agent.decompress()?;

    let mut child = Command::new("ssh")
        .arg("-S")
        .arg(&ctx.control_path)
        .arg(&ctx.target)
        .arg(format!("cat > {} && chmod +x {}", remote_path, remote_path))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn SSH for deployment")?;

    // Write binary to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&binary).await?;
        stdin.shutdown().await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to deploy agent: {}", stderr);
    }

    Ok(())
}

/// Ensure the agent is deployed to the remote server.
///
/// Returns the result indicating whether deployment succeeded, the agent was
/// already present, or we should fall back to the shell script.
pub async fn ensure_agent_deployed(ctx: &SshContext) -> Result<DeployResult> {
    // Build a single command that gets arch AND checks all possible agent paths
    // This reduces 2 SSH round trips to 1
    use crate::embedded::{AGENT_AARCH64, AGENT_ARMV7, AGENT_X86_64};

    // Note: Each test command ends with "|| true" to ensure the overall command succeeds
    // even when the agent doesn't exist yet
    let check_cmd = format!(
        "uname -m; (test -x {dir}/autofwd-agent-{h1} && echo {h1}) || true; (test -x {dir}/autofwd-agent-{h2} && echo {h2}) || true; (test -x {dir}/autofwd-agent-{h3} && echo {h3}) || true",
        dir = AGENT_DIR,
        h1 = AGENT_X86_64.hash,
        h2 = AGENT_AARCH64.hash,
        h3 = AGENT_ARMV7.hash,
    );

    let output = ssh_run(ctx, &check_cmd)
        .await
        .context("Failed to detect remote architecture")?;

    let mut lines = output.lines();

    // First line is the architecture
    let arch = lines.next().unwrap_or("").trim();
    if arch.is_empty() {
        anyhow::bail!("Failed to detect remote architecture");
    }

    // Get embedded agent for this architecture
    let agent = match agent_for_arch(arch) {
        Some(a) => a,
        None => {
            return Ok(DeployResult::Unsupported {
                arch: arch.to_string(),
            })
        }
    };

    // Check if agent is available (not a stub)
    if !agent.is_available() {
        return Ok(DeployResult::NotAvailable);
    }

    // Check if the agent's hash was found in the output (meaning it exists on remote)
    let remote_filename = agent.remote_filename();
    let remote_path = format!("{}/{}", AGENT_DIR, remote_filename);
    let agent_exists = lines.any(|line| line.trim() == agent.hash);

    if agent_exists {
        return Ok(DeployResult::Ready { path: remote_path });
    }

    // Deploy the agent
    deploy_agent(ctx, agent, &remote_path).await?;

    Ok(DeployResult::Deployed {
        path: remote_path,
        arch: arch.to_string(),
    })
}

/// Get the agent path for the given architecture (without deploying).
#[allow(dead_code)]
pub fn agent_path_for_arch(arch: &str) -> Option<String> {
    agent_for_arch(arch).map(|a| format!("{}/{}", AGENT_DIR, a.remote_filename()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_path_for_arch() {
        // Should return Some for supported architectures
        assert!(agent_path_for_arch("x86_64").is_some());
        assert!(agent_path_for_arch("aarch64").is_some());
        assert!(agent_path_for_arch("armv7l").is_some());

        // Should return None for unsupported
        assert!(agent_path_for_arch("riscv64").is_none());
    }
}
