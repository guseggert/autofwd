use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

const IMAGE_NAME: &str = "autofwd-test-ssh";
const CONTAINER_PREFIX: &str = "autofwd-test-";

/// A Docker container running an SSH server for testing.
pub struct TestContainer {
    container_id: String,
    ssh_port: u16,
    /// Kept alive to prevent TempDir from being dropped (deleting keys)
    _key_dir: TempDir,
    key_path: PathBuf,
}

impl TestContainer {
    /// Start a new test container with an ephemeral SSH key.
    pub fn start() -> Result<Self> {
        // Create temp directory for SSH keys
        let key_dir = TempDir::new().context("failed to create temp dir for keys")?;
        let key_path = key_dir.path().join("id_ed25519");
        let pub_key_path = key_dir.path().join("id_ed25519.pub");

        // Generate ephemeral SSH key
        let status = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                key_path.to_str().unwrap(),
                "-N",
                "",   // No passphrase
                "-q", // Quiet
            ])
            .status()
            .context("failed to run ssh-keygen")?;

        if !status.success() {
            bail!("ssh-keygen failed");
        }

        // Read public key
        let pub_key =
            std::fs::read_to_string(&pub_key_path).context("failed to read public key")?;

        // Create authorized_keys file in temp dir
        let auth_keys_path = key_dir.path().join("authorized_keys");
        std::fs::write(&auth_keys_path, &pub_key).context("failed to write authorized_keys")?;

        // Generate unique container name
        let container_name = format!("{}{}", CONTAINER_PREFIX, std::process::id());

        // Start container with mounted authorized_keys
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &container_name,
                "-P", // Publish all exposed ports to random host ports
                "-v",
                &format!(
                    "{}:/home/testuser/.ssh/authorized_keys:ro",
                    auth_keys_path.display()
                ),
                IMAGE_NAME,
            ])
            .output()
            .context("failed to run docker")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("docker run failed: {}", stderr);
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Get the mapped SSH port
        let output = Command::new("docker")
            .args(["port", &container_id, "22"])
            .output()
            .context("failed to get container port")?;

        if !output.status.success() {
            // Clean up container on failure
            let _ = Command::new("docker")
                .args(["rm", "-f", &container_id])
                .status();
            bail!("failed to get container port");
        }

        let port_output = String::from_utf8_lossy(&output.stdout);
        // Output format: "0.0.0.0:32768" or "[::]:32768"
        let ssh_port: u16 = port_output
            .trim()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| anyhow!("failed to parse port from: {}", port_output))?;

        let container = TestContainer {
            container_id,
            ssh_port,
            _key_dir: key_dir,
            key_path,
        };

        // Wait for SSH to be ready
        container.wait_for_ssh()?;

        Ok(container)
    }

    /// Wait for SSH server to be ready.
    fn wait_for_ssh(&self) -> Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);

        while std::time::Instant::now() < deadline {
            let status = Command::new("ssh")
                .args(self.ssh_args())
                .args(["-o", "ConnectTimeout=1"])
                .arg(self.ssh_target())
                .arg("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if let Ok(s) = status {
                if s.success() {
                    return Ok(());
                }
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        bail!("SSH server did not become ready within 30 seconds")
    }

    /// Get the SSH target string (user@host).
    pub fn ssh_target(&self) -> String {
        format!("testuser@127.0.0.1")
    }

    /// Get SSH command arguments for connecting to this container.
    pub fn ssh_args(&self) -> Vec<String> {
        vec![
            "-p".to_string(),
            self.ssh_port.to_string(),
            "-i".to_string(),
            self.key_path.to_string_lossy().to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-o".to_string(),
            "LogLevel=ERROR".to_string(),
        ]
    }

    /// Get the mapped SSH port on the host.
    #[allow(dead_code)]
    pub fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    /// Get the path to the SSH private key.
    #[allow(dead_code)]
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Execute a command inside the container and return the output.
    pub fn exec(&self, cmd: &str) -> Result<String> {
        let output = Command::new("ssh")
            .args(self.ssh_args())
            .arg(self.ssh_target())
            .arg(cmd)
            .output()
            .context("failed to execute command via SSH")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("command failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Start a TCP listener on the given port inside the container.
    /// Returns immediately (listener runs in background).
    pub fn start_listener(&self, port: u16) -> Result<()> {
        // Start listener using docker exec -d to avoid SSH backgrounding issues
        // This runs as testuser (UID 1000) so autofwd will detect it
        let output = Command::new("docker")
            .args([
                "exec",
                "-u",
                "testuser",
                "-d",
                &self.container_id,
                "sh",
                "-c",
                &format!("while true; do echo ready | nc -l {}; done", port),
            ])
            .output()
            .context("failed to start listener via docker exec")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("failed to start listener on port {}: {}", port, stderr);
        }

        // Give it a moment to start
        std::thread::sleep(Duration::from_millis(500));

        Ok(())
    }

    /// Stop a TCP listener on the given port inside the container.
    pub fn stop_listener(&self, port: u16) -> Result<()> {
        // Kill any process listening on the port (pattern matches start_listener)
        let _ = Command::new("docker")
            .args([
                "exec",
                &self.container_id,
                "pkill",
                "-f",
                &format!("nc -l {}", port),
            ])
            .output();

        // Give it a moment to die
        std::thread::sleep(Duration::from_millis(200));
        Ok(())
    }

    /// Stop the container.
    pub fn stop(&self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Drop for TestContainer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Build the test Docker image if it doesn't exist.
pub fn ensure_image_built() -> Result<()> {
    // Check if image exists
    let output = Command::new("docker")
        .args(["images", "-q", IMAGE_NAME])
        .output()
        .context("failed to check for docker image")?;

    if !output.stdout.is_empty() {
        return Ok(()); // Image exists
    }

    // Build the image
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dockerfile_path = Path::new(manifest_dir).join("tests/docker");

    let status = Command::new("docker")
        .args(["build", "-t", IMAGE_NAME, dockerfile_path.to_str().unwrap()])
        .status()
        .context("failed to build docker image")?;

    if !status.success() {
        bail!("docker build failed");
    }

    Ok(())
}
