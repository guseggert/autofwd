use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

const SSH_IMAGE_NAME: &str = "autofwd-test-ssh";
const CONTAINER_PREFIX: &str = "autofwd-test";

/// Generate a unique ID for test isolation.
fn unique_id() -> String {
    format!("{}-{}", std::process::id(), rand::random::<u32>())
}

/// Container types for protocol detection testing.
#[derive(Clone, Copy, Debug)]
pub enum ContainerType {
    /// Our custom SSH test image
    Ssh,
    /// redis:alpine
    Redis,
    /// postgres:alpine
    PostgreSql,
    /// mariadb:lts
    MariaDb,
    /// nginx:alpine for HTTP testing
    Http,
}

impl ContainerType {
    pub fn image(&self) -> &str {
        match self {
            Self::Ssh => SSH_IMAGE_NAME,
            Self::Redis => "redis:alpine",
            Self::PostgreSql => "postgres:alpine",
            Self::MariaDb => "mariadb:lts",
            Self::Http => "nginx:alpine",
        }
    }

    pub fn internal_port(&self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Redis => 6379,
            Self::PostgreSql => 5432,
            Self::MariaDb => 3306,
            Self::Http => 80,
        }
    }

    pub fn env_vars(&self) -> Vec<(&str, &str)> {
        match self {
            Self::PostgreSql => vec![("POSTGRES_HOST_AUTH_METHOD", "trust")],
            Self::MariaDb => vec![("MARIADB_ALLOW_EMPTY_ROOT_PASSWORD", "1")],
            _ => vec![],
        }
    }

    pub fn expected_protocol(&self) -> &str {
        match self {
            Self::Ssh => "ssh",
            Self::Redis => "redis",
            Self::PostgreSql => "postgresql",
            Self::MariaDb => "mysql", // MariaDB uses MySQL protocol
            Self::Http => "http",
        }
    }

    /// How long to wait for this service to be ready
    pub fn startup_timeout(&self) -> Duration {
        match self {
            Self::MariaDb => Duration::from_secs(60), // MariaDB can be slow
            Self::PostgreSql => Duration::from_secs(30),
            _ => Duration::from_secs(10),
        }
    }
}

/// A Docker network for test isolation.
pub struct TestNetwork {
    name: String,
}

impl TestNetwork {
    /// Create a new isolated Docker network.
    pub fn new() -> Result<Self> {
        let name = format!("{}-net-{}", CONTAINER_PREFIX, unique_id());

        let output = Command::new("docker")
            .args(["network", "create", &name])
            .output()
            .context("failed to create docker network")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("docker network create failed: {}", stderr);
        }

        Ok(Self { name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["network", "rm", &self.name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// A generic service container for testing.
pub struct ServiceContainer {
    container_id: String,
    container_name: String,
    container_type: ContainerType,
    #[allow(dead_code)]
    network: String,
}

impl ServiceContainer {
    /// Start a service container on the given network.
    pub fn start(container_type: ContainerType, network: &TestNetwork) -> Result<Self> {
        let container_name = format!(
            "{}-{}-{}",
            CONTAINER_PREFIX,
            match container_type {
                ContainerType::Ssh => "ssh",
                ContainerType::Redis => "redis",
                ContainerType::PostgreSql => "postgres",
                ContainerType::MariaDb => "mariadb",
                ContainerType::Http => "http",
            },
            unique_id()
        );

        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--rm".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "--network".to_string(),
            network.name().to_string(),
        ];

        // Add environment variables
        for (key, value) in container_type.env_vars() {
            args.push("-e".to_string());
            args.push(format!("{}={}", key, value));
        }

        args.push(container_type.image().to_string());

        let output = Command::new("docker")
            .args(&args)
            .output()
            .context("failed to run docker")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "docker run failed for {}: {}",
                container_type.image(),
                stderr
            );
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        let container = Self {
            container_id,
            container_name,
            container_type,
            network: network.name().to_string(),
        };

        // Wait for service to be ready
        container.wait_for_ready()?;

        Ok(container)
    }

    /// Get the container name (for use as hostname in Docker network).
    pub fn hostname(&self) -> &str {
        &self.container_name
    }

    /// Get the internal port of the service.
    pub fn port(&self) -> u16 {
        self.container_type.internal_port()
    }

    /// Get the expected protocol string.
    pub fn expected_protocol(&self) -> &str {
        self.container_type.expected_protocol()
    }

    /// Wait for the service to be ready.
    fn wait_for_ready(&self) -> Result<()> {
        let deadline = std::time::Instant::now() + self.container_type.startup_timeout();

        while std::time::Instant::now() < deadline {
            // Try to connect to the service port
            let check_cmd = format!(
                "nc -z {} {} 2>/dev/null && echo ok",
                self.container_name,
                self.container_type.internal_port()
            );

            let output = Command::new("docker")
                .args([
                    "run",
                    "--rm",
                    "--network",
                    &self.network,
                    "alpine",
                    "sh",
                    "-c",
                    &check_cmd,
                ])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if stdout.contains("ok") {
                        // Additional delay for services that need time after port is open
                        match self.container_type {
                            ContainerType::MariaDb | ContainerType::PostgreSql => {
                                std::thread::sleep(Duration::from_secs(2));
                            }
                            _ => {}
                        }
                        return Ok(());
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(500));
        }

        bail!(
            "{} service did not become ready within {:?}",
            self.container_type.image(),
            self.container_type.startup_timeout()
        )
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

impl Drop for ServiceContainer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A Docker container running an SSH server for testing.
/// This is the main container that autofwd connects to.
pub struct TestContainer {
    container_id: String,
    container_name: String,
    ssh_port: u16,
    network: Option<String>,
    /// Kept alive to prevent TempDir from being dropped (deleting keys)
    _key_dir: TempDir,
    key_path: PathBuf,
}

impl TestContainer {
    /// Start a new test container with an ephemeral SSH key.
    pub fn start() -> Result<Self> {
        Self::start_internal(None)
    }

    /// Start a new test container on the given network.
    pub fn start_on_network(network: &TestNetwork) -> Result<Self> {
        Self::start_internal(Some(network))
    }

    fn start_internal(network: Option<&TestNetwork>) -> Result<Self> {
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
        let container_name = format!("{}-ssh-{}", CONTAINER_PREFIX, unique_id());

        // Build docker run args
        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--rm".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "-P".to_string(), // Publish all exposed ports to random host ports
        ];

        // Add network if specified
        if let Some(net) = network {
            args.push("--network".to_string());
            args.push(net.name().to_string());
        }

        args.push("-v".to_string());
        args.push(format!(
            "{}:/home/testuser/.ssh/authorized_keys:ro",
            auth_keys_path.display()
        ));
        args.push(SSH_IMAGE_NAME.to_string());

        // Start container
        let output = Command::new("docker")
            .args(&args)
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
            container_name,
            ssh_port,
            network: network.map(|n| n.name().to_string()),
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

    /// Get the container name (for use as hostname in Docker network).
    #[allow(dead_code)]
    pub fn hostname(&self) -> &str {
        &self.container_name
    }

    /// Get the SSH target string (user@host).
    pub fn ssh_target(&self) -> String {
        "testuser@127.0.0.1".to_string()
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

    /// Start a port forwarder inside the container that forwards traffic to another host:port.
    /// This is used to forward traffic to service containers on the same network.
    pub fn start_forwarder(
        &self,
        local_port: u16,
        target_host: &str,
        target_port: u16,
    ) -> Result<()> {
        // Use socat to listen on IPv4 (127.0.0.1) specifically.
        // autofwd prefers IPv4 for local connections.
        let forward_cmd = format!(
            "socat TCP4-LISTEN:{},bind=127.0.0.1,fork,reuseaddr TCP:{}:{}",
            local_port, target_host, target_port
        );

        // First, verify the target is reachable
        let check_dns = Command::new("docker")
            .args([
                "exec",
                &self.container_id,
                "sh",
                "-c",
                &format!("getent hosts {}", target_host),
            ])
            .output();

        if let Ok(out) = &check_dns {
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                bail!(
                    "Target host {} not resolvable from container: {}",
                    target_host,
                    stderr
                );
            }
        }

        // Use -d to run in detached mode
        let output = Command::new("docker")
            .args([
                "exec",
                "-d",
                "-u",
                "testuser",
                &self.container_id,
                "sh",
                "-c",
                &forward_cmd,
            ])
            .output()
            .context("failed to start forwarder via docker exec")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "failed to start forwarder on port {}: {}",
                local_port,
                stderr.trim()
            );
        }

        // Wait for the listener to be ready (check /proc/net/tcp for IPv4)
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let port_hex = format!("{:04X}", local_port);

        while std::time::Instant::now() < deadline {
            // Check if port is listening via /proc/net/tcp (IPv4)
            let check_output = Command::new("docker")
                .args([
                    "exec",
                    &self.container_id,
                    "sh",
                    "-c",
                    &format!("cat /proc/net/tcp 2>/dev/null | grep -i ':{}'", port_hex),
                ])
                .output();

            if let Ok(out) = check_output {
                if out.status.success() && !out.stdout.is_empty() {
                    // Found the listener
                    return Ok(());
                }
            }

            std::thread::sleep(Duration::from_millis(200));
        }

        bail!(
            "forwarder on port {} did not start within 10 seconds",
            local_port
        )
    }

    /// Stop a TCP listener on the given port inside the container.
    pub fn stop_listener(&self, port: u16) -> Result<()> {
        // Kill any process listening on the port
        let _ = Command::new("docker")
            .args([
                "exec",
                &self.container_id,
                "pkill",
                "-f",
                &format!("nc -l {}", port),
            ])
            .output();

        // Also kill socat if it was used
        let _ = Command::new("docker")
            .args([
                "exec",
                &self.container_id,
                "pkill",
                "-f",
                &format!("socat.*{}", port),
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
        .args(["images", "-q", SSH_IMAGE_NAME])
        .output()
        .context("failed to check for docker image")?;

    if !output.stdout.is_empty() {
        return Ok(()); // Image exists
    }

    // Build the image
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dockerfile_path = Path::new(manifest_dir).join("tests/docker");

    let status = Command::new("docker")
        .args([
            "build",
            "-t",
            SSH_IMAGE_NAME,
            dockerfile_path.to_str().unwrap(),
        ])
        .status()
        .context("failed to build docker image")?;

    if !status.success() {
        bail!("docker build failed");
    }

    Ok(())
}

/// Pull service images needed for protocol detection tests.
pub fn ensure_service_images_pulled() -> Result<()> {
    let images = [
        "redis:alpine",
        "postgres:alpine",
        "mariadb:lts",
        "nginx:alpine",
        "alpine", // Used for network connectivity checks
    ];

    for image in images {
        let output = Command::new("docker")
            .args(["images", "-q", image])
            .output()
            .context("failed to check for docker image")?;

        if output.stdout.is_empty() {
            // Pull the image
            let status = Command::new("docker")
                .args(["pull", image])
                .status()
                .context("failed to pull docker image")?;

            if !status.success() {
                bail!("docker pull {} failed", image);
            }
        }
    }

    Ok(())
}
