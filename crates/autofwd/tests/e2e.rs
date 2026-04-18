mod support;

use anyhow::Result;
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use support::{
    ensure_image_built, ensure_service_images_pulled, ContainerType, ServiceContainer,
    TestContainer, TestNetwork,
};

/// Helper to run autofwd in headless mode and capture JSON events.
struct AutofwdProcess {
    child: Child,
    line_rx: mpsc::Receiver<String>,
    _reader_thread: thread::JoinHandle<()>,
}

impl AutofwdProcess {
    fn start(container: &TestContainer) -> Result<Self> {
        Self::start_with_options(container, "500ms", &[], &[])
    }

    fn start_with_args(container: &TestContainer, extra_args: &[&str]) -> Result<Self> {
        Self::start_with_options(container, "500ms", extra_args, &[])
    }

    fn start_with_options(
        container: &TestContainer,
        interval: &str,
        extra_args: &[&str],
        env_vars: &[(&str, &str)],
    ) -> Result<Self> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_autofwd"));
        cmd.arg("--headless").arg("--interval").arg(interval);

        for arg in extra_args {
            cmd.arg(arg);
        }

        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        cmd.arg(container.ssh_target())
            .arg("--")
            .args(container.ssh_args())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        // Spawn a thread to read lines and send them through a channel
        let stdout = child.stdout.take().unwrap();
        let (line_tx, line_rx) = mpsc::channel();

        let reader_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if line_tx.send(line).is_err() {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            child,
            line_rx,
            _reader_thread: reader_thread,
        })
    }

    /// Read JSON events from stdout until we see the expected event or timeout.
    fn wait_for_event(&mut self, event_type: &str, timeout: Duration) -> Result<Value> {
        let deadline = std::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("timeout waiting for event: {}", event_type);
            }

            match self.line_rx.recv_timeout(remaining) {
                Ok(line) => {
                    if line.is_empty() {
                        continue;
                    }

                    let event: Value = serde_json::from_str(&line)?;
                    if event.get("event").and_then(|e| e.as_str()) == Some(event_type) {
                        return Ok(event);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    anyhow::bail!("timeout waiting for event: {}", event_type);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("EOF without finding event: {}", event_type);
                }
            }
        }
    }

    /// Read JSON events from stdout until the predicate matches or timeout.
    fn wait_for_event_matching<F>(&mut self, timeout: Duration, mut f: F) -> Result<Value>
    where
        F: FnMut(&Value) -> bool,
    {
        let deadline = std::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("timeout waiting for matching event");
            }

            match self.line_rx.recv_timeout(remaining) {
                Ok(line) => {
                    if line.is_empty() {
                        continue;
                    }
                    let event: Value = serde_json::from_str(&line)?;
                    if f(&event) {
                        return Ok(event);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    anyhow::bail!("timeout waiting for matching event");
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("EOF without finding matching event");
                }
            }
        }
    }

    /// Wait for the expected event and return it along with all events seen.
    /// Useful for checking what events were (or weren't) emitted.
    fn wait_for_event_collecting(
        &mut self,
        event_type: &str,
        timeout: Duration,
    ) -> Result<(Value, Vec<Value>)> {
        let deadline = std::time::Instant::now() + timeout;
        let mut collected = Vec::new();

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("timeout waiting for event: {}", event_type);
            }

            match self.line_rx.recv_timeout(remaining) {
                Ok(line) => {
                    if line.is_empty() {
                        continue;
                    }

                    let event: Value = serde_json::from_str(&line)?;
                    collected.push(event.clone());
                    if event.get("event").and_then(|e| e.as_str()) == Some(event_type) {
                        return Ok((event, collected));
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    anyhow::bail!("timeout waiting for event: {}", event_type);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("EOF without finding event: {}", event_type);
                }
            }
        }
    }

    /// Stop the process.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for AutofwdProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Check if a TCP port is reachable on localhost.
fn check_port(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        Duration::from_secs(1),
    )
    .is_ok()
}

/// Connect to local port and read a line; returns trimmed string if successful.
/// `start_listener` publishes "ready\n" on each accept, so this verifies the
/// forward is actually carrying traffic end-to-end (not just a locally bound
/// socket by a now-dead master).
fn read_line_from_port(port: u16) -> Result<String> {
    use std::io::Read;
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        Duration::from_secs(3),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

/// Wait until data actually flows through the forward on the given port.
/// Retries until timeout. Returns true if we got expected data, false otherwise.
fn wait_for_forward_data(port: u16, expected: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        match read_line_from_port(port) {
            Ok(line) if line == expected => return true,
            _ => std::thread::sleep(Duration::from_millis(300)),
        }
    }
    false
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_docker_image_builds() -> Result<()> {
    ensure_image_built()?;
    Ok(())
}

#[test]
fn test_container_starts() -> Result<()> {
    ensure_image_built()?;
    let container = TestContainer::start()?;

    // Verify we can execute commands
    let output = container.exec("echo hello")?;
    assert_eq!(output.trim(), "hello");

    Ok(())
}

#[test]
fn test_ssh_master_lifecycle() -> Result<()> {
    ensure_image_built()?;
    let container = TestContainer::start()?;

    // Build path for control socket
    let control_path =
        std::env::temp_dir().join(format!("autofwd-test-{}.sock", std::process::id()));

    // Start SSH master
    let status = Command::new("ssh")
        .args(container.ssh_args())
        .args(["-M", "-N", "-f"])
        .arg("-o")
        .arg("ControlPersist=yes")
        .arg("-S")
        .arg(control_path.to_str().unwrap())
        .arg(container.ssh_target())
        .status()?;

    assert!(status.success(), "SSH master should start successfully");

    // Check master is alive
    let status = Command::new("ssh")
        .args(container.ssh_args())
        .arg("-S")
        .arg(control_path.to_str().unwrap())
        .arg("-O")
        .arg("check")
        .arg(container.ssh_target())
        .status()?;

    assert!(status.success(), "SSH master should be alive");

    // Exit master
    let status = Command::new("ssh")
        .args(container.ssh_args())
        .arg("-S")
        .arg(control_path.to_str().unwrap())
        .arg("-O")
        .arg("exit")
        .arg(container.ssh_target())
        .status()?;

    assert!(status.success(), "SSH master should exit cleanly");

    // Cleanup socket file
    let _ = std::fs::remove_file(&control_path);

    Ok(())
}

#[test]
fn test_headless_ready_event() -> Result<()> {
    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start(&container)?;

    // Should receive ready event
    let event = autofwd.wait_for_event("ready", Duration::from_secs(10))?;
    assert!(event.get("target").is_some());

    Ok(())
}

#[test]
fn test_port_detection_and_forwarding() -> Result<()> {
    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start(&container)?;

    // Wait for ready
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    // Start a listener on the remote
    container.start_listener(8080)?;

    // Should detect and forward
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(10))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(8080)
    );

    let local_port = event.get("local_port").and_then(|p| p.as_u64()).unwrap() as u16;

    // Verify local port is accessible
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        check_port(local_port),
        "Local port {} should be accessible",
        local_port
    );

    Ok(())
}

#[test]
fn test_port_collision_fallback() -> Result<()> {
    ensure_image_built()?;
    let container = TestContainer::start()?;

    // Bind local port 9000 first
    let local_listener = std::net::TcpListener::bind("127.0.0.1:9000")?;

    let mut autofwd = AutofwdProcess::start(&container)?;
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    // Start listener on remote port 9000
    container.start_listener(9000)?;

    // Should forward to a different local port
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(10))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(9000)
    );

    let local_port = event.get("local_port").and_then(|p| p.as_u64()).unwrap() as u16;
    assert_ne!(
        local_port, 9000,
        "Should use different local port due to collision"
    );

    drop(local_listener);

    Ok(())
}

#[test]
fn test_port_removal_detection() -> Result<()> {
    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start(&container)?;
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    // Start a listener
    container.start_listener(7777)?;

    // Wait for it to be forwarded
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(10))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(7777)
    );

    // Stop the listener
    container.stop_listener(7777)?;

    // Should detect removal
    let event = autofwd.wait_for_event("forward_removed", Duration::from_secs(10))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(7777)
    );

    Ok(())
}

// ============================================================================
// Protocol Detection Tests
// ============================================================================

#[test]
fn test_protocol_detection_http() -> Result<()> {
    ensure_image_built()?;
    ensure_service_images_pulled()?;

    // Create isolated network
    let network = TestNetwork::new()?;

    // Start nginx container
    let nginx = ServiceContainer::start(ContainerType::Http, &network)?;

    // Start SSH container on same network
    let ssh = TestContainer::start_on_network(&network)?;

    // Set up port forwarder in SSH container to nginx
    ssh.start_forwarder(8080, nginx.hostname(), nginx.port())?;

    // Start autofwd
    let mut autofwd = AutofwdProcess::start(&ssh)?;
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    // Wait for forward_added
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(15))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(8080)
    );

    // Wait for protocol detection
    let event = autofwd.wait_for_event("protocol_detected", Duration::from_secs(10))?;
    assert_eq!(event.get("protocol").and_then(|p| p.as_str()), Some("http"));

    Ok(())
}

#[test]
fn test_protocol_detection_redis() -> Result<()> {
    ensure_image_built()?;
    ensure_service_images_pulled()?;

    let network = TestNetwork::new()?;
    let redis = ServiceContainer::start(ContainerType::Redis, &network)?;
    let ssh = TestContainer::start_on_network(&network)?;

    // Forward redis port
    ssh.start_forwarder(6379, redis.hostname(), redis.port())?;

    // Start autofwd with --allow to override default deny
    let mut autofwd = AutofwdProcess::start_with_args(&ssh, &["--allow", "6379"])?;
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(15))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(6379)
    );

    let event = autofwd.wait_for_event("protocol_detected", Duration::from_secs(10))?;
    assert_eq!(
        event.get("protocol").and_then(|p| p.as_str()),
        Some("redis")
    );

    Ok(())
}

#[test]
fn test_protocol_detection_postgresql() -> Result<()> {
    ensure_image_built()?;
    ensure_service_images_pulled()?;

    let network = TestNetwork::new()?;
    let postgres = ServiceContainer::start(ContainerType::PostgreSql, &network)?;
    let ssh = TestContainer::start_on_network(&network)?;

    ssh.start_forwarder(5432, postgres.hostname(), postgres.port())?;

    let mut autofwd = AutofwdProcess::start_with_args(&ssh, &["--allow", "5432"])?;
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(15))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(5432)
    );

    let event = autofwd.wait_for_event("protocol_detected", Duration::from_secs(10))?;
    assert_eq!(
        event.get("protocol").and_then(|p| p.as_str()),
        Some("postgresql")
    );

    Ok(())
}

#[test]
fn test_protocol_detection_mariadb() -> Result<()> {
    ensure_image_built()?;
    ensure_service_images_pulled()?;

    let network = TestNetwork::new()?;
    let mariadb = ServiceContainer::start(ContainerType::MariaDb, &network)?;
    let ssh = TestContainer::start_on_network(&network)?;

    ssh.start_forwarder(3306, mariadb.hostname(), mariadb.port())?;

    let mut autofwd = AutofwdProcess::start_with_args(&ssh, &["--allow", "3306"])?;
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(15))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(3306)
    );

    let event = autofwd.wait_for_event("protocol_detected", Duration::from_secs(10))?;
    assert_eq!(
        event.get("protocol").and_then(|p| p.as_str()),
        Some("mysql")
    );

    Ok(())
}

#[test]
fn test_assume_http_flag() -> Result<()> {
    ensure_image_built()?;
    ensure_service_images_pulled()?;

    let network = TestNetwork::new()?;
    let redis = ServiceContainer::start(ContainerType::Redis, &network)?;
    let ssh = TestContainer::start_on_network(&network)?;

    ssh.start_forwarder(6379, redis.hostname(), redis.port())?;

    // Use --assume-http flag - should skip detection and assume HTTP
    let mut autofwd = AutofwdProcess::start_with_args(&ssh, &["--allow", "6379", "--assume-http"])?;
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(15))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(6379)
    );
    // With --assume-http, protocol should be "http" even for redis
    assert_eq!(event.get("protocol").and_then(|p| p.as_str()), Some("http"));

    Ok(())
}

// ============================================================================
// Agent Deployment Tests
// ============================================================================

/// Check if we're running with real agent binaries (not stubs).
/// Real binaries are >50KB, stubs are just a few bytes.
fn agents_available() -> bool {
    // Check if target/agents directory has files >50KB
    let agents_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/agents");

    if !agents_dir.exists() {
        return false;
    }

    // Check x86_64 agent size (it's always built)
    let x86_agent = agents_dir.join("x86_64-unknown-linux-musl.zst");
    if let Ok(metadata) = std::fs::metadata(&x86_agent) {
        metadata.len() > 50_000
    } else {
        false
    }
}

#[test]
fn test_agent_deployment() -> Result<()> {
    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start(&container)?;

    // Collect events while waiting for ready
    let (_ready, events) = autofwd.wait_for_event_collecting("ready", Duration::from_secs(15))?;

    // Check what agent-related event we got
    let got_deployed = events
        .iter()
        .any(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_deployed"));
    let got_fallback = events
        .iter()
        .any(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_fallback"));

    if agents_available() {
        // With real agents, we should see agent_deployed, not agent_fallback
        assert!(
            got_deployed,
            "Expected agent_deployed event with real agent binaries. Events: {:?}",
            events
        );
        assert!(
            !got_fallback,
            "Should not see agent_fallback with real agent binaries. Events: {:?}",
            events
        );

        // Check the architecture in agent_deployed
        let deployed_event = events
            .iter()
            .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_deployed"))
            .unwrap();
        let arch = deployed_event.get("arch").and_then(|v| v.as_str());
        assert!(
            arch.is_some(),
            "agent_deployed should include arch. Event: {:?}",
            deployed_event
        );
        println!("Agent deployed for arch: {}", arch.unwrap());
    } else {
        // With stub agents, we should see agent_fallback
        assert!(
            got_fallback,
            "Expected agent_fallback event with stub binaries. Events: {:?}",
            events
        );
        println!("Running with stub agents, fallback used as expected");
    }

    // Verify port forwarding still works either way
    container.start_listener(9999)?;
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(10))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(9999)
    );

    Ok(())
}

#[test]
fn test_agent_with_process_name() -> Result<()> {
    // This test verifies that process names are detected when using the agent
    // (process names are NOT available in shell fallback mode)
    if !agents_available() {
        println!("Skipping test_agent_with_process_name - agents not available");
        return Ok(());
    }

    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start(&container)?;

    // Wait for agent to be deployed
    let (_ready, events) = autofwd.wait_for_event_collecting("ready", Duration::from_secs(15))?;
    let got_deployed = events
        .iter()
        .any(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_deployed"));
    assert!(got_deployed, "Agent should be deployed for this test");

    // Start a listener (nc command)
    container.start_listener(8888)?;

    // Wait for forward_added
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(10))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(8888)
    );

    // With the agent, process_name should be detected
    // Note: The listener uses 'nc' via a shell loop, so we expect "sh" or "nc"
    let process_name = event.get("process_name").and_then(|v| v.as_str());
    assert!(
        process_name.is_some(),
        "Agent should detect process name. Event: {:?}",
        event
    );
    println!("Detected process name: {}", process_name.unwrap());

    Ok(())
}

#[test]
fn test_shell_fallback_mode() -> Result<()> {
    // This test verifies that the shell fallback mode works correctly
    // by forcing it via AUTOFWD_FORCE_SHELL environment variable.
    // This ensures port forwarding works even without the agent.
    ensure_image_built()?;
    let container = TestContainer::start()?;

    // Start autofwd with forced shell mode
    let mut autofwd = AutofwdProcess::start_with_options(
        &container,
        "500ms",
        &[],
        &[("AUTOFWD_FORCE_SHELL", "1")],
    )?;

    // Collect events while waiting for ready
    let (_ready, events) = autofwd.wait_for_event_collecting("ready", Duration::from_secs(15))?;

    // Should see agent_fallback, NOT agent_deployed
    let got_fallback = events
        .iter()
        .any(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_fallback"));
    let got_deployed = events
        .iter()
        .any(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_deployed"));

    assert!(
        got_fallback,
        "Should see agent_fallback with AUTOFWD_FORCE_SHELL. Events: {:?}",
        events
    );
    assert!(
        !got_deployed,
        "Should NOT see agent_deployed with AUTOFWD_FORCE_SHELL. Events: {:?}",
        events
    );

    // Check the fallback reason
    let fallback_event = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_fallback"))
        .unwrap();
    let reason = fallback_event.get("reason").and_then(|v| v.as_str());
    assert!(
        reason
            .map(|r| r.contains("AUTOFWD_FORCE_SHELL"))
            .unwrap_or(false),
        "Fallback reason should mention AUTOFWD_FORCE_SHELL. Event: {:?}",
        fallback_event
    );

    // Verify port forwarding still works in shell mode
    container.start_listener(7777)?;
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(10))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(7777)
    );

    // In shell mode, process_name should be null (shell script can't detect it)
    let process_name = event.get("process_name");
    assert!(
        process_name.is_none() || process_name == Some(&Value::Null),
        "Shell fallback should NOT have process_name. Event: {:?}",
        event
    );

    println!("Shell fallback mode working correctly - port forwarded without process name");

    Ok(())
}

#[test]
fn test_agent_backoff_emits_diagnostics() -> Result<()> {
    // Verifies agent-side exponential backoff is observable via optional JSON diagnostics.
    if !agents_available() {
        println!("Skipping test_agent_backoff_emits_diagnostics - agents not available");
        return Ok(());
    }

    ensure_image_built()?;
    let container = TestContainer::start()?;

    // Use a small min interval so backoff steps happen quickly, and cap max interval for determinism.
    let mut autofwd = AutofwdProcess::start_with_options(
        &container,
        "50ms",
        &[],
        &[
            ("AUTOFWD_DEBUG_EVENTS", "1"),
            ("AUTOFWD_AGENT_DEBUG", "1"),
            ("AUTOFWD_AGENT_MAX_INTERVAL_MS", "200"),
            // Make this test deterministic across environments.
            ("AUTOFWD_AGENT_DISABLE_NETLINK", "1"),
        ],
    )?;

    // Collect startup events so we can assert we're actually using the agent (not shell fallback).
    let (_ready, startup_events) =
        autofwd.wait_for_event_collecting("ready", Duration::from_secs(15))?;
    let got_fallback = startup_events
        .iter()
        .any(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_fallback"));
    assert!(
        !got_fallback,
        "Expected agent mode (no fallback). Startup events: {:?}",
        startup_events
    );

    // Wait for *any* diagnostics first to confirm the channel is working and max interval is applied.
    let first_diag = autofwd.wait_for_event_matching(Duration::from_secs(10), |e| {
        e.get("event").and_then(|v| v.as_str()) == Some("agent_diagnostics")
    })?;
    println!("Saw first agent diagnostics: {:?}", first_diag);
    assert_eq!(
        first_diag.get("backend").and_then(|v| v.as_str()),
        Some("proc"),
        "Expected proc backend (netlink disabled). Event: {:?}",
        first_diag
    );
    assert_eq!(
        first_diag.get("min_ms").and_then(|v| v.as_u64()),
        Some(50),
        "Expected min_ms=50. Event: {:?}",
        first_diag
    );
    assert_eq!(
        first_diag.get("max_ms").and_then(|v| v.as_u64()),
        Some(200),
        "Expected max_ms=200 (flag must reach agent). Event: {:?}",
        first_diag
    );

    // Now wait until the agent reports it has backed off to the configured max interval.
    let ev = autofwd.wait_for_event_matching(Duration::from_secs(10), |e| {
        e.get("event").and_then(|v| v.as_str()) == Some("agent_diagnostics")
            && e.get("phase").and_then(|v| v.as_str()) == Some("backoff")
            && e.get("sleep_ms").and_then(|v| v.as_u64()) == Some(200)
    })?;
    println!("Saw agent diagnostics at max backoff: {:?}", ev);

    // Trigger activity; backoff should reset.
    container.start_listener(7778)?;

    // Ensure forwarding still works.
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(10))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(7778)
    );

    // We should eventually see a reset diagnostic (sleep back to min interval).
    let ev = autofwd.wait_for_event_matching(Duration::from_secs(10), |e| {
        e.get("event").and_then(|v| v.as_str()) == Some("agent_diagnostics")
            && e.get("phase").and_then(|v| v.as_str()) == Some("reset")
            && e.get("sleep_ms").and_then(|v| v.as_u64()) == Some(50)
    })?;
    println!("Saw agent reset diagnostics: {:?}", ev);

    Ok(())
}

#[test]
fn test_agent_netlink_backend_used() -> Result<()> {
    // Verifies that netlink sock_diag is used by default when available.
    // Skip on QEMU-emulated platforms where netlink syscalls may not work properly.
    if let Ok(platform) = std::env::var("AUTOFWD_TEST_PLATFORM") {
        if platform != "linux/amd64" {
            println!(
                "Skipping test_agent_netlink_backend_used - netlink unreliable under QEMU ({})",
                platform
            );
            return Ok(());
        }
    }

    if !agents_available() {
        println!("Skipping test_agent_netlink_backend_used - agents not available");
        return Ok(());
    }

    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start_with_options(
        &container,
        "50ms",
        &[],
        &[
            ("AUTOFWD_DEBUG_EVENTS", "1"),
            ("AUTOFWD_AGENT_DEBUG", "1"),
            ("AUTOFWD_AGENT_MAX_INTERVAL_MS", "200"),
        ],
    )?;

    let (_ready, startup_events) =
        autofwd.wait_for_event_collecting("ready", Duration::from_secs(15))?;
    let got_fallback = startup_events
        .iter()
        .any(|e| e.get("event").and_then(|v| v.as_str()) == Some("agent_fallback"));
    assert!(
        !got_fallback,
        "Expected agent mode (no fallback). Startup events: {:?}",
        startup_events
    );

    let first_diag = autofwd.wait_for_event_matching(Duration::from_secs(10), |e| {
        e.get("event").and_then(|v| v.as_str()) == Some("agent_diagnostics")
    })?;
    println!("Saw first agent diagnostics: {:?}", first_diag);

    assert_eq!(
        first_diag.get("backend").and_then(|v| v.as_str()),
        Some("netlink"),
        "Expected netlink backend by default. Event: {:?}",
        first_diag
    );

    Ok(())
}

#[test]
fn test_startup_timing() -> Result<()> {
    // This test captures timing events to debug startup performance
    ensure_image_built()?;
    let container = TestContainer::start()?;

    // Start a listener first so there's something to detect
    container.start_listener(9999)?;

    let mut autofwd = AutofwdProcess::start(&container)?;

    // Wait for forward_added (means first data was processed)
    let (_fwd, events) =
        autofwd.wait_for_event_collecting("forward_added", Duration::from_secs(30))?;

    // Print all timing events
    println!("\n=== Startup Timing ===");
    for event in &events {
        if event.get("event").and_then(|v| v.as_str()) == Some("timing") {
            let phase = event.get("phase").and_then(|v| v.as_str()).unwrap_or("?");
            let duration = event
                .get("duration_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("  {}: {}ms", phase, duration);
        }
    }
    println!("======================\n");

    // Also print non-timing events for context
    println!("All events:");
    for event in &events {
        let event_type = event.get("event").and_then(|v| v.as_str()).unwrap_or("?");
        println!("  {}: {:?}", event_type, event);
    }

    Ok(())
}

#[test]
fn test_reconnect_after_container_pause() -> Result<()> {
    // Simulates laptop sleep/wake by pausing the SSH server container.
    // We expect autofwd to detect staleness and recover without restart.
    if !agents_available() {
        println!("Skipping test_reconnect_after_container_pause - agents not available");
        return Ok(());
    }

    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start_with_options(
        &container,
        "200ms",
        &[],
        &[
            ("AUTOFWD_STALE_MS", "6000"),
            // Ensure we can observe state changes
            ("AUTOFWD_DEBUG_EVENTS", "1"),
            ("AUTOFWD_AGENT_DEBUG", "1"),
            ("AUTOFWD_AGENT_MAX_INTERVAL_MS", "500"),
        ],
    )?;

    autofwd.wait_for_event("ready", Duration::from_secs(15))?;

    // Pause long enough to exceed AUTOFWD_STALE_MS.
    container.pause()?;
    std::thread::sleep(Duration::from_secs(7));

    // We should get a connection_lost event (triggered by stale watchdog).
    autofwd.wait_for_event("connection_lost", Duration::from_secs(10))?;

    // Bring it back and ensure we can forward a new port.
    container.unpause()?;
    std::thread::sleep(Duration::from_millis(500));

    // We should see a reconnected event once the monitor stream is alive again.
    autofwd.wait_for_event("reconnected", Duration::from_secs(20))?;

    container.start_listener(7781)?;
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(20))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(7781)
    );

    Ok(())
}

#[test]
fn test_existing_forwards_restored_after_pause() -> Result<()> {
    // Regression test for "tunnels not restored after laptop sleep/wake".
    //
    // Flow:
    //   1. Start listener and let autofwd forward it.
    //   2. Verify the local forwarded port works.
    //   3. Pause container longer than AUTOFWD_STALE_MS.
    //   4. Unpause.
    //   5. Verify the SAME local port still works after reconnect.
    if !agents_available() {
        println!("Skipping test_existing_forwards_restored_after_pause - agents not available");
        return Ok(());
    }

    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start_with_options(
        &container,
        "200ms",
        &[],
        &[
            ("AUTOFWD_STALE_MS", "6000"),
            ("AUTOFWD_AGENT_MAX_INTERVAL_MS", "500"),
        ],
    )?;

    autofwd.wait_for_event("ready", Duration::from_secs(15))?;

    // Establish a forward BEFORE the pause.
    container.start_listener(7790)?;
    let added = autofwd.wait_for_event("forward_added", Duration::from_secs(15))?;
    let local_port = added
        .get("local_port")
        .and_then(|p| p.as_u64())
        .expect("forward_added should have local_port") as u16;

    // Verify data actually flows through the forward BEFORE the pause.
    assert!(
        wait_for_forward_data(local_port, "ready", Duration::from_secs(5)),
        "forward on {} should carry data before pause",
        local_port
    );

    // Simulate laptop sleep.
    container.pause()?;
    std::thread::sleep(Duration::from_secs(7));

    autofwd.wait_for_event("connection_lost", Duration::from_secs(10))?;

    container.unpause()?;

    // Wait for autofwd to declare itself reconnected.
    autofwd.wait_for_event("reconnected", Duration::from_secs(20))?;

    // Data should flow through the SAME local port after reconnect. This
    // catches the case where the port is still bound (by the old master) but
    // the forward no longer actually carries traffic.
    assert!(
        wait_for_forward_data(local_port, "ready", Duration::from_secs(15)),
        "existing forward on {} should still carry data after pause/unpause",
        local_port
    );

    // And new forwards should still work.
    container.start_listener(7791)?;
    let event = autofwd.wait_for_event("forward_added", Duration::from_secs(20))?;
    assert_eq!(
        event.get("remote_port").and_then(|p| p.as_u64()),
        Some(7791)
    );

    Ok(())
}

#[test]
fn test_forwards_restored_when_old_master_holds_ports() -> Result<()> {
    // Closer simulation of real laptop sleep/wake: the old ControlMaster
    // process is STILL ALIVE when the stale watchdog fires, still holding
    // the bound local ports. The recovery code must free those ports before
    // the new master tries to bind them, or the forward will fail to restore
    // through the *new* master.
    //
    // We reproduce this by:
    //   1. Starting autofwd and forwarding a port.
    //   2. Pausing the container just long enough for the stale watchdog to
    //      fire, but not long enough for ServerAliveInterval (15s) to kill
    //      the master.
    //   3. After recovery, killing the old master PID *manually*. If the new
    //      master is actually handling the forward, data should still flow.
    //      If the old master was secretly doing the work, data flow breaks.
    if !agents_available() {
        println!(
            "Skipping test_forwards_restored_when_old_master_holds_ports - agents not available"
        );
        return Ok(());
    }

    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start_with_options(
        &container,
        "200ms",
        &[],
        &[
            ("AUTOFWD_STALE_MS", "4000"),
            ("AUTOFWD_AGENT_MAX_INTERVAL_MS", "500"),
        ],
    )?;

    autofwd.wait_for_event("ready", Duration::from_secs(15))?;

    container.start_listener(7795)?;
    let added = autofwd.wait_for_event("forward_added", Duration::from_secs(15))?;
    let local_port = added
        .get("local_port")
        .and_then(|p| p.as_u64())
        .expect("forward_added should have local_port") as u16;

    assert!(
        wait_for_forward_data(local_port, "ready", Duration::from_secs(5)),
        "forward on {} should carry data before pause",
        local_port
    );

    // Record the PIDs of every ssh process currently bound to local_port.
    // After the stale watchdog fires, we'll kill these "old" masters.
    let old_master_pids = pids_listening_on_port(local_port);
    println!(
        "Old master PID(s) holding local port {}: {:?}",
        local_port, old_master_pids
    );
    assert!(
        !old_master_pids.is_empty(),
        "expected an ssh master to be bound to local port {}",
        local_port
    );

    container.pause()?;
    std::thread::sleep(Duration::from_millis(5000));

    autofwd.wait_for_event("connection_lost", Duration::from_secs(5))?;
    container.unpause()?;

    autofwd.wait_for_event("reconnected", Duration::from_secs(20))?;
    std::thread::sleep(Duration::from_millis(1500));

    // Now kill the OLD master(s). If autofwd's "new master" is actually
    // serving the forward, killing the old master should not break data flow.
    for pid in &old_master_pids {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
    std::thread::sleep(Duration::from_millis(500));

    let new_master_pids = pids_listening_on_port(local_port);
    println!(
        "New master PID(s) holding local port {} after old killed: {:?}",
        local_port, new_master_pids
    );

    assert!(
        wait_for_forward_data(local_port, "ready", Duration::from_secs(15)),
        "forward on {} should still carry data after old master was killed; new_pids={:?}",
        local_port,
        new_master_pids
    );

    Ok(())
}

#[test]
fn test_forward_verified_on_add() -> Result<()> {
    // Verifies that newly-added forwards emit a forward_verified event
    // shortly after forward_added, so the status overlay doesn't show
    // "never verified" indefinitely.
    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start(&container)?;
    autofwd.wait_for_event("ready", Duration::from_secs(10))?;

    container.start_listener(8088)?;

    let added = autofwd.wait_for_event("forward_added", Duration::from_secs(10))?;
    let local_port = added.get("local_port").and_then(|p| p.as_u64()).unwrap() as u16;

    // Soon after, we should see a forward_verified event with alive=true.
    let verified = autofwd.wait_for_event_matching(Duration::from_secs(5), |e| {
        e.get("event").and_then(|v| v.as_str()) == Some("forward_verified")
            && e.get("local_port").and_then(|p| p.as_u64()) == Some(local_port as u64)
    })?;
    assert_eq!(
        verified.get("alive").and_then(|v| v.as_bool()),
        Some(true),
        "expected alive=true, got {:?}",
        verified
    );

    Ok(())
}

#[test]
fn test_reconnect_emits_rich_events() -> Result<()> {
    // Verifies the observability work: during a sleep/wake cycle we emit
    // stale_detected, master_terminated, master_started, restore_attempt,
    // forward_verified, forward_restored — so the user can see what happened.
    if !agents_available() {
        println!("Skipping test_reconnect_emits_rich_events - agents not available");
        return Ok(());
    }

    ensure_image_built()?;
    let container = TestContainer::start()?;

    let mut autofwd = AutofwdProcess::start_with_options(
        &container,
        "200ms",
        &[],
        &[
            ("AUTOFWD_STALE_MS", "4000"),
            ("AUTOFWD_AGENT_MAX_INTERVAL_MS", "500"),
        ],
    )?;

    autofwd.wait_for_event("ready", Duration::from_secs(15))?;

    container.start_listener(7798)?;
    autofwd.wait_for_event("forward_added", Duration::from_secs(15))?;

    container.pause()?;
    std::thread::sleep(Duration::from_millis(5000));

    // Collect events through forward_restored so we can assert on the sequence.
    let (_restored, events) = {
        let result = autofwd
            .wait_for_event_collecting("connection_lost", Duration::from_secs(10))?
            .1;
        container.unpause()?;
        let (restored, more) =
            autofwd.wait_for_event_collecting("forward_restored", Duration::from_secs(25))?;
        let mut combined = result;
        combined.extend(more);
        (restored, combined)
    };

    fn has(events: &[Value], name: &str) -> bool {
        events
            .iter()
            .any(|e| e.get("event").and_then(|v| v.as_str()) == Some(name))
    }

    assert!(has(&events, "stale_detected"), "expected stale_detected");
    assert!(
        has(&events, "master_terminated"),
        "expected master_terminated"
    );
    assert!(has(&events, "master_started"), "expected master_started");
    assert!(has(&events, "restore_attempt"), "expected restore_attempt");
    assert!(
        has(&events, "forward_verified"),
        "expected forward_verified"
    );

    // The stale_detected event should report an idle time at/above the threshold.
    let stale = events
        .iter()
        .find(|e| e.get("event").and_then(|v| v.as_str()) == Some("stale_detected"))
        .unwrap();
    let idle = stale
        .get("idle_ms")
        .and_then(|v| v.as_u64())
        .expect("idle_ms in stale_detected");
    assert!(idle >= 4000, "expected idle_ms >= 4000, got {}", idle);

    Ok(())
}

/// Return all PIDs currently bound to the given local TCP port. macOS-only.
fn pids_listening_on_port(port: u16) -> Vec<u32> {
    let output = std::process::Command::new("lsof")
        .args(["-nP", "-iTCP:", &format!("-iTCP:{}", port), "-sTCP:LISTEN"])
        .args(["-t"])
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok())
            .collect(),
        _ => {
            // Fallback: use `-i :port` form which works more broadly.
            let out = std::process::Command::new("lsof")
                .args(["-nP", "-t", "-i", &format!(":{}", port), "-sTCP:LISTEN"])
                .output()
                .ok();
            out.and_then(|o| {
                if o.status.success() {
                    Some(
                        String::from_utf8_lossy(&o.stdout)
                            .split_whitespace()
                            .filter_map(|s| s.parse::<u32>().ok())
                            .collect(),
                    )
                } else {
                    None
                }
            })
            .unwrap_or_default()
        }
    }
}
