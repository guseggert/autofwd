mod support;

use anyhow::Result;
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use support::{ensure_image_built, TestContainer};

/// Helper to run autofwd in headless mode and capture JSON events.
struct AutofwdProcess {
    child: Child,
    line_rx: mpsc::Receiver<String>,
    _reader_thread: thread::JoinHandle<()>,
}

impl AutofwdProcess {
    fn start(container: &TestContainer) -> Result<Self> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_autofwd"));
        cmd.arg("--headless")
            .arg("--interval")
            .arg("500ms")
            .arg(container.ssh_target())
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
