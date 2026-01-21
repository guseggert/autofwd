//! autofwd-agent: High-performance server-side agent for port monitoring.
//!
//! Monitors listening TCP ports by reading /proc directly (no subprocess spawning).
//! Uses parallel scanning and caching for optimal performance.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use std::{env, thread};

const END_MARKER: &str = "__AUTOFWD_END__";
const HEARTBEAT_MARKER: &str = "__AUTOFWD_HEARTBEAT__";
const NUM_THREADS: usize = 4;

/// Information about a listening port.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PortInfo {
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    pub ipv4: bool,
    pub ipv6: bool,
}

/// Snapshot of all listening ports.
#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub ports: Vec<PortInfo>,
}

/// A listening socket from /proc/net/tcp.
#[derive(Debug, Clone)]
struct ListeningSocket {
    port: u16,
    inode: u64,
    is_v6: bool,
}

/// Port monitor with caching for efficient repeated polling.
struct PortMonitor {
    /// Cache: inode → (pid, process_name)
    inode_cache: HashMap<u64, (u32, String)>,
    /// Inodes seen in the last poll
    last_inodes: HashSet<u64>,
    /// Last snapshot key for change detection
    last_snapshot_key: String,
}

impl PortMonitor {
    fn new() -> Self {
        Self {
            inode_cache: HashMap::new(),
            last_inodes: HashSet::new(),
            last_snapshot_key: String::new(),
        }
    }

    /// Poll for port changes. Returns Some(snapshot) if changed, None otherwise.
    fn poll(&mut self) -> Option<Snapshot> {
        // 1. Read listening sockets from /proc/net/tcp{,6}
        let sockets = read_listening_sockets();

        // 2. Build current state
        let current_inodes: HashSet<u64> = sockets.iter().map(|s| s.inode).collect();

        // 3. Check if we need to update the cache
        if current_inodes != self.last_inodes {
            // Find new inodes we haven't seen before
            let new_inodes: HashSet<u64> = current_inodes
                .difference(&self.last_inodes)
                .copied()
                .collect();

            if !new_inodes.is_empty() {
                // Parallel scan for new inodes only
                let new_mappings = build_inode_pid_map(&new_inodes);
                for (inode, pid) in new_mappings {
                    let name = get_process_name(pid).unwrap_or_default();
                    self.inode_cache.insert(inode, (pid, name));
                }
            }

            // Remove stale entries
            self.inode_cache
                .retain(|inode, _| current_inodes.contains(inode));
            self.last_inodes = current_inodes;
        }

        // 4. Build snapshot and check if it changed
        let snapshot = self.build_snapshot(&sockets);
        let snapshot_key = snapshot_key(&snapshot);

        if snapshot_key != self.last_snapshot_key {
            self.last_snapshot_key = snapshot_key;
            Some(snapshot)
        } else {
            None
        }
    }

    fn build_snapshot(&self, sockets: &[ListeningSocket]) -> Snapshot {
        // Group sockets by port
        let mut port_map: HashMap<u16, PortInfo> = HashMap::new();

        for socket in sockets {
            let entry = port_map.entry(socket.port).or_insert(PortInfo {
                port: socket.port,
                process: None,
                ipv4: false,
                ipv6: false,
            });

            if socket.is_v6 {
                entry.ipv6 = true;
            } else {
                entry.ipv4 = true;
            }

            // Set process name from cache if available
            if entry.process.is_none() {
                if let Some((_, name)) = self.inode_cache.get(&socket.inode) {
                    if !name.is_empty() {
                        entry.process = Some(name.clone());
                    }
                }
            }
        }

        let mut ports: Vec<PortInfo> = port_map.into_values().collect();
        ports.sort_by_key(|p| p.port);
        Snapshot { ports }
    }
}

/// Create a comparable key for change detection.
fn snapshot_key(snapshot: &Snapshot) -> String {
    snapshot
        .ports
        .iter()
        .map(|p| format!("{}:{:?}", p.port, p.process))
        .collect::<Vec<_>>()
        .join(",")
}

// =============================================================================
// /proc/net/tcp parsing
// =============================================================================

/// Read listening sockets from /proc/net/tcp and /proc/net/tcp6.
fn read_listening_sockets() -> Vec<ListeningSocket> {
    let mut sockets = Vec::new();

    // Read IPv4
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        parse_proc_net_tcp(&content, false, &mut sockets);
    }

    // Read IPv6
    if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
        parse_proc_net_tcp(&content, true, &mut sockets);
    }

    sockets
}

/// Parse /proc/net/tcp or /proc/net/tcp6 content.
///
/// Format (space-separated, header line first):
///   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
///    0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 ...
///
/// - local_address is hex IP:port (e.g., 00000000:1F90 = 0.0.0.0:8080)
/// - st (state) 0A = TCP_LISTEN
/// - inode is the socket inode for PID mapping
fn parse_proc_net_tcp(content: &str, is_v6: bool, sockets: &mut Vec<ListeningSocket>) {
    for line in content.lines().skip(1) {
        // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // parts[3] is state, 0A = LISTEN
        if parts[3] != "0A" {
            continue;
        }

        // parts[1] is local_address (IP:port in hex)
        let local_addr = parts[1];
        let port = match parse_hex_port(local_addr) {
            Some(p) => p,
            None => continue,
        };

        // parts[9] is inode
        let inode: u64 = match parts[9].parse() {
            Ok(i) => i,
            Err(_) => continue,
        };

        // Skip inode 0 (not a real socket)
        if inode == 0 {
            continue;
        }

        sockets.push(ListeningSocket { port, inode, is_v6 });
    }
}

/// Parse port from hex address like "00000000:1F90" or "00000000000000000000000000000000:1F90"
fn parse_hex_port(addr: &str) -> Option<u16> {
    let port_hex = addr.rsplit(':').next()?;
    u16::from_str_radix(port_hex, 16).ok()
}

// =============================================================================
// Parallel inode → PID scanning
// =============================================================================

/// Build a map of socket inodes to PIDs by scanning /proc/[pid]/fd.
/// Uses parallel scanning with early exit when all inodes are found.
fn build_inode_pid_map(needed_inodes: &HashSet<u64>) -> HashMap<u64, u32> {
    if needed_inodes.is_empty() {
        return HashMap::new();
    }

    let pids = list_pids();
    if pids.is_empty() {
        return HashMap::new();
    }

    let result: Mutex<HashMap<u64, u32>> = Mutex::new(HashMap::new());
    let remaining = AtomicUsize::new(needed_inodes.len());

    // References for sharing across threads
    let result_ref = &result;
    let remaining_ref = &remaining;

    thread::scope(|s| {
        let chunk_size = (pids.len() / NUM_THREADS).max(1);

        for chunk in pids.chunks(chunk_size) {
            s.spawn(move || {
                for &pid in chunk {
                    // Early exit if all inodes found
                    if remaining_ref.load(Ordering::Relaxed) == 0 {
                        return;
                    }
                    scan_pid_fds(pid, needed_inodes, result_ref, remaining_ref);
                }
            });
        }
    });

    result.into_inner().unwrap()
}

/// List all numeric PIDs from /proc.
fn list_pids() -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .collect()
}

/// Scan a single PID's fd directory for socket inodes.
fn scan_pid_fds(
    pid: u32,
    needed_inodes: &HashSet<u64>,
    result: &Mutex<HashMap<u64, u32>>,
    remaining: &AtomicUsize,
) {
    let fd_path = format!("/proc/{}/fd", pid);
    let Ok(entries) = fs::read_dir(&fd_path) else {
        return; // Can't read (permission denied or process gone)
    };

    for entry in entries.filter_map(|e| e.ok()) {
        // Early exit check
        if remaining.load(Ordering::Relaxed) == 0 {
            return;
        }

        // Read the symlink target
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };

        // Check if it's a socket: "socket:[12345]"
        let Some(link_str) = link.to_str() else {
            continue;
        };

        if let Some(inode) = parse_socket_inode(link_str) {
            if needed_inodes.contains(&inode) {
                let mut map = result.lock().unwrap();
                if let std::collections::hash_map::Entry::Vacant(e) = map.entry(inode) {
                    e.insert(pid);
                    remaining.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Parse inode from socket link like "socket:[12345]"
fn parse_socket_inode(link: &str) -> Option<u64> {
    let link = link.strip_prefix("socket:[")?;
    let link = link.strip_suffix(']')?;
    link.parse().ok()
}

/// Get process name from /proc/[pid]/comm.
fn get_process_name(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// =============================================================================
// Main
// =============================================================================

fn print_usage() {
    eprintln!("Usage: autofwd-agent [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --interval <MS>    Polling interval in milliseconds (default: 500)");
    eprintln!("  --version          Print version and exit");
    eprintln!("  --help             Print this help message");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut interval_ms: u64 = 500;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                println!("autofwd-agent {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            "--interval" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --interval requires a value");
                    std::process::exit(1);
                }
                interval_ms = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("Error: invalid interval value");
                    std::process::exit(1);
                });
            }
            arg => {
                eprintln!("Error: unknown argument: {}", arg);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let interval = Duration::from_millis(interval_ms);
    let heartbeat_threshold = (5000 / interval_ms).max(1) as u32;

    let mut monitor = PortMonitor::new();
    let mut heartbeat_counter: u32 = 0;

    loop {
        match monitor.poll() {
            Some(snapshot) => {
                // State changed - emit snapshot
                println!("{}", serde_json::to_string(&snapshot).unwrap_or_default());
                println!("{}", END_MARKER);
                heartbeat_counter = 0;
            }
            None => {
                // No change - maybe send heartbeat
                heartbeat_counter += 1;
                if heartbeat_counter >= heartbeat_threshold {
                    println!("{}", HEARTBEAT_MARKER);
                    heartbeat_counter = 0;
                }
            }
        }

        thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_port() {
        assert_eq!(parse_hex_port("00000000:1F90"), Some(8080));
        assert_eq!(parse_hex_port("00000000:0050"), Some(80));
        assert_eq!(parse_hex_port("0100007F:1538"), Some(5432)); // 127.0.0.1:5432
        assert_eq!(
            parse_hex_port("00000000000000000000000000000000:1F90"),
            Some(8080)
        ); // IPv6
    }

    #[test]
    fn test_parse_socket_inode() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("socket:[0]"), Some(0));
        assert_eq!(parse_socket_inode("pipe:[999]"), None);
        assert_eq!(parse_socket_inode("/dev/null"), None);
    }

    #[test]
    fn test_parse_proc_net_tcp() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 67890 1 0000000000000000 100 0 0 10 0
   2: 0100007F:8000 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0"#;

        let mut sockets = Vec::new();
        parse_proc_net_tcp(content, false, &mut sockets);

        // Should only get LISTEN sockets (state 0A)
        assert_eq!(sockets.len(), 2);

        assert_eq!(sockets[0].port, 8080);
        assert_eq!(sockets[0].inode, 12345);
        assert!(!sockets[0].is_v6);

        assert_eq!(sockets[1].port, 5432);
        assert_eq!(sockets[1].inode, 67890);
        assert!(!sockets[1].is_v6);
    }

    #[test]
    fn test_parse_proc_net_tcp6() {
        let content = r#"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 100 0 0 10 0"#;

        let mut sockets = Vec::new();
        parse_proc_net_tcp(content, true, &mut sockets);

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 22);
        assert_eq!(sockets[0].inode, 54321);
        assert!(sockets[0].is_v6);
    }

    #[test]
    fn test_snapshot_key() {
        let snapshot = Snapshot {
            ports: vec![
                PortInfo {
                    port: 8080,
                    process: Some("node".to_string()),
                    ipv4: true,
                    ipv6: false,
                },
                PortInfo {
                    port: 3000,
                    process: None,
                    ipv4: true,
                    ipv6: true,
                },
            ],
        };

        let key = snapshot_key(&snapshot);
        assert!(key.contains("8080"));
        assert!(key.contains("node"));
        assert!(key.contains("3000"));
    }
}
