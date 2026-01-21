use serde::Deserialize;
use std::collections::HashMap;

/// Host preference indicating which address families a port is listening on.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostPref {
    pub ipv4: bool,
    pub ipv6: bool,
}

/// Information about a listening port, including host preferences and process name.
#[derive(Clone, Debug, Default)]
pub struct PortInfo {
    pub host_pref: HostPref,
    pub process_name: Option<String>,
}

/// Represents a parsed entry from netstat -tlnp output.
#[allow(dead_code)]
#[derive(Debug)]
pub struct NetstatEntry {
    pub local_port: u16,
    pub is_ipv6: bool,
    pub process_name: Option<String>,
}

/// Parse the local address from netstat format.
/// Examples: "0.0.0.0:9999", "127.0.0.1:5432", ":::22", "::1:22"
#[allow(dead_code)]
fn parse_local_address(addr: &str) -> Option<u16> {
    // IPv6 format: ":::port" or "[::1]:port" or "::1:port"
    // IPv4 format: "host:port"
    // The port is always the last colon-separated component
    let port_str = addr.rsplit(':').next()?;
    port_str.parse().ok()
}

/// Parse a single line from netstat -tlnp output.
/// Format: Proto Recv-Q Send-Q Local Address  Foreign Address  State  PID/Program
/// Example: tcp   0      0      0.0.0.0:9999   0.0.0.0:*        LISTEN 13/nc
#[allow(dead_code)]
pub fn parse_netstat_line(line: &str) -> Option<NetstatEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    // Need at least: Proto, Recv-Q, Send-Q, Local Address, Foreign Address, State
    if parts.len() < 6 {
        return None;
    }

    let proto = parts[0];

    // Only care about tcp and tcp6
    let is_ipv6 = match proto {
        "tcp" => false,
        "tcp6" => true,
        _ => return None,
    };

    // State must be LISTEN
    if parts[5] != "LISTEN" {
        return None;
    }

    // Parse local address (column 3, 0-indexed)
    let local_addr = parts[3];
    let local_port = parse_local_address(local_addr)?;

    // Parse PID/Program name (column 6 if present)
    let process_name = if parts.len() > 6 {
        let pid_prog = parts[6];
        // Format is "PID/program" or "-" if not owned by current user
        if pid_prog == "-" {
            None
        } else if let Some((_pid, prog)) = pid_prog.split_once('/') {
            Some(prog.to_string())
        } else {
            None
        }
    } else {
        None
    };

    Some(NetstatEntry {
        local_port,
        is_ipv6,
        process_name,
    })
}

/// Parse the output of `netstat -tlnp`.
/// Returns a map of port -> PortInfo for all listening ports.
#[allow(dead_code)]
pub fn parse_netstat_output(output: &str) -> HashMap<u16, PortInfo> {
    let mut result: HashMap<u16, PortInfo> = HashMap::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(entry) = parse_netstat_line(line) {
            let info = result.entry(entry.local_port).or_default();
            if entry.is_ipv6 {
                info.host_pref.ipv6 = true;
            } else {
                info.host_pref.ipv4 = true;
            }
            // Keep the first non-empty process name we find
            if info.process_name.is_none() && entry.process_name.is_some() {
                info.process_name = entry.process_name;
            }
        }
    }

    result
}

/// Determine the best remote host to use for forwarding.
/// Prefers IPv4 (127.0.0.1) unless only IPv6 is available.
pub fn remote_host_for(pref: &HostPref) -> &'static str {
    if !pref.ipv4 && pref.ipv6 {
        "[::1]"
    } else {
        "127.0.0.1"
    }
}

// ============================================================================
// Agent JSON output parsing
// ============================================================================

/// Port info from agent JSON output.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentPortInfo {
    pub port: u16,
    pub process: Option<String>,
    pub ipv4: bool,
    pub ipv6: bool,
}

/// Snapshot from agent JSON output.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentSnapshot {
    pub ports: Vec<AgentPortInfo>,
}

/// Parse JSON output from the autofwd-agent.
/// Format: {"ports":[{"port":8080,"process":"node","ipv4":true,"ipv6":false}]}
pub fn parse_agent_output(output: &str) -> HashMap<u16, PortInfo> {
    let mut result = HashMap::new();

    // Try to parse as JSON
    if let Ok(snapshot) = serde_json::from_str::<AgentSnapshot>(output) {
        for port_info in snapshot.ports {
            result.insert(
                port_info.port,
                PortInfo {
                    host_pref: HostPref {
                        ipv4: port_info.ipv4,
                        ipv6: port_info.ipv6,
                    },
                    process_name: port_info.process,
                },
            );
        }
    }

    result
}

// ============================================================================
// /proc/net/tcp fallback parsing (no process names)
// ============================================================================

/// Parse a hex IPv4 address from /proc/net/tcp format.
/// Format: AABBCCDD where bytes are in reverse order (little-endian).
#[allow(dead_code)]
fn parse_ipv4_hex(hex: &str) -> bool {
    // We just need to know if it's valid, not the actual address
    hex.len() == 8 && u32::from_str_radix(hex, 16).is_ok()
}

/// Parse a line from /proc/net/tcp or /proc/net/tcp6.
/// Format: sl local_address rem_address st ...
/// Example: 0: 0100007F:1F90 00000000:0000 0A ...
/// Returns (port, is_ipv6) if it's a listening socket.
fn parse_proc_tcp_line(line: &str) -> Option<(u16, bool)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    // Skip header
    if parts[0] == "sl" {
        return None;
    }

    // State must be 0A (LISTEN)
    if parts[3] != "0A" {
        return None;
    }

    // Parse local address (format: ADDR:PORT in hex)
    let local = parts[1];
    let (addr_hex, port_hex) = local.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // Determine if IPv6 by address length (32 hex chars = IPv6)
    let is_ipv6 = addr_hex.len() == 32;

    Some((port, is_ipv6))
}

/// Parse raw /proc/net/tcp output (fallback when agent unavailable).
/// This doesn't include process names.
pub fn parse_proc_net_output(output: &str) -> HashMap<u16, PortInfo> {
    let mut result: HashMap<u16, PortInfo> = HashMap::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some((port, is_ipv6)) = parse_proc_tcp_line(line) {
            let info = result.entry(port).or_default();
            if is_ipv6 {
                info.host_pref.ipv6 = true;
            } else {
                info.host_pref.ipv4 = true;
            }
            // No process name available in /proc/net/tcp
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_local_address() {
        assert_eq!(parse_local_address("0.0.0.0:9999"), Some(9999));
        assert_eq!(parse_local_address("127.0.0.1:5432"), Some(5432));
        assert_eq!(parse_local_address(":::22"), Some(22));
        assert_eq!(parse_local_address("::1:8080"), Some(8080));
    }

    #[test]
    fn test_parse_netstat_line() {
        // Basic IPv4 line
        let line =
            "tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      13/nc";
        let entry = parse_netstat_line(line).unwrap();
        assert_eq!(entry.local_port, 9999);
        assert!(!entry.is_ipv6);
        assert_eq!(entry.process_name, Some("nc".to_string()));

        // IPv4 localhost
        let line = "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      45/postgres";
        let entry = parse_netstat_line(line).unwrap();
        assert_eq!(entry.local_port, 5432);
        assert!(!entry.is_ipv6);
        assert_eq!(entry.process_name, Some("postgres".to_string()));

        // IPv6 line
        let line = "tcp6       0      0 :::22                   :::*                    LISTEN      1/sshd";
        let entry = parse_netstat_line(line).unwrap();
        assert_eq!(entry.local_port, 22);
        assert!(entry.is_ipv6);
        assert_eq!(entry.process_name, Some("sshd".to_string()));

        // Line without process (not owned by user)
        let line =
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -";
        let entry = parse_netstat_line(line).unwrap();
        assert_eq!(entry.local_port, 80);
        assert_eq!(entry.process_name, None);
    }

    #[test]
    fn test_parse_netstat_output() {
        let output = r#"Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      13/nc
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      45/postgres
tcp6       0      0 :::22                   :::*                    LISTEN      1/sshd"#;

        let result = parse_netstat_output(output);

        assert!(result.contains_key(&9999));
        assert!(result.contains_key(&5432));
        assert!(result.contains_key(&22));

        let nc = result.get(&9999).unwrap();
        assert!(nc.host_pref.ipv4);
        assert!(!nc.host_pref.ipv6);
        assert_eq!(nc.process_name, Some("nc".to_string()));

        let postgres = result.get(&5432).unwrap();
        assert!(postgres.host_pref.ipv4);
        assert_eq!(postgres.process_name, Some("postgres".to_string()));

        let sshd = result.get(&22).unwrap();
        assert!(sshd.host_pref.ipv6);
        assert_eq!(sshd.process_name, Some("sshd".to_string()));
    }

    #[test]
    fn test_parse_netstat_output_dual_stack() {
        // Port listening on both IPv4 and IPv6
        let output = r#"tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      100/nginx
tcp6       0      0 :::8080                 :::*                    LISTEN      100/nginx"#;

        let result = parse_netstat_output(output);

        let nginx = result.get(&8080).unwrap();
        assert!(nginx.host_pref.ipv4);
        assert!(nginx.host_pref.ipv6);
        assert_eq!(nginx.process_name, Some("nginx".to_string()));
    }

    #[test]
    fn test_remote_host_for() {
        // IPv4 only -> 127.0.0.1
        let pref = HostPref {
            ipv4: true,
            ipv6: false,
        };
        assert_eq!(remote_host_for(&pref), "127.0.0.1");

        // IPv6 only -> [::1]
        let pref = HostPref {
            ipv4: false,
            ipv6: true,
        };
        assert_eq!(remote_host_for(&pref), "[::1]");

        // Both -> prefer IPv4
        let pref = HostPref {
            ipv4: true,
            ipv6: true,
        };
        assert_eq!(remote_host_for(&pref), "127.0.0.1");

        // Neither (default) -> 127.0.0.1
        let pref = HostPref {
            ipv4: false,
            ipv6: false,
        };
        assert_eq!(remote_host_for(&pref), "127.0.0.1");
    }

    #[test]
    fn test_parse_agent_output() {
        let json = r#"{"ports":[{"port":8080,"process":"node","ipv4":true,"ipv6":false},{"port":3000,"process":"npm","ipv4":true,"ipv6":true}]}"#;
        let result = parse_agent_output(json);

        assert_eq!(result.len(), 2);

        let node = result.get(&8080).unwrap();
        assert!(node.host_pref.ipv4);
        assert!(!node.host_pref.ipv6);
        assert_eq!(node.process_name, Some("node".to_string()));

        let npm = result.get(&3000).unwrap();
        assert!(npm.host_pref.ipv4);
        assert!(npm.host_pref.ipv6);
        assert_eq!(npm.process_name, Some("npm".to_string()));
    }

    #[test]
    fn test_parse_agent_output_no_process() {
        let json = r#"{"ports":[{"port":80,"ipv4":true,"ipv6":false}]}"#;
        let result = parse_agent_output(json);

        let http = result.get(&80).unwrap();
        assert!(http.host_pref.ipv4);
        assert_eq!(http.process_name, None);
    }

    #[test]
    fn test_parse_proc_net_output() {
        // Sample /proc/net/tcp output
        let output = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1"#;

        let result = parse_proc_net_output(output);

        // 0x1F90 = 8080, 0x01BB = 443
        assert!(result.contains_key(&8080));
        assert!(result.contains_key(&443));

        let port_8080 = result.get(&8080).unwrap();
        assert!(port_8080.host_pref.ipv4);
        assert!(!port_8080.host_pref.ipv6);
        assert_eq!(port_8080.process_name, None); // No process info from /proc/net/tcp
    }
}
