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

/// Represents a parsed entry from /proc/net/tcp or /proc/net/tcp6.
#[derive(Debug)]
pub struct TcpEntry {
    #[allow(dead_code)] // Useful for debugging/future features
    pub local_addr: String,
    pub local_port: u16,
    pub state: TcpState,
    pub is_ipv6: bool,
    pub uid: u32,
    pub process_name: Option<String>,
}

/// TCP connection states from /proc/net/tcp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown(u8),
}

impl From<u8> for TcpState {
    fn from(val: u8) -> Self {
        match val {
            0x01 => TcpState::Established,
            0x02 => TcpState::SynSent,
            0x03 => TcpState::SynRecv,
            0x04 => TcpState::FinWait1,
            0x05 => TcpState::FinWait2,
            0x06 => TcpState::TimeWait,
            0x07 => TcpState::Close,
            0x08 => TcpState::CloseWait,
            0x09 => TcpState::LastAck,
            0x0A => TcpState::Listen,
            0x0B => TcpState::Closing,
            other => TcpState::Unknown(other),
        }
    }
}

/// Parse a hex IPv4 address from /proc/net/tcp format.
/// Format: AABBCCDD where bytes are in reverse order (little-endian).
fn parse_ipv4_addr(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let bytes = u32::from_str_radix(hex, 16).ok()?;
    // /proc/net/tcp stores IPv4 in host byte order (little-endian on x86)
    let a = (bytes & 0xFF) as u8;
    let b = ((bytes >> 8) & 0xFF) as u8;
    let c = ((bytes >> 16) & 0xFF) as u8;
    let d = ((bytes >> 24) & 0xFF) as u8;
    Some(format!("{a}.{b}.{c}.{d}"))
}

/// Parse a hex IPv6 address from /proc/net/tcp6 format.
/// Format: 32 hex chars, stored as 4 little-endian 32-bit words.
fn parse_ipv6_addr(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    // IPv6 in /proc is stored as 4 little-endian 32-bit words
    let mut words = [0u32; 4];
    for (i, word) in words.iter_mut().enumerate() {
        let start = i * 8;
        let chunk = &hex[start..start + 8];
        *word = u32::from_str_radix(chunk, 16).ok()?;
    }

    // Convert to standard IPv6 format
    let mut segments = [0u16; 8];
    for (i, word) in words.iter().enumerate() {
        // Each 32-bit word gives us 2 16-bit segments, byte-swapped
        segments[i * 2] = (word & 0xFFFF) as u16;
        segments[i * 2] = segments[i * 2].swap_bytes();
        segments[i * 2 + 1] = ((word >> 16) & 0xFFFF) as u16;
        segments[i * 2 + 1] = segments[i * 2 + 1].swap_bytes();
    }

    // Format as IPv6, simplifying if it's a common address
    let formatted: Vec<String> = segments.iter().map(|s| format!("{s:x}")).collect();
    Some(formatted.join(":"))
}

/// Parse a single line from /proc/net/tcp or /proc/net/tcp6.
/// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
///         0  1             2           3  4        5        6  7        8        9   10      11
/// With process name suffix: <tcp_line>|<process_name>
pub fn parse_proc_tcp_line(line: &str, is_ipv6: bool) -> Option<TcpEntry> {
    // Check for process name suffix (format: <tcp_line>|<process_name>)
    let (tcp_part, process_name) = if let Some(idx) = line.rfind('|') {
        let proc = line[idx + 1..].trim();
        let proc_name = if proc.is_empty() {
            None
        } else {
            Some(proc.to_string())
        };
        (&line[..idx], proc_name)
    } else {
        (line, None)
    };

    let parts: Vec<&str> = tcp_part.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    // Skip header line
    if parts[0] == "sl" {
        return None;
    }

    // local_address is in format ADDR:PORT (hex)
    let local = parts[1];
    let (addr_hex, port_hex) = local.rsplit_once(':')?;

    let local_addr = if is_ipv6 {
        parse_ipv6_addr(addr_hex)?
    } else {
        parse_ipv4_addr(addr_hex)?
    };

    let local_port = u16::from_str_radix(port_hex, 16).ok()?;
    let state_val = u8::from_str_radix(parts[3], 16).ok()?;

    // UID is at index 7 (after tx_queue rx_queue tr tm->when retrnsmt)
    // But the format varies - tx_queue:rx_queue is one field, tr tm->when is two
    // Actually: sl(0) local(1) rem(2) st(3) tx:rx(4) tr:tm(5) retrnsmt(6) uid(7)
    let uid: u32 = parts[7].parse().ok()?;

    Some(TcpEntry {
        local_addr,
        local_port,
        state: TcpState::from(state_val),
        is_ipv6,
        uid,
        process_name,
    })
}

/// Parse the combined output of /proc/net/tcp and /proc/net/tcp6.
/// Returns a map of port -> PortInfo for all listening ports.
/// If `filter_uid` is Some, only include ports owned by that UID.
pub fn parse_proc_net_output(output: &str, filter_uid: Option<u32>) -> HashMap<u16, PortInfo> {
    let mut result: HashMap<u16, PortInfo> = HashMap::new();

    // Track whether we're in the tcp6 section
    let mut in_ipv6_section = false;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Detect section switch - tcp6 entries have 32-char addresses
        // Header line indicates new section
        if line.starts_with("sl") || line.starts_with("  sl") {
            // Check next data line to determine if ipv6
            continue;
        }

        // Try to detect IPv6 by address length in the line
        // Need to handle potential |process_name suffix
        let tcp_part = line.split('|').next().unwrap_or(line);
        let parts: Vec<&str> = tcp_part.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Some((addr, _)) = parts[1].rsplit_once(':') {
                in_ipv6_section = addr.len() == 32;
            }
        }

        if let Some(entry) = parse_proc_tcp_line(line, in_ipv6_section) {
            // Only care about listening sockets
            if entry.state != TcpState::Listen {
                continue;
            }

            // Filter by UID if specified
            if let Some(uid) = filter_uid {
                if entry.uid != uid {
                    continue;
                }
            }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_addr() {
        // 0.0.0.0 = 00000000
        assert_eq!(parse_ipv4_addr("00000000"), Some("0.0.0.0".to_string()));
        // 127.0.0.1 = 0100007F (little-endian)
        assert_eq!(parse_ipv4_addr("0100007F"), Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_parse_tcp_line() {
        let line = "   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        let entry = parse_proc_tcp_line(line, false).unwrap();
        assert_eq!(entry.local_addr, "127.0.0.1");
        assert_eq!(entry.local_port, 0x0CEA); // 3306
        assert_eq!(entry.state, TcpState::Listen);
        assert_eq!(entry.process_name, None);
    }

    #[test]
    fn test_parse_tcp_line_with_process() {
        // Line with process name suffix
        let line = "   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1|mysqld";
        let entry = parse_proc_tcp_line(line, false).unwrap();
        assert_eq!(entry.local_addr, "127.0.0.1");
        assert_eq!(entry.local_port, 0x0CEA); // 3306
        assert_eq!(entry.process_name, Some("mysqld".to_string()));

        // Line with empty process name
        let line = "   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1|";
        let entry = parse_proc_tcp_line(line, false).unwrap();
        assert_eq!(entry.process_name, None);
    }

    #[test]
    fn test_parse_output() {
        let output = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1"#;

        let result = parse_proc_net_output(output, None);
        assert!(result.contains_key(&3306)); // 0x0CEA
        assert!(result.contains_key(&443)); // 0x01BB
    }

    #[test]
    fn test_parse_output_with_process_names() {
        let output = r#"   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1|mysqld
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1|nginx
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1|"#;

        let result = parse_proc_net_output(output, None);

        // Check port 3306 (0x0CEA) has mysqld
        let info_3306 = result.get(&3306).unwrap();
        assert_eq!(info_3306.process_name, Some("mysqld".to_string()));

        // Check port 443 (0x01BB) has nginx
        let info_443 = result.get(&443).unwrap();
        assert_eq!(info_443.process_name, Some("nginx".to_string()));

        // Check port 8080 (0x1F90) has no process name
        let info_8080 = result.get(&8080).unwrap();
        assert_eq!(info_8080.process_name, None);
    }

    #[test]
    fn test_parse_output_uid_filter() {
        let output = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1"#;

        // No filter - get both
        let result = parse_proc_net_output(output, None);
        assert!(result.contains_key(&3306));
        assert!(result.contains_key(&443));

        // Filter to UID 1000 - only get 443
        let result = parse_proc_net_output(output, Some(1000));
        assert!(!result.contains_key(&3306)); // owned by root (0)
        assert!(result.contains_key(&443)); // owned by UID 1000

        // Filter to UID 0 - only get 3306
        let result = parse_proc_net_output(output, Some(0));
        assert!(result.contains_key(&3306)); // owned by root (0)
        assert!(!result.contains_key(&443)); // owned by UID 1000
    }
}
