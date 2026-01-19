use anyhow::{Context, Result};

/// Ports that are never forwarded by default (system/infrastructure services).
/// These can be overridden with an explicit --allow.
const DEFAULT_DENY: &[u16] = &[
    // System services
    22,   // SSH
    53,   // DNS
    67,   // DHCP server
    68,   // DHCP client
    123,  // NTP
    137,  // NetBIOS
    138,  // NetBIOS
    139,  // NetBIOS
    445,  // SMB
    631,  // CUPS (printing)
    5353, // mDNS
    // Databases
    1433,  // MSSQL
    1521,  // Oracle
    3306,  // MySQL/MariaDB
    5432,  // PostgreSQL
    27017, // MongoDB
    // Caches / message queues
    6379,  // Redis
    11211, // Memcached
    5672,  // RabbitMQ
    // Container / orchestration
    2375,  // Docker
    2376,  // Docker TLS
    2379,  // etcd
    2380,  // etcd
    10250, // Kubelet
];

/// A range of ports (inclusive).
#[derive(Clone, Debug)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// Filter for determining which ports should be forwarded.
#[derive(Clone, Debug)]
pub struct PortFilter {
    /// If Some, only these ports are allowed (explicit allowlist).
    /// If None, all ports except the default denylist are allowed.
    allow: Option<Vec<PortRange>>,
}

impl PortFilter {
    /// Create a new port filter from an allowlist string.
    /// Format: "3000,5173,8000-9000"
    ///
    /// If no allowlist is provided, the default denylist is applied.
    /// If an allowlist IS provided, it overrides the denylist entirely.
    pub fn new(allow: Option<&str>) -> Result<Self> {
        let allow = match allow {
            None => None,
            Some(s) => Some(parse_allowlist(s)?),
        };
        Ok(Self { allow })
    }

    /// Check if a port is allowed by this filter.
    pub fn allows(&self, port: u16) -> bool {
        match &self.allow {
            // Explicit allowlist: only allow ports in the list
            Some(ranges) => ranges.iter().any(|r| r.contains(port)),
            // No allowlist: allow everything except default deny
            None => !DEFAULT_DENY.contains(&port),
        }
    }
}

/// Parse an allowlist string into a list of port ranges.
fn parse_allowlist(s: &str) -> Result<Vec<PortRange>> {
    let mut result = Vec::new();

    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a
                .trim()
                .parse()
                .with_context(|| format!("bad port in range: {part}"))?;
            let end: u16 = b
                .trim()
                .parse()
                .with_context(|| format!("bad port in range: {part}"))?;

            // Normalize so start <= end
            let (start, end) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };

            result.push(PortRange { start, end });
        } else {
            let port: u16 = part.parse().with_context(|| format!("bad port: {part}"))?;
            result.push(PortRange {
                start: port,
                end: port,
            });
        }
    }

    Ok(result)
}

/// Find a free local port starting from the given port.
/// Tries up to `tries` consecutive ports.
pub fn find_free_local_port(start: u16, tries: u16) -> Option<u16> {
    let start_u32 = start as u32;

    for offset in 0..tries as u32 {
        let port_u32 = start_u32 + offset;
        if port_u32 > u16::MAX as u32 {
            break;
        }

        let port = port_u32 as u16;
        if port == 0 {
            continue;
        }

        // Try to bind to check if the port is free
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Some(port);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_allowlist_single() {
        let ranges = parse_allowlist("3000").unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 3000);
        assert_eq!(ranges[0].end, 3000);
    }

    #[test]
    fn test_parse_allowlist_range() {
        let ranges = parse_allowlist("8000-9000").unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 8000);
        assert_eq!(ranges[0].end, 9000);
    }

    #[test]
    fn test_parse_allowlist_mixed() {
        let ranges = parse_allowlist("3000, 5173, 8000-9000").unwrap();
        assert_eq!(ranges.len(), 3);
        assert!(ranges[0].contains(3000));
        assert!(ranges[1].contains(5173));
        assert!(ranges[2].contains(8500));
    }

    #[test]
    fn test_filter_allows() {
        let filter = PortFilter::new(Some("3000,8000-9000")).unwrap();
        assert!(filter.allows(3000));
        assert!(filter.allows(8000));
        assert!(filter.allows(8500));
        assert!(filter.allows(9000));
        assert!(!filter.allows(3001));
        assert!(!filter.allows(7999));
    }

    #[test]
    fn test_filter_default_denylist() {
        let filter = PortFilter::new(None).unwrap();
        // Regular ports are allowed
        assert!(filter.allows(3000));
        assert!(filter.allows(8080));
        assert!(filter.allows(65535));
        // System ports are denied
        assert!(!filter.allows(22)); // SSH
        assert!(!filter.allows(53)); // DNS
        assert!(!filter.allows(5353)); // mDNS
    }

    #[test]
    fn test_explicit_allow_overrides_deny() {
        // Explicit allowlist can include normally-denied ports
        let filter = PortFilter::new(Some("22,3000")).unwrap();
        assert!(filter.allows(22)); // Explicitly allowed
        assert!(filter.allows(3000)); // Explicitly allowed
        assert!(!filter.allows(8080)); // Not in allowlist
    }
}
