use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Detected protocol for a forwarded port.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)] // Https not yet detected but planned
pub enum Protocol {
    #[default]
    Unknown,
    Http,
    Http2,
    Http3,
    Https,
    Redis,
    PostgreSql,
    MySql,
    Ssh,
}

impl Protocol {
    /// Return the protocol as a string (for JSON events).
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Unknown => "unknown",
            Protocol::Http => "http",
            Protocol::Http2 => "http2",
            Protocol::Http3 => "http3",
            Protocol::Https => "https",
            Protocol::Redis => "redis",
            Protocol::PostgreSql => "postgresql",
            Protocol::MySql => "mysql",
            Protocol::Ssh => "ssh",
        }
    }

    /// Format the address with appropriate scheme for display.
    /// HTTP, HTTP/2, and HTTP/3 all display as http:// in TUI.
    pub fn format_address(&self, port: u16) -> String {
        match self {
            Protocol::Http | Protocol::Http2 | Protocol::Http3 => {
                format!("http://localhost:{}", port)
            }
            Protocol::Https => format!("https://localhost:{}", port),
            Protocol::Redis => format!("redis://localhost:{}", port),
            Protocol::PostgreSql => format!("postgres://localhost:{}", port),
            Protocol::MySql => format!("mysql://localhost:{}", port),
            Protocol::Ssh => format!("ssh://localhost:{}", port),
            Protocol::Unknown => format!("localhost:{}", port),
        }
    }
}

/// Probe a port and detect the protocol.
/// Returns within 2s timeout.
pub async fn detect_protocol(port: u16) -> Protocol {
    tokio::time::timeout(Duration::from_millis(2000), detect_inner(port))
        .await
        .unwrap_or(Protocol::Unknown)
}

async fn detect_inner(port: u16) -> Protocol {
    let addr = format!("127.0.0.1:{}", port);

    // Try to connect with longer timeout for SSH tunnels
    let stream = match tokio::time::timeout(
        Duration::from_millis(500),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return Protocol::Unknown,
    };

    // Try passive detection first (protocols that send data immediately)
    if let Some(protocol) = try_passive_detection(stream).await {
        return protocol;
    }

    // Try active probes (need new connections for each to avoid protocol confusion)
    
    // Try Redis
    if let Ok(Ok(stream)) = tokio::time::timeout(
        Duration::from_millis(500),
        TcpStream::connect(&addr),
    ).await {
        if try_redis(stream).await {
            return Protocol::Redis;
        }
    }

    // Try PostgreSQL (sends SSL request, expects 'N' or 'S' response)
    if let Ok(Ok(stream)) = tokio::time::timeout(
        Duration::from_millis(500),
        TcpStream::connect(&addr),
    ).await {
        if try_postgresql(stream).await {
            return Protocol::PostgreSql;
        }
    }

    // Try HTTP (this is the most common case for dev servers)
    if let Ok(Ok(stream)) = tokio::time::timeout(
        Duration::from_millis(500),
        TcpStream::connect(&addr),
    ).await {
        if let Some(protocol) = try_http(stream).await {
            return protocol;
        }
    }

    Protocol::Unknown
}

/// Try to detect protocol from data the server sends immediately.
/// Works for SSH, MySQL/MariaDB, and PostgreSQL.
async fn try_passive_detection(mut stream: TcpStream) -> Option<Protocol> {
    let mut buf = [0u8; 256];

    // Wait up to 500ms for server to send initial data (through SSH tunnel)
    let n = match tokio::time::timeout(
        Duration::from_millis(500),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };

    let data = &buf[..n];

    // SSH: Banner starts with "SSH-"
    if data.starts_with(b"SSH-") {
        return Some(Protocol::Ssh);
    }

    // MySQL/MariaDB: Initial handshake packet
    // Format: 3 bytes length + 1 byte sequence (0) + protocol version (0x0a for v10)
    if n >= 5 && data[3] == 0x00 && data[4] == 0x0a {
        return Some(Protocol::MySql);
    }

    // PostgreSQL: Server sends various messages
    // 'N' = SSL not supported, 'S' = SSL supported, 'E' = Error
    // Or authentication request starting with 'R'
    if n >= 1 && matches!(data[0], b'N' | b'S' | b'E' | b'R') {
        // Check for more PostgreSQL-specific patterns
        // Error message format: 'E' followed by length (4 bytes, big-endian)
        if data[0] == b'E' && n >= 5 {
            return Some(Protocol::PostgreSql);
        }
        // Auth request: 'R' followed by length
        if data[0] == b'R' && n >= 5 {
            return Some(Protocol::PostgreSql);
        }
        // SSL response is just 'N' or 'S'
        if n == 1 && matches!(data[0], b'N' | b'S') {
            return Some(Protocol::PostgreSql);
        }
    }

    None
}

/// Try Redis PING/PONG detection.
async fn try_redis(mut stream: TcpStream) -> bool {
    // Send PING command
    if stream.write_all(b"PING\r\n").await.is_err() {
        return false;
    }

    let mut buf = [0u8; 32];
    let n = match tokio::time::timeout(
        Duration::from_millis(500),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return false,
    };

    // Redis responds with "+PONG\r\n"
    buf[..n].starts_with(b"+PONG")
}

/// Try PostgreSQL detection by sending SSL request.
/// PostgreSQL responds with 'N' (no SSL) or 'S' (SSL supported).
async fn try_postgresql(mut stream: TcpStream) -> bool {
    // PostgreSQL SSL request packet:
    // 4 bytes: length (8)
    // 4 bytes: SSL request code (80877103 = 0x04d2162f)
    let ssl_request: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    
    if stream.write_all(&ssl_request).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 1];
    let n = match tokio::time::timeout(
        Duration::from_millis(500),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return false,
    };

    // PostgreSQL responds with 'N' (no SSL) or 'S' (SSL supported)
    n == 1 && (buf[0] == b'N' || buf[0] == b'S')
}

/// Try HTTP detection. Returns Http, Http2, or Http3 if detected.
async fn try_http(mut stream: TcpStream) -> Option<Protocol> {
    // Send a simple HTTP/1.1 HEAD request
    let request = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).await.is_err() {
        return None;
    }

    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(
        Duration::from_millis(500),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };

    let response = String::from_utf8_lossy(&buf[..n]);

    // Check if it's a valid HTTP response
    if !response.starts_with("HTTP/") {
        return None;
    }

    // Check for HTTP/2 indication
    if response.contains("HTTP/2") {
        return Some(Protocol::Http2);
    }

    // Check for HTTP/3 via Alt-Svc header
    let response_lower = response.to_lowercase();
    if response_lower.contains("alt-svc:") && response_lower.contains("h3") {
        return Some(Protocol::Http3);
    }

    Some(Protocol::Http)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Http.as_str(), "http");
        assert_eq!(Protocol::Http2.as_str(), "http2");
        assert_eq!(Protocol::Http3.as_str(), "http3");
        assert_eq!(Protocol::Redis.as_str(), "redis");
        assert_eq!(Protocol::PostgreSql.as_str(), "postgresql");
        assert_eq!(Protocol::MySql.as_str(), "mysql");
        assert_eq!(Protocol::Ssh.as_str(), "ssh");
        assert_eq!(Protocol::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_protocol_format_address() {
        assert_eq!(Protocol::Http.format_address(3000), "http://localhost:3000");
        assert_eq!(Protocol::Http2.format_address(3000), "http://localhost:3000");
        assert_eq!(Protocol::Http3.format_address(3000), "http://localhost:3000");
        assert_eq!(Protocol::Https.format_address(443), "https://localhost:443");
        assert_eq!(Protocol::Redis.format_address(6379), "redis://localhost:6379");
        assert_eq!(Protocol::PostgreSql.format_address(5432), "postgres://localhost:5432");
        assert_eq!(Protocol::MySql.format_address(3306), "mysql://localhost:3306");
        assert_eq!(Protocol::Ssh.format_address(22), "ssh://localhost:22");
        assert_eq!(Protocol::Unknown.format_address(8080), "localhost:8080");
    }
}
