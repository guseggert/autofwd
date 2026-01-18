//! SSH client using russh library.
//!
//! Handles connection, authentication (agent -> keys -> password), and known hosts.

use anyhow::{anyhow, bail, Result};
use russh::keys::agent::client::AgentClient;
use russh::keys::PrivateKeyWithHashAlg;
use russh::{client, ChannelId, ChannelMsg, Disconnect};

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;

/// Callback for requesting a password from the user (via TUI).
pub type PasswordCallback = Box<dyn Fn() -> Option<String> + Send + Sync>;

/// Client handler for russh callbacks.
pub struct ClientHandler;

impl ClientHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClientHandler {
    fn default() -> Self {
        Self::new()
    }
}

// Implement From for Channel messages (required by russh 0.56)
impl From<(ChannelId, ChannelMsg)> for ClientHandler {
    fn from(_: (ChannelId, ChannelMsg)) -> Self {
        Self
    }
}

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        // Accept all server keys for now
        // TODO: Implement proper known_hosts checking
        async { Ok(true) }
    }
}

/// Resolved SSH connection parameters from ~/.ssh/config
#[derive(Debug, Default)]
struct SshHostConfig {
    hostname: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    identity_file: Option<PathBuf>,
    proxy_command: Option<String>,
}

/// Parse ~/.ssh/config and resolve settings for a given host alias.
fn parse_ssh_config(host_alias: &str) -> SshHostConfig {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return SshHostConfig::default(),
    };

    let config_path = home.join(".ssh").join("config");
    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return SshHostConfig::default(),
    };

    let mut result = SshHostConfig::default();
    let mut in_matching_host = false;

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse "Key Value" or "Key=Value"
        let (key, value) = if let Some(eq_pos) = line.find('=') {
            (line[..eq_pos].trim(), line[eq_pos + 1..].trim())
        } else if let Some(space_pos) = line.find(char::is_whitespace) {
            (line[..space_pos].trim(), line[space_pos..].trim())
        } else {
            continue;
        };

        let key_lower = key.to_lowercase();

        if key_lower == "host" {
            // Check if this Host line matches our alias
            // Handle multiple patterns: "Host foo bar baz"
            in_matching_host = value.split_whitespace().any(|pattern| {
                if pattern == "*" {
                    true
                } else if pattern.contains('*') || pattern.contains('?') {
                    // Simple glob matching
                    glob_match(pattern, host_alias)
                } else {
                    pattern == host_alias
                }
            });
        } else if in_matching_host {
            match key_lower.as_str() {
                "hostname" => {
                    if result.hostname.is_none() {
                        result.hostname = Some(value.to_string());
                    }
                }
                "port" => {
                    if result.port.is_none() {
                        result.port = value.parse().ok();
                    }
                }
                "user" => {
                    if result.user.is_none() {
                        result.user = Some(value.to_string());
                    }
                }
                "identityfile" => {
                    if result.identity_file.is_none() {
                        // Expand ~ to home directory
                        let expanded = if value.starts_with("~/") {
                            home.join(&value[2..])
                        } else {
                            PathBuf::from(value)
                        };
                        result.identity_file = Some(expanded);
                    }
                }
                "proxycommand" => {
                    if result.proxy_command.is_none() {
                        result.proxy_command = Some(value.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    result
}

/// Simple glob pattern matching (supports * and ?)
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut p_chars = pattern.chars().peekable();
    let mut t_chars = text.chars().peekable();

    while let Some(p) = p_chars.next() {
        match p {
            '*' => {
                // * matches zero or more characters
                if p_chars.peek().is_none() {
                    return true; // trailing * matches everything
                }
                // Try matching rest of pattern at each position
                let rest_pattern: String = p_chars.collect();
                while t_chars.peek().is_some() {
                    let rest_text: String = t_chars.clone().collect();
                    if glob_match(&rest_pattern, &rest_text) {
                        return true;
                    }
                    t_chars.next();
                }
                return glob_match(&rest_pattern, "");
            }
            '?' => {
                // ? matches exactly one character
                if t_chars.next().is_none() {
                    return false;
                }
            }
            c => {
                if t_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }

    t_chars.peek().is_none()
}

/// SSH connection wrapper.
pub struct SshClient {
    handle: client::Handle<ClientHandler>,
    _host: String,
    _port: u16,
}

impl SshClient {
    /// Connect to an SSH server using ~/.ssh/config for host resolution.
    pub async fn connect(target: &str, password_cb: Option<PasswordCallback>) -> Result<Self> {
        // Parse target into user@host:port format
        let (cmd_user, host, cmd_port) = parse_target(target)?;

        // Parse SSH config to resolve the host alias
        let ssh_config = parse_ssh_config(&host);

        // Resolve effective connection parameters
        // Priority: command line > ssh_config > defaults
        let effective_host = ssh_config.hostname.as_deref().unwrap_or(&host);
        let effective_port = cmd_port.or(ssh_config.port).unwrap_or(22);
        let effective_user = cmd_user
            .or(ssh_config.user)
            .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "root".to_string()));

        // Collect identity files to try
        let mut identity_files = Vec::new();
        if let Some(ref id_file) = ssh_config.identity_file {
            identity_files.push(id_file.clone());
        }
        identity_files.extend(default_identity_files());

        // Create handler
        let handler = ClientHandler::new();

        // SSH client config
        let client_config = client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(30)),
            keepalive_interval: Some(std::time::Duration::from_secs(5)),
            keepalive_max: 3,
            ..Default::default()
        };

        // Connect via ProxyCommand or direct TCP
        let stream = if let Some(ref proxy_cmd) = ssh_config.proxy_command {
            // Expand tokens in proxy command
            let expanded = proxy_cmd
                .replace("%h", effective_host)
                .replace("%p", &effective_port.to_string())
                .replace("%r", &effective_user)
                .replace("%%", "%");

            return Err(anyhow!(
                "ProxyCommand not yet supported: {}",
                expanded
            ));
        } else {
            // Direct TCP connection
            let addr = format!("{}:{}", effective_host, effective_port);
            TcpStream::connect(&addr)
                .await
                .map_err(|e| anyhow!("Failed to connect to {}: {}", addr, e))?
        };

        let mut handle =
            client::connect_stream(Arc::new(client_config), stream, handler).await?;

        // Authenticate
        authenticate(&mut handle, &effective_user, &identity_files, password_cb).await?;

        Ok(Self {
            handle,
            _host: effective_host.to_string(),
            _port: effective_port,
        })
    }

    /// Get a reference to the underlying handle for channel operations.
    #[allow(dead_code)]
    pub fn handle(&self) -> &client::Handle<ClientHandler> {
        &self.handle
    }

    /// Consume self and return the handle.
    pub fn into_handle(self) -> client::Handle<ClientHandler> {
        self.handle
    }

    /// Check if the connection is still alive.
    #[allow(dead_code)]
    pub fn is_connected(&self) -> bool {
        !self.handle.is_closed()
    }

    /// Disconnect gracefully.
    #[allow(dead_code)]
    pub async fn disconnect(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
    }
}

/// Parse target string into (optional_user, host, optional_port).
fn parse_target(target: &str) -> Result<(Option<String>, String, Option<u16>)> {
    let (user, rest) = if let Some(at_pos) = target.find('@') {
        (Some(target[..at_pos].to_string()), &target[at_pos + 1..])
    } else {
        (None, target)
    };

    let (host, port) = if let Some(colon_pos) = rest.rfind(':') {
        // Check if it's an IPv6 address
        if rest.starts_with('[') {
            if let Some(bracket_pos) = rest.find(']') {
                if colon_pos > bracket_pos {
                    // Port after IPv6 address
                    let port: u16 = rest[colon_pos + 1..]
                        .parse()
                        .map_err(|_| anyhow!("Invalid port number"))?;
                    (rest[1..bracket_pos].to_string(), Some(port))
                } else {
                    (rest[1..bracket_pos].to_string(), None)
                }
            } else {
                bail!("Invalid IPv6 address format");
            }
        } else {
            // Regular host:port
            let port: u16 = rest[colon_pos + 1..]
                .parse()
                .map_err(|_| anyhow!("Invalid port number"))?;
            (rest[..colon_pos].to_string(), Some(port))
        }
    } else {
        (rest.to_string(), None)
    };

    Ok((user, host, port))
}

/// Authenticate with the SSH server.
/// Tries: 1) SSH agent, 2) Identity files, 3) Password
async fn authenticate(
    handle: &mut client::Handle<ClientHandler>,
    user: &str,
    identity_files: &[PathBuf],
    password_cb: Option<PasswordCallback>,
) -> Result<()> {
    let mut auth_errors = Vec::new();

    // First, try SSH agent
    match try_agent_auth(handle, user).await {
        Ok(true) => return Ok(()),
        Ok(false) => auth_errors.push("agent: no accepted keys".to_string()),
        Err(e) => auth_errors.push(format!("agent: {}", e)),
    }

    // Try identity files
    for key_path in identity_files {
        if !key_path.exists() {
            continue;
        }

        match try_key_auth(handle, user, key_path).await {
            Ok(true) => return Ok(()),
            Ok(false) => auth_errors.push(format!("{}: key rejected", key_path.display())),
            Err(e) => auth_errors.push(format!("{}: {}", key_path.display(), e)),
        }
    }

    // Try password if callback provided
    if let Some(cb) = password_cb {
        if let Some(password) = cb() {
            let result = handle.authenticate_password(user, &password).await?;
            if result.success() {
                return Ok(());
            }
            auth_errors.push("password: rejected".to_string());
        }
    }

    bail!(
        "Authentication failed for user '{}'. Tried:\n  - {}",
        user,
        auth_errors.join("\n  - ")
    )
}

/// Try to authenticate using SSH agent.
async fn try_agent_auth(handle: &mut client::Handle<ClientHandler>, user: &str) -> Result<bool> {
    let agent_path =
        std::env::var("SSH_AUTH_SOCK").map_err(|_| anyhow!("SSH_AUTH_SOCK not set"))?;

    let stream = tokio::net::UnixStream::connect(&agent_path).await
        .map_err(|e| anyhow!("cannot connect to agent: {}", e))?;
    let mut agent = AgentClient::connect(stream);

    let identities = agent.request_identities().await
        .map_err(|e| anyhow!("cannot list agent keys: {}", e))?;

    if identities.is_empty() {
        return Err(anyhow!("no keys in agent"));
    }

    for identity in identities {
        let result = handle
            .authenticate_publickey_with(user, identity.clone(), None, &mut agent)
            .await;
        match result {
            Ok(r) if r.success() => return Ok(true),
            _ => continue,
        }
    }

    Ok(false)
}

/// Try to authenticate using a key file.
async fn try_key_auth(
    handle: &mut client::Handle<ClientHandler>,
    user: &str,
    key_path: &PathBuf,
) -> Result<bool> {
    // Try to load the key without a passphrase
    let key = match russh::keys::load_secret_key(key_path, None) {
        Ok(k) => k,
        Err(e) => {
            // Check if it's an encryption error (key needs passphrase)
            let err_str = e.to_string().to_lowercase();
            if err_str.contains("encrypted") || err_str.contains("passphrase") || err_str.contains("decrypt") {
                return Err(anyhow!(
                    "key is encrypted - add it to ssh-agent with: ssh-add {}",
                    key_path.display()
                ));
            }
            return Err(anyhow!("failed to load key: {}", e));
        }
    };
    let key = Arc::new(key);

    // Try with different hash algorithms
    // Some servers are picky about which signature algorithm is used
    let hash_algs = [
        None, // Default
        Some(russh::keys::HashAlg::Sha512),
        Some(russh::keys::HashAlg::Sha256),
    ];

    for hash_alg in hash_algs {
        let key_with_hash = PrivateKeyWithHashAlg::new(key.clone(), hash_alg);

        match handle.authenticate_publickey(user, key_with_hash).await {
            Ok(r) if r.success() => return Ok(true),
            Ok(_) => continue, // Try next algorithm
            Err(e) => return Err(anyhow!("Key auth error: {}", e)),
        }
    }

    Ok(false)
}

/// Get default identity file paths.
fn default_identity_files() -> Vec<PathBuf> {
    let home = dirs::home_dir().unwrap_or_default();
    let ssh_dir = home.join(".ssh");

    vec![
        ssh_dir.join("id_ed25519"),
        ssh_dir.join("id_ecdsa"),
        ssh_dir.join("id_rsa"),
        ssh_dir.join("id_dsa"),
    ]
}
