//! Port forwarding using russh direct-tcpip channels.
//!
//! For each forwarded port, we:
//! 1. Listen on a local TCP port
//! 2. On accept, open an SSH channel with channel_open_direct_tcpip
//! 3. Bidirectionally proxy data between the local socket and SSH channel

use anyhow::{anyhow, Result};
use russh::client::Handle;
use russh::ChannelMsg;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::client::ClientHandler;

/// Shared handle wrapped for concurrent access
pub type SharedHandle = Arc<Mutex<Handle<ClientHandler>>>;

/// Manages all active port forwards.
pub struct ForwardManager {
    /// SSH client handle (shared)
    handle: SharedHandle,
    /// Active forwards: local_port -> (listener task handle, shutdown sender)
    forwards: HashMap<u16, (JoinHandle<()>, mpsc::Sender<()>)>,
    /// Remote host to forward to (usually "127.0.0.1")
    remote_host: String,
}

impl ForwardManager {
    pub fn new(handle: SharedHandle) -> Self {
        Self {
            handle,
            forwards: HashMap::new(),
            remote_host: "127.0.0.1".to_string(),
        }
    }

    /// Add a new port forward.
    ///
    /// Returns the actual local port used (may differ if collision_tries > 0).
    pub async fn add_forward(
        &mut self,
        remote_port: u16,
        preferred_local_port: u16,
        collision_tries: u16,
    ) -> Result<u16> {
        // Try to bind to local port
        let (listener, local_port) =
            bind_with_fallback(preferred_local_port, collision_tries).await?;

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        // Clone handle for the listener task
        let handle = self.handle.clone();
        let remote_host = self.remote_host.clone();

        // Spawn listener task
        let task = tokio::spawn(async move {
            run_listener(listener, handle, remote_host, remote_port, shutdown_rx).await;
        });

        self.forwards.insert(local_port, (task, shutdown_tx));
        Ok(local_port)
    }

    /// Remove a port forward.
    pub async fn remove_forward(&mut self, local_port: u16) -> Result<()> {
        if let Some((task, shutdown_tx)) = self.forwards.remove(&local_port) {
            // Signal shutdown
            let _ = shutdown_tx.send(()).await;
            // Wait for task to finish (with timeout)
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
        }
        Ok(())
    }

    /// Check if a forward exists.
    #[allow(dead_code)]
    pub fn has_forward(&self, local_port: u16) -> bool {
        self.forwards.contains_key(&local_port)
    }

    /// Get all active local ports.
    #[allow(dead_code)]
    pub fn active_ports(&self) -> Vec<u16> {
        self.forwards.keys().copied().collect()
    }

    /// Shutdown all forwards.
    pub async fn shutdown_all(&mut self) {
        let ports: Vec<u16> = self.forwards.keys().copied().collect();
        for port in ports {
            let _ = self.remove_forward(port).await;
        }
    }
}

/// Try to bind to a port, with fallback to next ports if taken.
async fn bind_with_fallback(preferred: u16, tries: u16) -> Result<(TcpListener, u16)> {
    for offset in 0..=tries {
        let port = preferred.saturating_add(offset);
        if port == 0 {
            continue;
        }

        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        match TcpListener::bind(addr).await {
            Ok(listener) => return Ok((listener, port)),
            Err(_) if offset < tries => continue,
            Err(e) => return Err(anyhow!("Failed to bind to port {}: {}", preferred, e)),
        }
    }

    Err(anyhow!(
        "Failed to bind to port {} (tried {} alternatives)",
        preferred,
        tries
    ))
}

/// Run the listener for a single forwarded port.
async fn run_listener(
    listener: TcpListener,
    handle: SharedHandle,
    remote_host: String,
    remote_port: u16,
    mut shutdown: mpsc::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let handle = handle.clone();
                        let remote_host = remote_host.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(
                                stream,
                                handle,
                                &remote_host,
                                remote_port,
                                peer_addr,
                            ).await {
                                tracing::debug!(
                                    "Connection from {} to {}:{} failed: {}",
                                    peer_addr, remote_host, remote_port, e
                                );
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!("Accept failed: {}", e);
                    }
                }
            }
        }
    }
}

/// Handle a single forwarded connection.
async fn handle_connection(
    mut local_stream: TcpStream,
    handle: SharedHandle,
    remote_host: &str,
    remote_port: u16,
    peer_addr: SocketAddr,
) -> Result<()> {
    // Open SSH channel for direct-tcpip
    let channel = {
        let handle = handle.lock().await;
        handle
            .channel_open_direct_tcpip(
                remote_host,
                remote_port as u32,
                &peer_addr.ip().to_string(),
                peer_addr.port() as u32,
            )
            .await
            .map_err(|e| anyhow!("Failed to open direct-tcpip channel: {}", e))?
    };

    // Split local stream
    let (mut local_read, mut local_write) = local_stream.split();

    // Run bidirectional proxy
    proxy_bidirectional(&mut local_read, &mut local_write, channel).await
}

/// Bidirectional proxy between local TCP and SSH channel.
async fn proxy_bidirectional(
    local_read: &mut (impl AsyncReadExt + Unpin),
    local_write: &mut (impl AsyncWriteExt + Unpin),
    mut channel: russh::Channel<russh::client::Msg>,
) -> Result<()> {
    let mut buf = vec![0u8; 32 * 1024]; // 32KB buffer

    loop {
        tokio::select! {
            // Local -> Remote
            read_result = local_read.read(&mut buf) => {
                match read_result {
                    Ok(0) => {
                        // Local closed, send EOF to remote
                        let _ = channel.eof().await;
                        break;
                    }
                    Ok(n) => {
                        channel.data(&buf[..n]).await
                            .map_err(|e| anyhow!("Failed to send data to remote: {}", e))?;
                    }
                    Err(e) => {
                        return Err(anyhow!("Local read error: {}", e));
                    }
                }
            }

            // Remote -> Local
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        local_write.write_all(&data).await
                            .map_err(|e| anyhow!("Local write error: {}", e))?;
                    }
                    Some(ChannelMsg::Eof) | None => {
                        // Remote closed
                        break;
                    }
                    Some(ChannelMsg::Close) => {
                        break;
                    }
                    _ => {
                        // Ignore other messages
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind_with_fallback() {
        // This test just verifies the binding logic works
        let (listener, port) = bind_with_fallback(0, 0).await.unwrap();
        assert!(port > 0);
        drop(listener);
    }
}
