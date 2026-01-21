use chrono::{DateTime, Utc};
use serde::Serialize;

/// JSON event emitted in headless mode.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A new port forward was established
    ForwardAdded {
        ts: DateTime<Utc>,
        remote_port: u16,
        local_port: u16,
        remote_host: String,
        protocol: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        process_name: Option<String>,
    },
    /// Protocol was detected for a forwarded port
    ProtocolDetected {
        ts: DateTime<Utc>,
        local_port: u16,
        protocol: String,
    },
    /// A port forward was removed (service stopped)
    ForwardRemoved { ts: DateTime<Utc>, remote_port: u16 },
    /// A port forward was disabled by user
    ForwardDisabled { ts: DateTime<Utc>, remote_port: u16 },
    /// A port forward was re-enabled by user
    ForwardEnabled {
        ts: DateTime<Utc>,
        remote_port: u16,
        local_port: u16,
    },
    /// SSH connection was lost
    ConnectionLost { ts: DateTime<Utc> },
    /// Attempting to reconnect
    Reconnecting { ts: DateTime<Utc>, delay_ms: u64 },
    /// Successfully reconnected
    Reconnected { ts: DateTime<Utc> },
    /// Service restarted on same port
    ServiceRestarted { ts: DateTime<Utc>, remote_port: u16 },
    /// Error occurred
    Error { ts: DateTime<Utc>, message: String },
    /// Ready and watching for ports
    Ready { ts: DateTime<Utc>, target: String },
    /// Shutting down
    Shutdown { ts: DateTime<Utc> },
    /// Agent is being deployed to remote
    #[allow(dead_code)]
    AgentDeploying { ts: DateTime<Utc>, arch: String },
    /// Agent was successfully deployed
    AgentDeployed {
        ts: DateTime<Utc>,
        arch: String,
        duration_ms: u64,
    },
    /// Falling back to shell script (agent unavailable)
    AgentFallback { ts: DateTime<Utc>, reason: String },
    /// Debug timing checkpoint
    Timing {
        ts: DateTime<Utc>,
        phase: String,
        duration_ms: u64,
    },
}

impl Event {
    pub fn forward_added(
        remote_port: u16,
        local_port: u16,
        remote_host: &str,
        protocol: &str,
        process_name: Option<String>,
    ) -> Self {
        Event::ForwardAdded {
            ts: Utc::now(),
            remote_port,
            local_port,
            remote_host: remote_host.to_string(),
            protocol: protocol.to_string(),
            process_name,
        }
    }

    pub fn protocol_detected(local_port: u16, protocol: &str) -> Self {
        Event::ProtocolDetected {
            ts: Utc::now(),
            local_port,
            protocol: protocol.to_string(),
        }
    }

    pub fn forward_removed(remote_port: u16) -> Self {
        Event::ForwardRemoved {
            ts: Utc::now(),
            remote_port,
        }
    }

    pub fn forward_disabled(remote_port: u16) -> Self {
        Event::ForwardDisabled {
            ts: Utc::now(),
            remote_port,
        }
    }

    pub fn forward_enabled(remote_port: u16, local_port: u16) -> Self {
        Event::ForwardEnabled {
            ts: Utc::now(),
            remote_port,
            local_port,
        }
    }

    pub fn connection_lost() -> Self {
        Event::ConnectionLost { ts: Utc::now() }
    }

    pub fn reconnecting(delay_ms: u64) -> Self {
        Event::Reconnecting {
            ts: Utc::now(),
            delay_ms,
        }
    }

    pub fn reconnected() -> Self {
        Event::Reconnected { ts: Utc::now() }
    }

    pub fn service_restarted(remote_port: u16) -> Self {
        Event::ServiceRestarted {
            ts: Utc::now(),
            remote_port,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Event::Error {
            ts: Utc::now(),
            message: message.into(),
        }
    }

    pub fn ready(target: &str) -> Self {
        Event::Ready {
            ts: Utc::now(),
            target: target.to_string(),
        }
    }

    pub fn shutdown() -> Self {
        Event::Shutdown { ts: Utc::now() }
    }

    #[allow(dead_code)]
    pub fn agent_deploying(arch: &str) -> Self {
        Event::AgentDeploying {
            ts: Utc::now(),
            arch: arch.to_string(),
        }
    }

    pub fn agent_deployed(arch: &str, duration_ms: u64) -> Self {
        Event::AgentDeployed {
            ts: Utc::now(),
            arch: arch.to_string(),
            duration_ms,
        }
    }

    pub fn agent_fallback(reason: &str) -> Self {
        Event::AgentFallback {
            ts: Utc::now(),
            reason: reason.to_string(),
        }
    }

    pub fn timing(phase: &str, duration_ms: u64) -> Self {
        Event::Timing {
            ts: Utc::now(),
            phase: phase.to_string(),
            duration_ms,
        }
    }

    /// Serialize to JSON and print to stdout
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{}", json);
        }
    }
}
