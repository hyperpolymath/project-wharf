// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Configuration Module
//!
//! Unified configuration loading for Project Wharf components.
//! Supports both TOML (simple) and Nickel (complex) configuration formats.
//!
//! ## Configuration Hierarchy
//!
//! Configuration is loaded with the following precedence (highest first):
//! 1. Command-line arguments
//! 2. Environment variables
//! 3. Project-local config (`.wharf/config.toml` or `.wharf/config.ncl`)
//! 4. User config (`~/.config/wharf/`)
//! 5. System config (`/etc/wharf/`)
//! 6. Hardcoded defaults

use crate::crypto::SignatureScheme;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    NotFound(PathBuf),

    #[error("Failed to read configuration file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse TOML: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("Invalid configuration: {0}")]
    ValidationError(String),

    #[error("Unsupported configuration format: {0}")]
    UnsupportedFormat(String),
}

/// Result type for configuration operations
pub type ConfigResult<T> = Result<T, ConfigError>;

// =============================================================================
// YACHT-AGENT CONFIGURATION
// =============================================================================

/// Configuration for the yacht-agent daemon
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct YachtAgentConfig {
    /// Logging configuration
    pub logging: LoggingConfig,

    /// Database proxy configuration
    pub db_proxy: DbProxyConfig,

    /// API server configuration
    pub api: ApiConfig,

    /// Firewall configuration
    pub firewall: FirewallConfig,

    /// Root directory of the site being protected (for integrity verification)
    pub site_root: Option<String>,

    /// Directory for storing persistent keypairs (default: /etc/wharf/keys/)
    pub key_store_dir: Option<String>,

    /// Signature scheme: "ml-dsa-87-only" (default, production-safe) or "hybrid" (requires ed448 audit)
    pub signature_scheme: SignatureScheme,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Verbosity level (0=info, 1=debug, 2+=trace)
    pub verbosity: u8,

    /// Log format: "human" or "json"
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            verbosity: 0,
            format: "human".to_string(),
        }
    }
}

/// Database proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DbProxyConfig {
    /// Database protocol: mysql, mariadb, postgres, redis
    pub protocol: String,

    /// Port to listen on (masquerade port)
    pub listen_port: u16,

    /// Real database host
    pub shadow_host: String,

    /// Real database port
    pub shadow_port: u16,
}

impl Default for DbProxyConfig {
    fn default() -> Self {
        Self {
            protocol: "mysql".to_string(),
            listen_port: 3306,
            shadow_host: "127.0.0.1".to_string(),
            shadow_port: 33060,
        }
    }
}

/// API server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    /// API server port
    pub port: u16,

    /// Enable Prometheus metrics endpoint
    pub metrics_enabled: bool,

    /// Metrics endpoint path
    pub metrics_path: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            port: 9001,
            metrics_enabled: true,
            metrics_path: "/metrics".to_string(),
        }
    }
}

/// Firewall configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallConfig {
    /// Firewall mode: ebpf, nftables, none
    pub mode: String,

    /// Network interface for XDP attachment
    pub xdp_interface: String,

    /// Allowed TCP ports
    pub tcp_ports: Vec<u16>,

    /// Allowed UDP ports
    pub udp_ports: Vec<u16>,

    /// Path to eBPF object file
    pub ebpf_object_path: Option<String>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            mode: "nftables".to_string(),
            xdp_interface: "eth0".to_string(),
            tcp_ports: vec![80, 443, 9001],
            udp_ports: vec![4242],
            ebpf_object_path: None,
        }
    }
}

// =============================================================================
// WHARF-CLI CONFIGURATION
// =============================================================================

/// Configuration for the wharf CLI tool
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WharfCliConfig {
    /// Logging configuration
    pub logging: LoggingConfig,

    /// Default paths
    pub paths: PathsConfig,

    /// Build settings
    pub build: BuildConfig,

    /// Mooring (deployment) settings
    pub mooring: MooringConfig,

    /// State management settings
    pub state: StateConfig,

    /// Directory for storing persistent keypairs (default: ~/.wharf/keys/)
    pub key_store_dir: Option<String>,

    /// Signature scheme: "ml-dsa-87-only" (default, production-safe) or "hybrid" (requires ed448 audit)
    pub signature_scheme: SignatureScheme,
}

/// Path configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PathsConfig {
    /// Configuration directory
    pub config_dir: PathBuf,

    /// Build output directory
    pub output_dir: PathBuf,

    /// Site source directory
    pub site_source: PathBuf,

    /// Fleet configuration file
    pub fleet_config: PathBuf,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            config_dir: PathBuf::from("."),
            output_dir: PathBuf::from("dist"),
            site_source: PathBuf::from("./site"),
            fleet_config: PathBuf::from("fleet.toml"),
        }
    }
}

/// Build configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BuildConfig {
    /// Target yacht to build (None = all)
    pub target: Option<String>,

    /// Build container images
    pub containers: bool,

    /// Build eBPF program
    pub ebpf: bool,

    /// Output directory
    pub output: PathBuf,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            target: None,
            containers: false,
            ebpf: false,
            output: PathBuf::from("dist"),
        }
    }
}

/// Mooring (deployment) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MooringConfig {
    /// Force sync even if checksums match
    pub force: bool,

    /// Emergency mode (skip verification)
    pub emergency: bool,

    /// Dry run mode
    pub dry_run: bool,

    /// Default layers to sync
    pub layers: Vec<String>,

    /// Fleet-wide default SSH identity file
    pub ssh_identity: Option<String>,
}

impl Default for MooringConfig {
    fn default() -> Self {
        Self {
            force: false,
            emergency: false,
            dry_run: false,
            layers: vec!["config".to_string(), "files".to_string()],
            ssh_identity: None,
        }
    }
}

/// State management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StateConfig {
    /// Number of snapshots to keep
    pub snapshots_to_keep: usize,

    /// Snapshot directory
    pub snapshot_dir: PathBuf,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            snapshots_to_keep: 10,
            snapshot_dir: PathBuf::from(".wharf/snapshots"),
        }
    }
}

// =============================================================================
// CONFIG LOADING
// =============================================================================

/// Load configuration from standard locations
pub struct ConfigLoader {
    /// Search paths for configuration files
    search_paths: Vec<PathBuf>,
}

impl ConfigLoader {
    /// Create a new config loader with default search paths
    pub fn new() -> Self {
        let mut search_paths = Vec::new();

        // Project-local config
        search_paths.push(PathBuf::from(".wharf"));
        search_paths.push(PathBuf::from("."));

        // User config
        if let Some(config_dir) = dirs::config_dir() {
            search_paths.push(config_dir.join("wharf"));
        }

        // System config
        search_paths.push(PathBuf::from("/etc/wharf"));
        search_paths.push(PathBuf::from("/opt/wharf"));

        Self { search_paths }
    }

    /// Create a config loader with custom search paths
    pub fn with_paths(paths: Vec<PathBuf>) -> Self {
        Self {
            search_paths: paths,
        }
    }

    /// Find a configuration file by name
    pub fn find_config(&self, filename: &str) -> Option<PathBuf> {
        for base in &self.search_paths {
            let path = base.join(filename);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }

    /// Load yacht-agent configuration
    pub fn load_yacht_agent_config(&self) -> ConfigResult<YachtAgentConfig> {
        // Try to find config file
        let config_file = self
            .find_config("yacht-agent.toml")
            .or_else(|| self.find_config("agent.toml"));

        match config_file {
            Some(path) => load_toml_config(&path),
            None => Ok(YachtAgentConfig::default()),
        }
    }

    /// Load wharf-cli configuration
    pub fn load_wharf_cli_config(&self) -> ConfigResult<WharfCliConfig> {
        // Try to find config file
        let config_file = self
            .find_config("wharf-cli.toml")
            .or_else(|| self.find_config("cli.toml"))
            .or_else(|| self.find_config("config.toml"));

        match config_file {
            Some(path) => load_toml_config(&path),
            None => Ok(WharfCliConfig::default()),
        }
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Load a TOML configuration file
pub fn load_toml_config<T: for<'de> Deserialize<'de>>(path: &Path) -> ConfigResult<T> {
    let content = std::fs::read_to_string(path)?;
    let config: T = toml::from_str(&content)?;
    Ok(config)
}

/// Save a configuration to a TOML file
pub fn save_toml_config<T: Serialize>(config: &T, path: &Path) -> ConfigResult<()> {
    let content = toml::to_string_pretty(config)
        .map_err(|e| ConfigError::ValidationError(e.to_string()))?;
    std::fs::write(path, content)?;
    Ok(())
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Get the default configuration directory for the current platform
pub fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .map(|p| p.join("wharf"))
        .unwrap_or_else(|| PathBuf::from("/etc/wharf"))
}

/// Get the system configuration directory
pub fn system_config_dir() -> PathBuf {
    PathBuf::from("/etc/wharf")
}

/// Ensure a configuration directory exists
pub fn ensure_config_dir(path: &Path) -> ConfigResult<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_yacht_agent_config() {
        let config = YachtAgentConfig::default();
        assert_eq!(config.db_proxy.protocol, "mysql");
        assert_eq!(config.db_proxy.listen_port, 3306);
        assert_eq!(config.firewall.mode, "nftables");
    }

    #[test]
    fn test_default_wharf_cli_config() {
        let config = WharfCliConfig::default();
        assert_eq!(config.state.snapshots_to_keep, 10);
        assert!(!config.build.containers);
    }

    #[test]
    fn test_config_serialization() {
        let config = YachtAgentConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("[db_proxy]"));
        assert!(toml_str.contains("protocol"));
    }
}
