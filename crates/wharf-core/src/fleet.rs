// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Fleet Configuration Module
//!
//! Manages the fleet of Yachts (runtime servers) controlled by the Wharf.
//! Loads configuration from JSON or Nickel files.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

use crate::db_policy::DatabasePolicy;

#[derive(Error, Debug)]
pub enum FleetError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Yacht not found: {0}")]
    YachtNotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Database configuration for a yacht
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database variant (mysql, mariadb, postgres, redis)
    pub variant: String,
    /// Database version
    pub version: String,
    /// Shadow port (where the real DB listens)
    pub shadow_port: u16,
    /// Public port (what the app connects to)
    pub public_port: u16,
    /// Database name
    pub database: String,
    /// Database user
    pub user: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            variant: "mariadb".to_string(),
            version: "10.11".to_string(),
            shadow_port: 33060,
            public_port: 3306,
            database: "wordpress".to_string(),
            user: "wordpress".to_string(),
        }
    }
}

/// CMS adapter type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Adapter {
    WordPress,
    Drupal,
    Moodle,
    Joomla,
    Custom,
}

impl Default for Adapter {
    fn default() -> Self {
        Self::WordPress
    }
}

/// Security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Allow writes to the database from the yacht
    pub allow_writes: bool,
    /// Enforce strict security headers
    pub strict_headers: bool,
    /// Enable eBPF firewall
    pub enable_firewall: bool,
    /// Database sharding policy
    pub database: DatabasePolicy,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allow_writes: false,
            strict_headers: true,
            enable_firewall: true,
            database: DatabasePolicy::default(),
        }
    }
}

/// A single Yacht (runtime server) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Yacht {
    /// Yacht identifier
    pub name: String,
    /// IP address or hostname
    pub ip: String,
    /// Domain name served by this yacht
    pub domain: String,
    /// SSH port for management
    pub ssh_port: u16,
    /// SSH user for deployments
    pub ssh_user: String,
    /// CMS adapter type
    pub adapter: Adapter,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Security policy
    pub policy: PolicyConfig,
    /// Path to web root on the yacht
    pub web_root: String,
    /// Tags for grouping/filtering
    pub tags: Vec<String>,
    /// Whether this yacht is enabled
    pub enabled: bool,
}

impl Default for Yacht {
    fn default() -> Self {
        Self {
            name: String::new(),
            ip: String::new(),
            domain: String::new(),
            ssh_port: 22,
            ssh_user: "wharf".to_string(),
            adapter: Adapter::default(),
            database: DatabaseConfig::default(),
            policy: PolicyConfig::default(),
            web_root: "/var/www/html".to_string(),
            tags: Vec::new(),
            enabled: true,
        }
    }
}

impl Yacht {
    /// Create a new yacht with minimal configuration
    pub fn new(name: &str, ip: &str, domain: &str) -> Self {
        Self {
            name: name.to_string(),
            ip: ip.to_string(),
            domain: domain.to_string(),
            ..Default::default()
        }
    }

    /// Get the SSH destination string (user@host)
    pub fn ssh_destination(&self) -> String {
        format!("{}@{}", self.ssh_user, self.ip)
    }

    /// Get the rsync destination for web root
    pub fn rsync_destination(&self) -> String {
        format!("{}@{}:{}", self.ssh_user, self.ip, self.web_root)
    }
}

/// The complete fleet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fleet {
    /// Version of the fleet config format
    pub version: u32,
    /// Fleet name/identifier
    pub name: String,
    /// All yachts in the fleet
    pub yachts: HashMap<String, Yacht>,
    /// Default policy for new yachts
    pub default_policy: PolicyConfig,
    /// Global excludes for file sync
    pub sync_excludes: Vec<String>,
}

impl Default for Fleet {
    fn default() -> Self {
        Self {
            version: 1,
            name: "default".to_string(),
            yachts: HashMap::new(),
            default_policy: PolicyConfig::default(),
            sync_excludes: vec![
                ".git".to_string(),
                "node_modules".to_string(),
                ".env".to_string(),
                "*.log".to_string(),
                ".DS_Store".to_string(),
                "Thumbs.db".to_string(),
            ],
        }
    }
}

impl Fleet {
    /// Load fleet configuration from a JSON file
    pub fn load_json(path: &Path) -> Result<Self, FleetError> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content).map_err(|e| FleetError::ParseError(e.to_string()))
    }

    /// Load fleet configuration from a TOML file
    pub fn load_toml(path: &Path) -> Result<Self, FleetError> {
        let content = fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| FleetError::ParseError(e.to_string()))
    }

    /// Load fleet configuration from a Nickel file (via nickel export)
    pub fn load_nickel(path: &Path) -> Result<Self, FleetError> {
        use std::process::Command;

        // Use nickel CLI to export to JSON
        let output = Command::new("nickel")
            .args(["export", path.to_str().unwrap_or("")])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FleetError::ParseError(format!(
                "Nickel export failed: {}",
                stderr
            )));
        }

        let json = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(&json).map_err(|e| FleetError::ParseError(e.to_string()))
    }

    /// Load fleet configuration (auto-detect format by extension)
    /// Supports: .toml, .json, .ncl (Nickel)
    pub fn load(path: &Path) -> Result<Self, FleetError> {
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match extension {
            "toml" => Self::load_toml(path),
            "json" => Self::load_json(path),
            "ncl" => Self::load_nickel(path),
            _ => {
                // Try TOML first (most common), then JSON, then Nickel
                Self::load_toml(path)
                    .or_else(|_| Self::load_json(path))
                    .or_else(|_| Self::load_nickel(path))
            }
        }
    }

    /// Save fleet configuration to a JSON file
    pub fn save(&self, path: &Path) -> Result<(), FleetError> {
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("json");

        match extension {
            "toml" => self.save_toml(path),
            _ => self.save_json(path),
        }
    }

    /// Save fleet configuration to a JSON file
    pub fn save_json(&self, path: &Path) -> Result<(), FleetError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| FleetError::ParseError(e.to_string()))?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Save fleet configuration to a TOML file
    pub fn save_toml(&self, path: &Path) -> Result<(), FleetError> {
        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| FleetError::ParseError(e.to_string()))?;
        fs::write(path, toml_str)?;
        Ok(())
    }

    /// Get a yacht by name
    pub fn get_yacht(&self, name: &str) -> Option<&Yacht> {
        self.yachts.get(name)
    }

    /// Get a yacht by name (mutable)
    pub fn get_yacht_mut(&mut self, name: &str) -> Option<&mut Yacht> {
        self.yachts.get_mut(name)
    }

    /// Add a yacht to the fleet
    pub fn add_yacht(&mut self, yacht: Yacht) {
        self.yachts.insert(yacht.name.clone(), yacht);
    }

    /// Remove a yacht from the fleet
    pub fn remove_yacht(&mut self, name: &str) -> Option<Yacht> {
        self.yachts.remove(name)
    }

    /// List all yacht names
    pub fn list_yachts(&self) -> Vec<&str> {
        self.yachts.keys().map(|s| s.as_str()).collect()
    }

    /// List enabled yachts
    pub fn list_enabled(&self) -> Vec<&Yacht> {
        self.yachts.values().filter(|y| y.enabled).collect()
    }

    /// Filter yachts by tag
    pub fn filter_by_tag(&self, tag: &str) -> Vec<&Yacht> {
        self.yachts
            .values()
            .filter(|y| y.tags.contains(&tag.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_yacht_creation() {
        let yacht = Yacht::new("primary", "192.168.1.10", "example.com");
        assert_eq!(yacht.name, "primary");
        assert_eq!(yacht.ip, "192.168.1.10");
        assert_eq!(yacht.domain, "example.com");
        assert_eq!(yacht.ssh_port, 22);
    }

    #[test]
    fn test_yacht_destinations() {
        let yacht = Yacht::new("test", "10.0.0.5", "test.com");
        assert_eq!(yacht.ssh_destination(), "wharf@10.0.0.5");
        assert_eq!(yacht.rsync_destination(), "wharf@10.0.0.5:/var/www/html");
    }

    #[test]
    fn test_fleet_operations() {
        let mut fleet = Fleet::default();

        let yacht1 = Yacht::new("primary", "10.0.0.1", "primary.com");
        let yacht2 = Yacht::new("staging", "10.0.0.2", "staging.com");

        fleet.add_yacht(yacht1);
        fleet.add_yacht(yacht2);

        assert_eq!(fleet.list_yachts().len(), 2);
        assert!(fleet.get_yacht("primary").is_some());
        assert!(fleet.get_yacht("nonexistent").is_none());

        fleet.remove_yacht("staging");
        assert_eq!(fleet.list_yachts().len(), 1);
    }

    #[test]
    fn test_fleet_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fleet.json");

        let mut fleet = Fleet::default();
        fleet.add_yacht(Yacht::new("test", "10.0.0.1", "test.com"));

        fleet.save(&path).unwrap();

        let loaded = Fleet::load_json(&path).unwrap();
        assert_eq!(loaded.yachts.len(), 1);
        assert!(loaded.get_yacht("test").is_some());
    }
}
