// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # File Synchronization Module
//!
//! Handles syncing files between the Wharf (controller) and Yacht (runtime).
//! Uses rsync over SSH for efficient delta transfers.

use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SyncError {
    #[error("SSH connection failed: {0}")]
    SshError(String),

    #[error("Rsync failed: {0}")]
    RsyncError(String),

    #[error("Source path does not exist: {0}")]
    SourceNotFound(PathBuf),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Configuration for a sync operation
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Local source directory
    pub source: PathBuf,
    /// Remote destination (user@host:/path)
    pub destination: String,
    /// SSH port (default 22)
    pub ssh_port: u16,
    /// SSH identity file (optional)
    pub identity_file: Option<PathBuf>,
    /// Exclude patterns
    pub excludes: Vec<String>,
    /// Dry run (don't actually sync)
    pub dry_run: bool,
    /// Delete files on destination that don't exist on source
    pub delete: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            source: PathBuf::from("."),
            destination: String::new(),
            ssh_port: 22,
            identity_file: None,
            excludes: vec![
                ".git".to_string(),
                "node_modules".to_string(),
                ".env".to_string(),
                "*.log".to_string(),
            ],
            dry_run: false,
            delete: false,
        }
    }
}

/// Result of a sync operation
#[derive(Debug)]
pub struct SyncResult {
    /// Number of files transferred
    pub files_transferred: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Files that were deleted (if delete=true)
    pub files_deleted: Vec<String>,
    /// Whether this was a dry run
    pub dry_run: bool,
}

/// Sync files from local source to remote destination using rsync
pub fn sync_to_remote(config: &SyncConfig) -> Result<SyncResult, SyncError> {
    // Verify source exists
    if !config.source.exists() {
        return Err(SyncError::SourceNotFound(config.source.clone()));
    }

    // Build rsync command
    let mut cmd = Command::new("rsync");

    // Basic flags: archive mode, compress, verbose, progress
    cmd.args(["-avz", "--progress"]);

    // Dry run
    if config.dry_run {
        cmd.arg("--dry-run");
    }

    // Delete extraneous files
    if config.delete {
        cmd.arg("--delete");
    }

    // SSH options
    let ssh_cmd = if let Some(ref identity) = config.identity_file {
        format!(
            "ssh -p {} -i {} -o StrictHostKeyChecking=accept-new",
            config.ssh_port,
            identity.display()
        )
    } else {
        format!(
            "ssh -p {} -o StrictHostKeyChecking=accept-new",
            config.ssh_port
        )
    };
    cmd.args(["-e", &ssh_cmd]);

    // Exclude patterns
    for exclude in &config.excludes {
        cmd.args(["--exclude", exclude]);
    }

    // Source (with trailing slash to sync contents)
    let source_str = format!("{}/", config.source.display());
    cmd.arg(&source_str);

    // Destination
    cmd.arg(&config.destination);

    // Execute
    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SyncError::RsyncError(stderr.to_string()));
    }

    // Parse output (simplified - real implementation would parse rsync stats)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let files_transferred = stdout.lines().filter(|l| !l.starts_with("sending") && !l.starts_with("total")).count() as u64;

    Ok(SyncResult {
        files_transferred,
        bytes_transferred: 0, // Would need to parse from rsync output
        files_deleted: vec![],
        dry_run: config.dry_run,
    })
}

/// Sync files from remote source to local destination (pull)
pub fn sync_from_remote(config: &SyncConfig) -> Result<SyncResult, SyncError> {
    // For pull, swap source and destination logic
    let mut pull_config = config.clone();

    // Build rsync command
    let mut cmd = Command::new("rsync");
    cmd.args(["-avz", "--progress"]);

    if config.dry_run {
        cmd.arg("--dry-run");
    }

    // SSH options
    let ssh_cmd = if let Some(ref identity) = config.identity_file {
        format!(
            "ssh -p {} -i {} -o StrictHostKeyChecking=accept-new",
            config.ssh_port,
            identity.display()
        )
    } else {
        format!(
            "ssh -p {} -o StrictHostKeyChecking=accept-new",
            config.ssh_port
        )
    };
    cmd.args(["-e", &ssh_cmd]);

    // Exclude patterns
    for exclude in &config.excludes {
        cmd.args(["--exclude", exclude]);
    }

    // Remote source
    cmd.arg(&config.destination);

    // Local destination
    cmd.arg(config.source.to_str().unwrap_or("."));

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SyncError::RsyncError(stderr.to_string()));
    }

    Ok(SyncResult {
        files_transferred: 0,
        bytes_transferred: 0,
        files_deleted: vec![],
        dry_run: config.dry_run,
    })
}

/// Check if rsync is available
pub fn check_rsync() -> bool {
    Command::new("rsync")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if SSH connection works
pub fn check_ssh_connection(host: &str, port: u16, identity_file: Option<&Path>) -> Result<bool, SyncError> {
    let mut cmd = Command::new("ssh");

    cmd.args(["-p", &port.to_string()]);
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.args(["-o", "ConnectTimeout=5"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new"]);

    if let Some(identity) = identity_file {
        cmd.args(["-i", identity.to_str().unwrap_or("")]);
    }

    cmd.arg(host);
    cmd.arg("echo ok");

    let output = cmd.output()?;
    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SyncConfig::default();
        assert_eq!(config.ssh_port, 22);
        assert!(!config.dry_run);
        assert!(config.excludes.contains(&".git".to_string()));
    }

    #[test]
    fn test_check_rsync() {
        // This will pass if rsync is installed
        let _ = check_rsync();
    }
}
