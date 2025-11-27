// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Integrity Operations
//!
//! File integrity manifest generation and verification.

use std::path::Path;
use anyhow::{Context, Result};
use tracing::info;

use wharf_core::integrity::{self, Manifest, VerifyResult};

/// Generate an integrity manifest for a directory
pub fn generate_manifest(
    root: &Path,
    excludes: &[String],
    output: Option<&Path>,
) -> Result<Manifest> {
    info!("Generating integrity manifest for {:?}", root);

    let manifest = integrity::generate_manifest(root, excludes)
        .context("Failed to generate manifest")?;

    info!("Generated manifest with {} files, {} directories",
          manifest.files.len(), manifest.directories.len());

    // Save if output path provided
    if let Some(out) = output {
        integrity::save_manifest(&manifest, out)
            .context("Failed to save manifest")?;
        info!("Manifest saved to {:?}", out);
    }

    Ok(manifest)
}

/// Verify a directory against a manifest
pub fn verify_against_manifest(
    root: &Path,
    manifest_path: &Path,
    allow_unexpected: bool,
) -> Result<VerifyResult> {
    info!("Verifying {:?} against manifest {:?}", root, manifest_path);

    let manifest = integrity::load_manifest(manifest_path)
        .context("Failed to load manifest")?;

    let result = integrity::verify_manifest(root, &manifest, allow_unexpected)
        .context("Verification failed")?;

    // Report results
    info!("Verification complete:");
    info!("  Passed: {} files", result.passed.len());

    if !result.mismatched.is_empty() {
        info!("  MISMATCHED: {} files", result.mismatched.len());
        for (path, expected, actual) in &result.mismatched {
            info!("    {} - expected: {}..., got: {}...",
                  path, &expected[..8], &actual[..8]);
        }
    }

    if !result.missing.is_empty() {
        info!("  MISSING: {} files", result.missing.len());
        for path in &result.missing {
            info!("    {}", path);
        }
    }

    if !result.unexpected.is_empty() {
        info!("  UNEXPECTED: {} files", result.unexpected.len());
        for path in &result.unexpected {
            info!("    {}", path);
        }
    }

    Ok(result)
}

/// Quick hash of a single file
pub fn hash_file(path: &Path) -> Result<String> {
    integrity::hash_file(path)
        .context(format!("Failed to hash file {:?}", path))
}

/// Verify a remote yacht's file integrity via SSH
pub fn verify_remote(
    manifest_path: &Path,
    ssh_user: &str,
    ssh_host: &str,
    ssh_port: u16,
    remote_root: &str,
    identity_file: Option<&Path>,
) -> Result<integrity::RemoteVerifyResult> {
    info!("Verifying remote yacht {} via SSH", ssh_host);
    info!("Remote root: {}", remote_root);

    // Load the manifest
    let manifest = integrity::load_manifest(manifest_path)
        .context("Failed to load manifest")?;

    info!("Loaded manifest with {} files", manifest.files.len());

    // Run remote verification
    let result = integrity::verify_remote_ssh(
        &manifest,
        ssh_user,
        ssh_host,
        ssh_port,
        remote_root,
        identity_file,
    ).context("Remote verification failed")?;

    // Report results
    if result.passed {
        info!("Remote verification PASSED");
        info!("  {} files verified", result.files_checked);
    } else {
        info!("Remote verification FAILED");

        if let Some(ref err) = result.error {
            info!("  Error: {}", err);
        }

        if !result.mismatched.is_empty() {
            info!("  MISMATCHED: {} files", result.mismatched.len());
            for path in &result.mismatched {
                info!("    {}", path);
            }
        }

        if !result.missing.is_empty() {
            info!("  MISSING: {} files", result.missing.len());
            for path in &result.missing {
                info!("    {}", path);
            }
        }
    }

    Ok(result)
}
