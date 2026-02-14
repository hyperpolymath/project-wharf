// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Wharf Core
//!
//! The shared logic library for Project Wharf - The Sovereign Web Hypervisor.
//!
//! This crate provides:
//! - SQL AST parsing for the database proxy ("Virtual Sharding")
//! - Cryptographic utilities (Ed448+ML-DSA-87 hybrid, SHAKE3-512, XChaCha20-Poly1305, BLAKE3)
//! - File integrity verification (BLAKE3 manifests)
//! - File synchronization (rsync over SSH)
//! - Fleet configuration management
//! - Configuration types for Nickel schema validation
//! - Common error types
//! - Configuration loading (TOML/Nickel)
//! - Mooring protocol for yacht synchronization
//! - Mooring HTTP client for Wharf→Yacht communication

pub mod config;
pub mod crypto;
pub mod db_policy;
pub mod errors;
pub mod fleet;
pub mod integrity;
pub mod mooring;
pub mod mooring_client;
pub mod sync;
pub mod types;

/// The current version of the Wharf protocol
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the version string for display
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }
}
