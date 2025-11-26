// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Wharf Core
//!
//! The shared logic library for Project Wharf - The Sovereign Web Hypervisor.
//!
//! This crate provides:
//! - SQL AST parsing for the database proxy ("Virtual Sharding")
//! - Cryptographic utilities (Ed25519 signing, BLAKE3 hashing, Argon2id)
//! - Configuration types for Nickel schema validation
//! - Common error types

pub mod crypto;
pub mod db_policy;
pub mod errors;
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
