// SPDX-License-Identifier: MPL-2.0

//! Project Wharf — High-Assurance WordPress Deployment Core.
//!
//! Wharf is a container-first deployment orchestrator for hardened 
//! WordPress environments. It treats WordPress sites as immutable 
//! artifacts, ensuring that every deployment is reproducible and 
//! cryptographically verified.
//!
//! ARCHITECTURE:
//! - `wharf-core`: Shared domain logic and deployment models.
//! - `wharf-cli`: Administrative interface for site lifecycle.
//! - `wharf-api`: Integration layer for CI/CD pipelines.

pub mod config;
pub mod crypto;
pub mod db_policy;
pub mod errors;
pub mod fleet;
pub mod integrity;
pub mod mooring;
pub mod mooring_client;
pub mod nebula;
pub mod snapshot;
pub mod sync;
pub mod types;

/// The semantic version of the wharf core engine.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
