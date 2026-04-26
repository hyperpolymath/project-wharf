// SPDX-License-Identifier: PMPL-1.0-or-later

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

pub mod site;
pub mod deployment;
pub mod security;
pub mod volumes;

/// The semantic version of the wharf core engine.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
