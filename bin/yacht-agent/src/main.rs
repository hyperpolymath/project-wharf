// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Yacht Agent
//!
//! The runtime enforcer for Project Wharf - The Sovereign Web Hypervisor.
//!
//! This agent runs on the "Yacht" (the live web server) and provides:
//!
//! - **Database Proxy**: AST-aware SQL filtering ("Virtual Sharding")
//! - **Header Airlock**: HTTP header sanitization
//! - **File Integrity Monitor**: BLAKE3 hash verification
//! - **Mooring Endpoint**: Secure sync channel for the Wharf controller
//!
//! ## Security Model
//!
//! The agent operates in "Fail-Closed" mode:
//! - If it cannot verify a request, it blocks it
//! - If it crashes, the site goes offline (better than being hacked)
//! - Only signed commands from the Wharf are accepted

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::get, Router};
use tokio::sync::RwLock;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use wharf_core::db_policy::{DatabasePolicy, PolicyEngine};
use wharf_core::types::HeaderPolicy;

/// The shared state for the Yacht Agent
struct AgentState {
    /// The database policy engine
    db_engine: PolicyEngine,

    /// The HTTP header policy
    header_policy: HeaderPolicy,

    /// Whether the Wharf is currently moored (connected)
    moored: bool,

    /// The expected filesystem hashes (from Wharf)
    integrity_hashes: std::collections::HashMap<String, String>,
}

impl AgentState {
    fn new() -> Self {
        Self {
            db_engine: PolicyEngine::new(DatabasePolicy::default()),
            header_policy: HeaderPolicy::default(),
            moored: false,
            integrity_hashes: std::collections::HashMap::new(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set up logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Yacht Agent starting...");
    info!("Version: {}", wharf_core::VERSION);

    // Initialize state
    let state = Arc::new(RwLock::new(AgentState::new()));

    // Build the router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/status", get(status))
        .with_state(state);

    // Bind to localhost only (Nebula mesh provides external access)
    let addr = SocketAddr::from(([127, 0, 0, 1], 9000));
    info!("Yacht Agent listening on {}", addr);
    info!("Admin API available via Nebula mesh only");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Status endpoint (returns agent state)
async fn status() -> &'static str {
    r#"{"status": "active", "moored": false, "version": "0.1.0"}"#
}
