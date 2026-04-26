// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Mooring Protocol
//!
//! The Mooring protocol defines the communication between Wharf CLI and Yacht agents
//! for secure file synchronization, configuration updates, and state management.
//!
//! ## Protocol Overview
//!
//! 1. Wharf initiates a mooring session with a signed request
//! 2. Yacht verifies the signature and responds with capabilities
//! 3. Wharf sends layers (config, files, db) in sequence
//! 4. Each layer is verified before proceeding
//! 5. Yacht commits all changes atomically
//!
//! ## Security Model
//!
//! - All requests are Ed448 + ML-DSA-87 hybrid signed (post-quantum safe)
//! - Yacht maintains an allow-list of Wharf public keys
//! - Emergency override via FIDO2 physical presence
//! - Manifests use BLAKE3 for integrity verification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Protocol version for compatibility checking
pub const MOORING_PROTOCOL_VERSION: &str = "1.0.0";

/// Default mooring API port on yacht-agent
pub const MOORING_PORT: u16 = 9001;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Mooring protocol errors
#[derive(Error, Debug)]
pub enum MooringError {
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Unknown Wharf public key")]
    UnknownPublicKey,

    #[error("Layer transfer failed: {0}")]
    LayerTransferFailed(String),

    #[error("Manifest verification failed: {0}")]
    ManifestVerificationFailed(String),

    #[error("Yacht not ready: {0}")]
    YachtNotReady(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Commit failed: {0}")]
    CommitFailed(String),

    #[error("Abort failed: {0}")]
    AbortFailed(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for mooring operations
pub type MooringResult<T> = Result<T, MooringError>;

// =============================================================================
// LAYER DEFINITIONS
// =============================================================================

/// Sync layers for mooring operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MooringLayer {
    /// Configuration files (highest priority, synced first)
    Config,

    /// Application files (PHP, themes, plugins, etc.)
    Files,

    /// Database state (schema + seed data)
    Database,

    /// Static assets (images, CSS, JS)
    Assets,

    /// Secrets (certificates, keys) - requires elevated auth
    Secrets,
}

impl MooringLayer {
    /// Get the sync priority (lower = synced first)
    pub fn priority(&self) -> u8 {
        match self {
            MooringLayer::Secrets => 0,  // First: secrets needed for other operations
            MooringLayer::Config => 1,   // Second: config determines behavior
            MooringLayer::Database => 2, // Third: schema before files
            MooringLayer::Files => 3,    // Fourth: application code
            MooringLayer::Assets => 4,   // Last: static content
        }
    }

    /// Get the default path for this layer
    pub fn default_path(&self) -> &'static str {
        match self {
            MooringLayer::Config => "/etc/wharf/",
            MooringLayer::Files => "/var/www/",
            MooringLayer::Database => "/var/lib/wharf/db/",
            MooringLayer::Assets => "/var/www/assets/",
            MooringLayer::Secrets => "/etc/wharf/secrets/",
        }
    }

    /// Check if this layer requires elevated authentication
    pub fn requires_elevated_auth(&self) -> bool {
        matches!(self, MooringLayer::Secrets | MooringLayer::Database)
    }
}

// =============================================================================
// SESSION MANAGEMENT
// =============================================================================

/// Mooring session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MooringSession {
    /// Unique session identifier
    pub session_id: String,

    /// Wharf public key (Ed25519)
    pub wharf_pubkey: String,

    /// Session creation timestamp (Unix epoch seconds)
    pub created_at: u64,

    /// Session expiration timestamp (Unix epoch seconds)
    pub expires_at: u64,

    /// Layers requested for this session
    pub requested_layers: Vec<MooringLayer>,

    /// Layers successfully committed
    pub committed_layers: Vec<MooringLayer>,

    /// Current session state
    pub state: SessionState,
}

/// Session state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Session initiated, waiting for layer transfer
    Initiated,

    /// Receiving layer data
    Receiving,

    /// Verifying received data
    Verifying,

    /// Ready to commit
    ReadyToCommit,

    /// Commit in progress
    Committing,

    /// Successfully completed
    Committed,

    /// Aborted by wharf or yacht
    Aborted,

    /// Failed with error
    Failed,
}

// =============================================================================
// PROTOCOL MESSAGES
// =============================================================================

/// Request to initiate a mooring session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MooringInitRequest {
    /// Protocol version
    pub version: String,

    /// Wharf public key (hex-encoded Ed25519)
    pub wharf_pubkey: String,

    /// Requested layers to sync
    pub layers: Vec<MooringLayer>,

    /// Request timestamp (Unix epoch seconds)
    pub timestamp: u64,

    /// Nonce for replay protection
    pub nonce: String,

    /// Force sync even if no changes detected
    pub force: bool,

    /// Dry run mode (verify but don't apply)
    pub dry_run: bool,

    /// Ed25519 signature of the request (hex-encoded)
    pub signature: String,
}

/// Response to mooring init request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MooringInitResponse {
    /// Session ID for subsequent requests
    pub session_id: String,

    /// Yacht protocol version
    pub version: String,

    /// Yacht public key (hex-encoded Ed25519)
    pub yacht_pubkey: String,

    /// Layers accepted for sync
    pub accepted_layers: Vec<MooringLayer>,

    /// Session expiration timestamp
    pub expires_at: u64,

    /// Current yacht status
    pub status: YachtStatus,
}

/// Yacht operational status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YachtStatus {
    /// Whether yacht is ready to receive mooring
    pub ready: bool,

    /// Current load percentage (0-100)
    pub load: u8,

    /// Active connections count
    pub connections: u32,

    /// Last successful mooring timestamp
    pub last_mooring: Option<u64>,

    /// Reason if not ready
    pub not_ready_reason: Option<String>,
}

/// Request to transfer a layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerTransferRequest {
    /// Session ID
    pub session_id: String,

    /// Layer being transferred
    pub layer: MooringLayer,

    /// BLAKE3 manifest of the layer contents
    pub manifest: LayerManifest,

    /// Request timestamp
    pub timestamp: u64,

    /// Signature of the request
    pub signature: String,
}

/// BLAKE3 manifest for a layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerManifest {
    /// Map of relative path to BLAKE3 hash
    pub files: HashMap<String, String>,

    /// Total size in bytes
    pub total_size: u64,

    /// Number of files
    pub file_count: usize,

    /// Root hash of the manifest itself
    pub root_hash: String,
}

/// Response to layer transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerTransferResponse {
    /// Transfer accepted
    pub accepted: bool,

    /// Files that need to be transferred (not already present)
    pub files_needed: Vec<String>,

    /// Files that match (already present with correct hash)
    pub files_matched: Vec<String>,

    /// Reason if not accepted
    pub rejection_reason: Option<String>,
}

/// Request to commit all transferred layers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRequest {
    /// Session ID
    pub session_id: String,

    /// Layers to commit (must be subset of transferred layers)
    pub layers: Vec<MooringLayer>,

    /// Request timestamp
    pub timestamp: u64,

    /// Signature of the request
    pub signature: String,
}

/// Response to commit request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResponse {
    /// Commit successful
    pub success: bool,

    /// Committed layers
    pub committed_layers: Vec<MooringLayer>,

    /// Files modified count
    pub files_modified: usize,

    /// Snapshot ID for rollback
    pub snapshot_id: Option<String>,

    /// Error message if failed
    pub error: Option<String>,
}

/// Request to abort a mooring session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbortRequest {
    /// Session ID
    pub session_id: String,

    /// Reason for abort
    pub reason: String,

    /// Request timestamp
    pub timestamp: u64,

    /// Signature of the request
    pub signature: String,
}

/// Response to abort request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbortResponse {
    /// Abort acknowledged
    pub acknowledged: bool,

    /// Cleanup actions taken
    pub cleanup_actions: Vec<String>,
}

/// Request to verify layer integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Session ID
    pub session_id: String,

    /// Layer to verify
    pub layer: MooringLayer,

    /// Expected manifest
    pub expected_manifest: LayerManifest,

    /// Request timestamp
    pub timestamp: u64,

    /// Signature of the request
    pub signature: String,
}

/// Response to verify request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Verification passed
    pub verified: bool,

    /// Files that match
    pub matched_files: usize,

    /// Files that differ
    pub differing_files: Vec<String>,

    /// Missing files
    pub missing_files: Vec<String>,

    /// Extra files (on yacht but not in manifest)
    pub extra_files: Vec<String>,
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Generate a unique session ID using CSPRNG
pub fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let random_bytes = crate::crypto::secure_random_bytes(8);
    let suffix = hex::encode(&random_bytes[..4]);
    format!("moor-{:x}-{}", timestamp, suffix)
}

/// Generate a nonce for replay protection using CSPRNG
pub fn generate_nonce() -> String {
    let random_bytes = crate::crypto::secure_random_bytes(16);
    hex::encode(random_bytes)
}

/// Get current Unix timestamp
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Compute canonical bytes for a mooring init request (for signing)
pub fn canonical_init_bytes(request: &MooringInitRequest) -> Vec<u8> {
    // All fields except signature, deterministic ordering
    let mut buf = Vec::new();
    buf.extend_from_slice(request.version.as_bytes());
    buf.extend_from_slice(request.wharf_pubkey.as_bytes());
    for layer in &request.layers {
        buf.extend_from_slice(&serde_json::to_vec(layer).unwrap_or_default());
    }
    buf.extend_from_slice(&request.timestamp.to_le_bytes());
    buf.extend_from_slice(request.nonce.as_bytes());
    buf.push(request.force as u8);
    buf.push(request.dry_run as u8);
    buf
}

/// Compute canonical bytes for a commit request (for signing)
pub fn canonical_commit_bytes(request: &CommitRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(request.session_id.as_bytes());
    for layer in &request.layers {
        buf.extend_from_slice(&serde_json::to_vec(layer).unwrap_or_default());
    }
    buf.extend_from_slice(&request.timestamp.to_le_bytes());
    buf
}

/// Compute canonical bytes for a verify request (for signing)
pub fn canonical_verify_bytes(request: &VerifyRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(request.session_id.as_bytes());
    buf.extend_from_slice(&serde_json::to_vec(&request.layer).unwrap_or_default());
    buf.extend_from_slice(&request.timestamp.to_le_bytes());
    buf
}

/// Compute canonical bytes for an abort request (for signing)
pub fn canonical_abort_bytes(request: &AbortRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(request.session_id.as_bytes());
    buf.extend_from_slice(request.reason.as_bytes());
    buf.extend_from_slice(&request.timestamp.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_priority() {
        assert!(MooringLayer::Secrets.priority() < MooringLayer::Config.priority());
        assert!(MooringLayer::Config.priority() < MooringLayer::Database.priority());
        assert!(MooringLayer::Database.priority() < MooringLayer::Files.priority());
        assert!(MooringLayer::Files.priority() < MooringLayer::Assets.priority());
    }

    #[test]
    fn test_layer_elevated_auth() {
        assert!(MooringLayer::Secrets.requires_elevated_auth());
        assert!(MooringLayer::Database.requires_elevated_auth());
        assert!(!MooringLayer::Config.requires_elevated_auth());
        assert!(!MooringLayer::Files.requires_elevated_auth());
        assert!(!MooringLayer::Assets.requires_elevated_auth());
    }

    #[test]
    fn test_session_id_generation() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert!(id1.starts_with("moor-"));
        assert!(id2.starts_with("moor-"));
        // IDs should be unique (with high probability)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert!(!nonce1.is_empty());
        assert!(!nonce2.is_empty());
    }

    #[test]
    fn test_serialization() {
        let manifest = LayerManifest {
            files: HashMap::from([
                ("config.toml".to_string(), "abc123".to_string()),
            ]),
            total_size: 1024,
            file_count: 1,
            root_hash: "def456".to_string(),
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: LayerManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.file_count, 1);
        assert_eq!(parsed.total_size, 1024);
    }
}
