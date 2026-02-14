// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <jonathan.jewell@open.ac.uk>

//! # Mooring Client
//!
//! HTTP client for Wharf CLI to communicate with yacht-agent's mooring API.
//! Handles the full mooring lifecycle: init → verify → rsync → commit.

use std::time::Duration;

use crate::crypto::{
    sign_hybrid, serialize_signature, serialize_public_key,
    hybrid_public_key, HybridKeypair,
};
use crate::mooring::{
    self, AbortRequest, AbortResponse, CommitRequest, CommitResponse,
    MooringInitRequest, MooringInitResponse, MooringLayer, VerifyRequest, VerifyResponse,
    LayerManifest, MOORING_PROTOCOL_VERSION,
    canonical_init_bytes, canonical_commit_bytes, canonical_verify_bytes, canonical_abort_bytes,
};
use thiserror::Error;

/// Errors from the mooring HTTP client
#[derive(Error, Debug)]
pub enum MooringClientError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Yacht returned error: {0}")]
    YachtError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Session error: {0}")]
    SessionError(String),
}

/// HTTP client for communicating with a yacht-agent's mooring API
pub struct MooringClient {
    client: reqwest::Client,
    base_url: String,
    keypair: HybridKeypair,
    pubkey_json: String,
}

impl MooringClient {
    /// Create a new mooring client targeting a yacht-agent
    ///
    /// `base_url` should be like `http://192.168.1.10:9001`
    pub fn new(base_url: &str, keypair: HybridKeypair) -> Self {
        let pubkey = hybrid_public_key(&keypair);
        let pubkey_json = serialize_public_key(&pubkey);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(2)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            keypair,
            pubkey_json,
        }
    }

    /// Initiate a mooring session with the yacht
    pub async fn init_session(
        &self,
        layers: Vec<MooringLayer>,
        force: bool,
        dry_run: bool,
    ) -> Result<MooringInitResponse, MooringClientError> {
        let nonce = mooring::generate_nonce();
        let timestamp = mooring::current_timestamp();

        // Build request without signature first
        let mut request = MooringInitRequest {
            version: MOORING_PROTOCOL_VERSION.to_string(),
            wharf_pubkey: self.pubkey_json.clone(),
            layers,
            timestamp,
            nonce,
            force,
            dry_run,
            signature: String::new(),
        };

        // Sign the canonical bytes
        let canonical = canonical_init_bytes(&request);
        let sig = sign_hybrid(&self.keypair, &canonical);
        request.signature = serialize_signature(&sig);

        let resp = self
            .client
            .post(format!("{}/mooring/init", self.base_url))
            .json(&request)
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;

        // Check for error response
        if let Some(error) = body.get("error") {
            return Err(MooringClientError::YachtError(
                error.as_str().unwrap_or("unknown error").to_string(),
            ));
        }

        serde_json::from_value(body)
            .map_err(|e| MooringClientError::SerializationError(e.to_string()))
    }

    /// Verify a layer against its manifest on the yacht
    pub async fn verify_layer(
        &self,
        session_id: &str,
        layer: MooringLayer,
        manifest: LayerManifest,
    ) -> Result<VerifyResponse, MooringClientError> {
        let timestamp = mooring::current_timestamp();

        let mut request = VerifyRequest {
            session_id: session_id.to_string(),
            layer,
            expected_manifest: manifest,
            timestamp,
            signature: String::new(),
        };

        // Sign
        let canonical = canonical_verify_bytes(&request);
        let sig = sign_hybrid(&self.keypair, &canonical);
        request.signature = serialize_signature(&sig);

        let resp = self
            .client
            .post(format!("{}/mooring/verify", self.base_url))
            .json(&request)
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;

        if let Some(error) = body.get("error") {
            return Err(MooringClientError::YachtError(
                error.as_str().unwrap_or("unknown error").to_string(),
            ));
        }

        serde_json::from_value(body)
            .map_err(|e| MooringClientError::SerializationError(e.to_string()))
    }

    /// Commit all transferred layers, creating a snapshot
    pub async fn commit(
        &self,
        session_id: &str,
        layers: Vec<MooringLayer>,
    ) -> Result<CommitResponse, MooringClientError> {
        let timestamp = mooring::current_timestamp();

        let mut request = CommitRequest {
            session_id: session_id.to_string(),
            layers,
            timestamp,
            signature: String::new(),
        };

        // Sign
        let canonical = canonical_commit_bytes(&request);
        let sig = sign_hybrid(&self.keypair, &canonical);
        request.signature = serialize_signature(&sig);

        let resp = self
            .client
            .post(format!("{}/mooring/commit", self.base_url))
            .json(&request)
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;

        if let Some(error) = body.get("error") {
            return Err(MooringClientError::YachtError(
                error.as_str().unwrap_or("unknown error").to_string(),
            ));
        }

        serde_json::from_value(body)
            .map_err(|e| MooringClientError::SerializationError(e.to_string()))
    }

    /// Abort a mooring session
    pub async fn abort(
        &self,
        session_id: &str,
        reason: &str,
    ) -> Result<AbortResponse, MooringClientError> {
        let timestamp = mooring::current_timestamp();

        let mut request = AbortRequest {
            session_id: session_id.to_string(),
            reason: reason.to_string(),
            timestamp,
            signature: String::new(),
        };

        // Sign
        let canonical = canonical_abort_bytes(&request);
        let sig = sign_hybrid(&self.keypair, &canonical);
        request.signature = serialize_signature(&sig);

        let resp = self
            .client
            .post(format!("{}/mooring/abort", self.base_url))
            .json(&request)
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;

        if let Some(error) = body.get("error") {
            return Err(MooringClientError::YachtError(
                error.as_str().unwrap_or("unknown error").to_string(),
            ));
        }

        serde_json::from_value(body)
            .map_err(|e| MooringClientError::SerializationError(e.to_string()))
    }
}
