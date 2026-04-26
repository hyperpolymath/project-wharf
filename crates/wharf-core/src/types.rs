// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! Common types for Project Wharf

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A Yacht (runtime server) definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Yacht {
    /// Unique identifier for this yacht
    pub id: String,

    /// The Nebula mesh IP address
    pub ip: String,

    /// IPv6 address if available
    pub ipv6: Option<String>,

    /// The adapter to use (wordpress, drupal, joomla, etc.)
    pub adapter: String,

    /// Security policy level
    pub policy: PolicyLevel,

    /// The domain this yacht serves
    pub domain: String,
}

/// Security policy levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyLevel {
    /// Minimal restrictions (development only)
    Permissive,

    /// Standard security (production default)
    #[default]
    Standard,

    /// Maximum security (high-value targets)
    Strict,

    /// Paranoid mode (nation-state threat model)
    Paranoid,
}

/// The fleet configuration (all managed yachts)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fleet {
    /// Map of yacht ID to yacht configuration
    pub yachts: HashMap<String, Yacht>,
}

/// DNS Zone template variables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneVariables {
    pub domain: String,
    pub ip: String,
    pub ipv6: Option<String>,
    pub nameserver: String,
    pub nameserver2: Option<String>,
    pub nameserver3: Option<String>,
    pub nameserver4: Option<String>,
    pub nameservera: String,
    pub nameservera2: Option<String>,
    pub rpemail: String,
    pub serial: String,
    pub ttl: String,
    pub nsttl: String,
    pub maildomain: Option<String>,
    pub ftpip: Option<String>,
    pub cpversion: Option<String>,

    // Security records
    pub tls_fingerprint_hash: Option<String>,
    pub ssh_public_key_fingerprint: Option<String>,
    pub dkim_public_key: Option<String>,
}

/// HTTP Header policy for the Airlock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPolicy {
    /// Headers to strip from incoming requests
    pub blocked_headers: Vec<String>,

    /// Headers to inject into responses
    pub forced_headers: HashMap<String, String>,

    /// Maximum allowed header length
    pub max_header_length: usize,

    /// Allowed hosts (for Host header validation)
    pub allowed_hosts: Vec<String>,
}

impl Default for HeaderPolicy {
    fn default() -> Self {
        let mut forced = HashMap::new();
        forced.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        forced.insert("X-Frame-Options".to_string(), "DENY".to_string());
        forced.insert("Referrer-Policy".to_string(), "strict-origin-when-cross-origin".to_string());
        forced.insert("Cross-Origin-Opener-Policy".to_string(), "same-origin".to_string());
        forced.insert("Cross-Origin-Embedder-Policy".to_string(), "require-corp".to_string());
        forced.insert("Cross-Origin-Resource-Policy".to_string(), "same-origin".to_string());
        forced.insert("Permissions-Policy".to_string(),
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()".to_string());

        Self {
            blocked_headers: vec![
                "X-Forwarded-For".to_string(),
                "X-Real-IP".to_string(),
                "Server".to_string(),
                "X-Powered-By".to_string(),
            ],
            forced_headers: forced,
            max_header_length: 2000,
            allowed_hosts: vec![],
        }
    }
}
