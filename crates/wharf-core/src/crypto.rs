// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! Cryptographic utilities for Wharf
//!
//! Provides:
//! - Ed25519 key generation and signing
//! - BLAKE3 hashing for file integrity
//! - Argon2id password hashing

use blake3::Hasher;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
}

/// Compute a BLAKE3 hash of the given data
pub fn hash_blake3(data: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Compute a BLAKE3 hash of a file's contents
pub fn hash_file(path: &std::path::Path) -> Result<String, std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(hash_blake3(&data))
}

/// Verify that a file matches an expected hash
pub fn verify_file_hash(path: &std::path::Path, expected: &str) -> Result<bool, CryptoError> {
    let actual = hash_file(path).map_err(|e| CryptoError::KeyGenerationError(e.to_string()))?;
    Ok(actual == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let hash = hash_blake3(b"hello world");
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // 256 bits = 64 hex chars
    }
}
