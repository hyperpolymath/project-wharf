// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <jonathan.jewell@open.ac.uk>

//! # Cryptographic Utilities for Wharf
//!
//! Provides:
//! - **Ed448 + ML-DSA-87 hybrid signatures** (post-quantum safe)
//! - **BLAKE3** hashing for file integrity (fast, verified)
//! - **SHAKE3-512** (SHA3-SHAKE256 with 512-bit output) for provenance/KDF
//! - **XChaCha20-Poly1305** AEAD symmetric encryption
//! - **HKDF-SHA3-256** key derivation
//! - **Argon2id** password hashing (512 MiB, 8 iterations, 4 lanes)
//! - **ChaCha20-DRBG** CSPRNG

use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed448_goldilocks::{SigningKey, VerifyingKey, Signature as Ed448Signature};
use ed448_goldilocks::elliptic_curve::common::Generate;
use hkdf::Hkdf;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use thiserror::Error;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Cryptographic operation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    #[error("Ed448 signature verification failed")]
    Ed448VerificationFailed,

    #[error("ML-DSA-87 signature verification failed")]
    MlDsa87VerificationFailed,

    #[error("Hybrid verification failed: {0}")]
    HybridVerificationFailed(String),

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

// =============================================================================
// HYBRID KEYPAIR
// =============================================================================

/// Ed448 + ML-DSA-87 hybrid keypair for post-quantum secure signing
pub struct HybridKeypair {
    ed448_signing: SigningKey,
    ed448_verifying: VerifyingKey,
    mldsa87_pk: mldsa87::PublicKey,
    mldsa87_sk: mldsa87::SecretKey,
}

/// Serializable hybrid public key for transport
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HybridPublicKey {
    /// Ed448 public key bytes (57 bytes, hex-encoded in JSON)
    pub ed448: Vec<u8>,
    /// ML-DSA-87 public key bytes
    pub mldsa87: Vec<u8>,
}

/// Hybrid signature (both must verify)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HybridSignature {
    /// Ed448 signature (114 bytes)
    pub ed448_sig: Vec<u8>,
    /// ML-DSA-87 detached signature
    pub mldsa87_sig: Vec<u8>,
}

// =============================================================================
// KEY GENERATION
// =============================================================================

/// Generate an Ed448 + ML-DSA-87 hybrid keypair
pub fn generate_hybrid_keypair() -> Result<HybridKeypair, CryptoError> {
    // Generate Ed448 keypair using OS entropy
    let ed448_signing = SigningKey::generate();
    let ed448_verifying = ed448_signing.verifying_key();

    // Generate ML-DSA-87 keypair
    let (mldsa87_pk, mldsa87_sk) = mldsa87::keypair();

    Ok(HybridKeypair {
        ed448_signing,
        ed448_verifying,
        mldsa87_pk,
        mldsa87_sk,
    })
}

/// Get the public key from a hybrid keypair
pub fn hybrid_public_key(keypair: &HybridKeypair) -> HybridPublicKey {
    let ed448_bytes: Vec<u8> = keypair.ed448_verifying.as_bytes().to_vec();
    let mldsa87_bytes: Vec<u8> =
        pqcrypto_traits::sign::PublicKey::as_bytes(&keypair.mldsa87_pk).to_vec();

    HybridPublicKey {
        ed448: ed448_bytes,
        mldsa87: mldsa87_bytes,
    }
}

// =============================================================================
// KEYPAIR SERIALIZATION
// =============================================================================

/// Magic bytes for wharf keypair files
const KEYPAIR_MAGIC: &[u8; 4] = b"WHRF";

/// Current keypair serialization version
const KEYPAIR_VERSION: u32 = 1;

impl HybridKeypair {
    /// Get the Ed448 verifying (public) key bytes (57 bytes)
    pub fn ed448_verifying_bytes(&self) -> Vec<u8> {
        self.ed448_verifying.as_bytes().to_vec()
    }

    /// Get the ML-DSA-87 public key bytes
    pub fn mldsa87_pk_bytes(&self) -> Vec<u8> {
        pqcrypto_traits::sign::PublicKey::as_bytes(&self.mldsa87_pk).to_vec()
    }

    /// Get the ML-DSA-87 secret key bytes
    pub fn mldsa87_sk_bytes(&self) -> Vec<u8> {
        pqcrypto_traits::sign::SecretKey::as_bytes(&self.mldsa87_sk).to_vec()
    }
}

/// Serialize a HybridKeypair to unencrypted bytes.
///
/// Format: `[4-byte magic "WHRF"][4-byte version][57-byte ed448_sk][57-byte ed448_vk]`
///         `[4-byte mldsa_sk_len][mldsa_sk][4-byte mldsa_pk_len][mldsa_pk]`
///
/// Use this for agent deployments where disk encryption handles confidentiality.
pub fn serialize_keypair_raw(keypair: &HybridKeypair) -> Result<Vec<u8>, CryptoError> {
    let ed448_sk_bytes = keypair.ed448_signing.as_bytes();
    let ed448_vk_bytes = keypair.ed448_verifying.as_bytes();
    let mldsa_sk_bytes = pqcrypto_traits::sign::SecretKey::as_bytes(&keypair.mldsa87_sk);
    let mldsa_pk_bytes = pqcrypto_traits::sign::PublicKey::as_bytes(&keypair.mldsa87_pk);

    let total_size = 4 + 4 + 57 + 57 + 4 + mldsa_sk_bytes.len() + 4 + mldsa_pk_bytes.len();
    let mut buf = Vec::with_capacity(total_size);

    // Header
    buf.extend_from_slice(KEYPAIR_MAGIC);
    buf.extend_from_slice(&KEYPAIR_VERSION.to_le_bytes());

    // Ed448 keys (fixed 57 bytes each)
    buf.extend_from_slice(ed448_sk_bytes);
    buf.extend_from_slice(ed448_vk_bytes);

    // ML-DSA-87 keys (length-prefixed)
    buf.extend_from_slice(&(mldsa_sk_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(mldsa_sk_bytes);
    buf.extend_from_slice(&(mldsa_pk_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(mldsa_pk_bytes);

    Ok(buf)
}

/// Deserialize a HybridKeypair from unencrypted bytes.
pub fn deserialize_keypair_raw(data: &[u8]) -> Result<HybridKeypair, CryptoError> {
    // Minimum size: 4 magic + 4 version + 57 sk + 57 vk + 4 sk_len + 4 pk_len = 130
    if data.len() < 130 {
        return Err(CryptoError::SerializationError(
            "Keypair data too short".to_string(),
        ));
    }

    // Verify magic
    if &data[0..4] != KEYPAIR_MAGIC {
        return Err(CryptoError::SerializationError(
            "Invalid keypair file (bad magic)".to_string(),
        ));
    }

    // Verify version
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != KEYPAIR_VERSION {
        return Err(CryptoError::SerializationError(
            format!("Unsupported keypair version: {} (expected {})", version, KEYPAIR_VERSION),
        ));
    }

    let mut offset = 8;

    // Ed448 signing key (57 bytes)
    let ed448_sk_bytes: [u8; 57] = data[offset..offset + 57]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyFormat("Ed448 signing key must be 57 bytes".to_string()))?;
    offset += 57;

    // Ed448 verifying key (57 bytes)
    let ed448_vk_bytes: [u8; 57] = data[offset..offset + 57]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyFormat("Ed448 verifying key must be 57 bytes".to_string()))?;
    offset += 57;

    // ML-DSA-87 secret key (length-prefixed)
    if data.len() < offset + 4 {
        return Err(CryptoError::SerializationError("Truncated ML-DSA-87 secret key length".to_string()));
    }
    let mldsa_sk_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    if data.len() < offset + mldsa_sk_len {
        return Err(CryptoError::SerializationError("Truncated ML-DSA-87 secret key".to_string()));
    }
    let mldsa_sk_bytes = &data[offset..offset + mldsa_sk_len];
    offset += mldsa_sk_len;

    // ML-DSA-87 public key (length-prefixed)
    if data.len() < offset + 4 {
        return Err(CryptoError::SerializationError("Truncated ML-DSA-87 public key length".to_string()));
    }
    let mldsa_pk_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    if data.len() < offset + mldsa_pk_len {
        return Err(CryptoError::SerializationError("Truncated ML-DSA-87 public key".to_string()));
    }
    let mldsa_pk_bytes = &data[offset..offset + mldsa_pk_len];

    // Reconstruct keys
    let ed448_signing = SigningKey::try_from(ed448_sk_bytes.as_slice())
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Ed448 signing key: {}", e)))?;
    let ed448_verifying = VerifyingKey::from_bytes(&ed448_vk_bytes)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Ed448 verifying key: {}", e)))?;

    let mldsa87_sk = mldsa87::SecretKey::from_bytes(mldsa_sk_bytes)
        .map_err(|_| CryptoError::InvalidKeyFormat("Invalid ML-DSA-87 secret key".to_string()))?;
    let mldsa87_pk = mldsa87::PublicKey::from_bytes(mldsa_pk_bytes)
        .map_err(|_| CryptoError::InvalidKeyFormat("Invalid ML-DSA-87 public key".to_string()))?;

    Ok(HybridKeypair {
        ed448_signing,
        ed448_verifying,
        mldsa87_pk,
        mldsa87_sk,
    })
}

/// Serialize a HybridKeypair with password-based encryption.
///
/// Format: `[4-byte magic][4-byte version][32-byte salt][24-byte nonce][encrypted payload]`
///
/// The payload is the raw keypair bytes encrypted with XChaCha20-Poly1305 using a key
/// derived via HKDF from the password.
pub fn serialize_keypair(keypair: &HybridKeypair, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Serialize the inner payload (raw format without the magic/version header)
    let raw = serialize_keypair_raw(keypair)?;
    // Skip the 8-byte header (magic + version) for the encrypted payload
    let payload = &raw[8..];

    // Derive encryption key from password
    let salt = secure_random_bytes(32);
    let key = derive_key_hkdf_shake512(password, Some(&salt), b"wharf-keypair-v1")?;

    // Encrypt
    let nonce = secure_random_bytes(24);
    let ciphertext = encrypt_xchacha20(&key, &nonce, payload)?;

    // Build output: magic + version + salt + nonce + ciphertext
    let mut buf = Vec::with_capacity(4 + 4 + 32 + 24 + ciphertext.len());
    buf.extend_from_slice(KEYPAIR_MAGIC);
    buf.extend_from_slice(&KEYPAIR_VERSION.to_le_bytes());
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ciphertext);

    Ok(buf)
}

/// Deserialize a HybridKeypair from password-encrypted bytes.
pub fn deserialize_keypair(data: &[u8], password: &[u8]) -> Result<HybridKeypair, CryptoError> {
    // Minimum: 4 magic + 4 version + 32 salt + 24 nonce + some ciphertext
    if data.len() < 65 {
        return Err(CryptoError::SerializationError(
            "Encrypted keypair data too short".to_string(),
        ));
    }

    // Verify magic
    if &data[0..4] != KEYPAIR_MAGIC {
        return Err(CryptoError::SerializationError(
            "Invalid keypair file (bad magic)".to_string(),
        ));
    }

    // Verify version
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != KEYPAIR_VERSION {
        return Err(CryptoError::SerializationError(
            format!("Unsupported keypair version: {}", version),
        ));
    }

    let salt = &data[8..40];
    let nonce = &data[40..64];
    let ciphertext = &data[64..];

    // Derive key from password
    let key = derive_key_hkdf_shake512(password, Some(salt), b"wharf-keypair-v1")?;

    // Decrypt
    let payload = decrypt_xchacha20(&key, nonce, ciphertext)?;

    // Reconstruct: prepend a fake raw header so deserialize_keypair_raw works
    let mut raw = Vec::with_capacity(8 + payload.len());
    raw.extend_from_slice(KEYPAIR_MAGIC);
    raw.extend_from_slice(&KEYPAIR_VERSION.to_le_bytes());
    raw.extend_from_slice(&payload);

    deserialize_keypair_raw(&raw)
}

// =============================================================================
// SIGNING & VERIFICATION
// =============================================================================

/// Sign a message with both Ed448 and ML-DSA-87
pub fn sign_hybrid(keypair: &HybridKeypair, message: &[u8]) -> HybridSignature {
    // Ed448 raw signature (no context, no prehash)
    let ed448_sig = keypair.ed448_signing.sign_raw(message);
    let ed448_sig_bytes = ed448_sig.to_bytes().to_vec();

    // ML-DSA-87 detached signature
    let mldsa87_sig = mldsa87::detached_sign(message, &keypair.mldsa87_sk);
    let mldsa87_sig_bytes =
        pqcrypto_traits::sign::DetachedSignature::as_bytes(&mldsa87_sig).to_vec();

    HybridSignature {
        ed448_sig: ed448_sig_bytes,
        mldsa87_sig: mldsa87_sig_bytes,
    }
}

/// Verify a hybrid signature — both Ed448 AND ML-DSA-87 must pass
pub fn verify_hybrid(
    pubkey: &HybridPublicKey,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<(), CryptoError> {
    // Verify Ed448
    let ed448_pk_bytes: [u8; 57] = pubkey.ed448.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidKeyFormat("Ed448 public key must be 57 bytes".to_string()))?;
    let ed448_vk = VerifyingKey::from_bytes(&ed448_pk_bytes)
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Ed448 public key: {}", e)))?;

    let ed448_sig = Ed448Signature::try_from(sig.ed448_sig.as_slice())
        .map_err(|e| CryptoError::InvalidKeyFormat(format!("Ed448 signature: {}", e)))?;

    ed448_vk
        .verify_raw(&ed448_sig, message)
        .map_err(|_| CryptoError::Ed448VerificationFailed)?;

    // Verify ML-DSA-87
    let mldsa_pk = mldsa87::PublicKey::from_bytes(&pubkey.mldsa87)
        .map_err(|_| CryptoError::InvalidKeyFormat("Invalid ML-DSA-87 public key".to_string()))?;
    let mldsa_sig = mldsa87::DetachedSignature::from_bytes(&sig.mldsa87_sig)
        .map_err(|_| CryptoError::InvalidKeyFormat("Invalid ML-DSA-87 signature".to_string()))?;

    mldsa87::verify_detached_signature(&mldsa_sig, message, &mldsa_pk)
        .map_err(|_| CryptoError::MlDsa87VerificationFailed)?;

    Ok(())
}

// =============================================================================
// SHAKE3-512 HASHING
// =============================================================================

/// Compute SHAKE3-512 (SHAKE256 with 512-bit output per FIPS 202)
pub fn hash_shake3_512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut output = vec![0u8; 64]; // 512 bits
    hasher.finalize_xof().read(&mut output);
    output
}

/// Compute SHAKE3-512 and return hex-encoded string
pub fn hash_shake3_512_hex(data: &[u8]) -> String {
    hex::encode(hash_shake3_512(data))
}

// =============================================================================
// BLAKE3 HASHING (unchanged — approved for file integrity speed)
// =============================================================================

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
    let actual = hash_file(path).map_err(CryptoError::IoError)?;
    Ok(actual == expected)
}

// =============================================================================
// XChaCha20-Poly1305 AEAD
// =============================================================================

/// Encrypt with XChaCha20-Poly1305
///
/// `key` must be exactly 32 bytes, `nonce` exactly 24 bytes.
pub fn encrypt_xchacha20(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::EncryptionError(
            "Key must be 32 bytes".to_string(),
        ));
    }
    if nonce.len() != 24 {
        return Err(CryptoError::EncryptionError(
            "Nonce must be 24 bytes".to_string(),
        ));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
    let xnonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(xnonce, plaintext)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))
}

/// Decrypt with XChaCha20-Poly1305
///
/// `key` must be exactly 32 bytes, `nonce` exactly 24 bytes.
pub fn decrypt_xchacha20(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::DecryptionError(
            "Key must be 32 bytes".to_string(),
        ));
    }
    if nonce.len() != 24 {
        return Err(CryptoError::DecryptionError(
            "Nonce must be 24 bytes".to_string(),
        ));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    let xnonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))
}

// =============================================================================
// HKDF KEY DERIVATION
// =============================================================================

/// Derive a key using HKDF with SHA3-256 as the hash function
///
/// Returns a 32-byte derived key suitable for XChaCha20-Poly1305.
pub fn derive_key_hkdf_shake512(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<sha3::Sha3_256>::new(salt, ikm);
    let mut okm = vec![0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    Ok(okm)
}

// =============================================================================
// ARGON2ID PASSWORD HASHING
// =============================================================================

/// Hash a password with Argon2id (512 MiB memory, 8 iterations, 4 lanes)
///
/// WARNING: This uses 512 MiB of memory. Only run on the Wharf (offline controller),
/// never on the yacht-agent (128 MiB memory limit).
pub fn hash_password_argon2id(password: &[u8]) -> Result<String, CryptoError> {
    use argon2::{
        password_hash::{rand_core::OsRng as PwOsRng, PasswordHasher, SaltString},
        Algorithm, Argon2, Params, Version,
    };

    let salt = SaltString::generate(&mut PwOsRng);
    let params = Params::new(
        512 * 1024, // 512 MiB (in KiB)
        8,          // 8 iterations
        4,          // 4 lanes
        Some(32),   // 32-byte output
    )
    .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash
pub fn verify_password_argon2id(password: &[u8], hash: &str) -> Result<bool, CryptoError> {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };

    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    Ok(Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok())
}

// =============================================================================
// CSPRNG
// =============================================================================

/// Generate cryptographically secure random bytes using ChaCha20-DRBG
pub fn secure_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

// =============================================================================
// SERIALIZATION
// =============================================================================

/// Serialize a hybrid public key to JSON
pub fn serialize_public_key(pubkey: &HybridPublicKey) -> String {
    serde_json::to_string(pubkey).unwrap_or_default()
}

/// Deserialize a hybrid public key from JSON
pub fn deserialize_public_key(json: &str) -> Result<HybridPublicKey, CryptoError> {
    serde_json::from_str(json).map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))
}

/// Serialize a hybrid signature to JSON
pub fn serialize_signature(sig: &HybridSignature) -> String {
    serde_json::to_string(sig).unwrap_or_default()
}

/// Deserialize a hybrid signature from JSON
pub fn deserialize_signature(json: &str) -> Result<HybridSignature, CryptoError> {
    serde_json::from_str(json).map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let hash = hash_blake3(b"hello world");
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // 256 bits = 64 hex chars
    }

    #[test]
    fn test_shake3_512() {
        let hash = hash_shake3_512(b"hello world");
        assert_eq!(hash.len(), 64); // 512 bits = 64 bytes
        let hex = hash_shake3_512_hex(b"hello world");
        assert_eq!(hex.len(), 128); // 64 bytes = 128 hex chars
    }

    #[test]
    fn test_hybrid_keypair_generation() {
        let keypair = generate_hybrid_keypair().unwrap();
        let pubkey = hybrid_public_key(&keypair);
        assert!(!pubkey.ed448.is_empty());
        assert!(!pubkey.mldsa87.is_empty());
    }

    #[test]
    fn test_hybrid_sign_verify() {
        let keypair = generate_hybrid_keypair().unwrap();
        let pubkey = hybrid_public_key(&keypair);
        let message = b"test message for hybrid signing";

        let sig = sign_hybrid(&keypair, message);
        assert!(!sig.ed448_sig.is_empty());
        assert!(!sig.mldsa87_sig.is_empty());

        // Full hybrid verification should succeed
        verify_hybrid(&pubkey, message, &sig).unwrap();
    }

    #[test]
    fn test_hybrid_verify_wrong_message() {
        let keypair = generate_hybrid_keypair().unwrap();
        let pubkey = hybrid_public_key(&keypair);

        let sig = sign_hybrid(&keypair, b"original message");

        // Verification with different message should fail
        assert!(verify_hybrid(&pubkey, b"wrong message", &sig).is_err());
    }

    #[test]
    fn test_xchacha20_roundtrip() {
        let key = secure_random_bytes(32);
        let nonce = secure_random_bytes(24);
        let plaintext = b"secret message";

        let ciphertext = encrypt_xchacha20(&key, &nonce, plaintext).unwrap();
        assert_ne!(&ciphertext, plaintext);

        let decrypted = decrypt_xchacha20(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20_wrong_key() {
        let key = secure_random_bytes(32);
        let wrong_key = secure_random_bytes(32);
        let nonce = secure_random_bytes(24);

        let ciphertext = encrypt_xchacha20(&key, &nonce, b"secret").unwrap();
        assert!(decrypt_xchacha20(&wrong_key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn test_hkdf_derive_key() {
        let ikm = b"input key material";
        let salt = b"optional salt";
        let info = b"context info";

        let key1 = derive_key_hkdf_shake512(ikm, Some(salt), info).unwrap();
        assert_eq!(key1.len(), 32);

        // Same inputs should produce same output
        let key2 = derive_key_hkdf_shake512(ikm, Some(salt), info).unwrap();
        assert_eq!(key1, key2);

        // Different info should produce different output
        let key3 = derive_key_hkdf_shake512(ikm, Some(salt), b"different").unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_secure_random_bytes() {
        let bytes1 = secure_random_bytes(32);
        let bytes2 = secure_random_bytes(32);
        assert_eq!(bytes1.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_signature_serialization() {
        let sig = HybridSignature {
            ed448_sig: vec![1, 2, 3],
            mldsa87_sig: vec![4, 5, 6],
        };
        let json = serialize_signature(&sig);
        let deserialized = deserialize_signature(&json).unwrap();
        assert_eq!(deserialized.ed448_sig, sig.ed448_sig);
        assert_eq!(deserialized.mldsa87_sig, sig.mldsa87_sig);
    }

    #[test]
    fn test_public_key_serialization() {
        let pk = HybridPublicKey {
            ed448: vec![10, 20, 30],
            mldsa87: vec![40, 50, 60],
        };
        let json = serialize_public_key(&pk);
        let deserialized = deserialize_public_key(&json).unwrap();
        assert_eq!(deserialized.ed448, pk.ed448);
        assert_eq!(deserialized.mldsa87, pk.mldsa87);
    }

    #[test]
    fn test_keypair_serialization_roundtrip() {
        let keypair = generate_hybrid_keypair().unwrap();
        let pubkey_before = hybrid_public_key(&keypair);

        let data = serialize_keypair_raw(&keypair).unwrap();
        let restored = deserialize_keypair_raw(&data).unwrap();
        let pubkey_after = hybrid_public_key(&restored);

        // Public keys must match
        assert_eq!(pubkey_before.ed448, pubkey_after.ed448);
        assert_eq!(pubkey_before.mldsa87, pubkey_after.mldsa87);

        // Sign with restored key, verify with original pubkey
        let msg = b"roundtrip test message";
        let sig = sign_hybrid(&restored, msg);
        verify_hybrid(&pubkey_before, msg, &sig).unwrap();
    }

    #[test]
    fn test_keypair_encrypted_roundtrip() {
        let keypair = generate_hybrid_keypair().unwrap();
        let pubkey_before = hybrid_public_key(&keypair);
        let password = b"test-password-wharf";

        let encrypted = serialize_keypair(&keypair, password).unwrap();
        let restored = deserialize_keypair(&encrypted, password).unwrap();
        let pubkey_after = hybrid_public_key(&restored);

        assert_eq!(pubkey_before.ed448, pubkey_after.ed448);
        assert_eq!(pubkey_before.mldsa87, pubkey_after.mldsa87);

        // Verify signing still works
        let msg = b"encrypted roundtrip";
        let sig = sign_hybrid(&restored, msg);
        verify_hybrid(&pubkey_before, msg, &sig).unwrap();
    }

    #[test]
    fn test_keypair_wrong_password() {
        let keypair = generate_hybrid_keypair().unwrap();
        let encrypted = serialize_keypair(&keypair, b"correct").unwrap();

        // Wrong password should fail decryption
        assert!(deserialize_keypair(&encrypted, b"wrong").is_err());
    }

    #[test]
    fn test_keypair_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        // Generate, serialize, write
        let keypair = generate_hybrid_keypair().unwrap();
        let pubkey_original = hybrid_public_key(&keypair);
        let data = serialize_keypair_raw(&keypair).unwrap();
        std::fs::write(&key_path, &data).unwrap();

        // Read, deserialize, verify
        let loaded_data = std::fs::read(&key_path).unwrap();
        let restored = deserialize_keypair_raw(&loaded_data).unwrap();
        let pubkey_restored = hybrid_public_key(&restored);

        assert_eq!(pubkey_original.ed448, pubkey_restored.ed448);
        assert_eq!(pubkey_original.mldsa87, pubkey_restored.mldsa87);

        // Sign → verify across the persistence boundary
        let msg = b"persistence test";
        let sig = sign_hybrid(&restored, msg);
        verify_hybrid(&pubkey_original, msg, &sig).unwrap();
    }
}
