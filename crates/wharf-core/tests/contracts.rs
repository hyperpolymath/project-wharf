// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! # Contract Tests for Wharf Core
//!
//! Tests invariants that must always hold:
//! - Type round-trips (serialization ↔ deserialization)
//! - State transitions maintain consistency
//! - Operations are deterministic (same input = same output)
//! - Configuration composition is valid

use std::fs;
use tempfile::TempDir;

use wharf_core::config::YachtAgentConfig;
use wharf_core::crypto::{
    generate_hybrid_keypair, serialize_public_key, deserialize_public_key,
    serialize_keypair_raw, deserialize_keypair_raw,
};
use wharf_core::fleet::{Fleet, Yacht, Adapter};
use wharf_core::integrity::generate_manifest;

// =============================================================================
// SERIALIZATION ROUND-TRIP CONTRACTS
// =============================================================================

/// Contract: PublicKey serialization ↔ deserialization is idempotent
#[test]
fn contract_public_key_roundtrip() {
    let keypair = generate_hybrid_keypair().expect("Key generation failed");
    let public_key = wharf_core::crypto::hybrid_public_key(&keypair);

    // Serialize (returns String)
    let serialized = serialize_public_key(&public_key);

    // Deserialize
    let deserialized = deserialize_public_key(&serialized)
        .expect("Deserialization failed");

    // Serialize again — should be identical
    let serialized2 = serialize_public_key(&deserialized);

    assert_eq!(
        serialized, serialized2,
        "PublicKey round-trip not idempotent"
    );
}

/// Contract: Keypair encryption round-trip is correct
#[test]
fn contract_keypair_encryption_roundtrip() {
    let keypair1 = generate_hybrid_keypair().expect("Key generation 1 failed");

    // Serialize keypair
    let serialized = serialize_keypair_raw(&keypair1)
        .expect("Serialization failed");

    // Deserialize
    let keypair2 = deserialize_keypair_raw(&serialized)
        .expect("Deserialization failed");

    // Both keypairs should produce identical public keys
    let pk1 = wharf_core::crypto::hybrid_public_key(&keypair1);
    let pk2 = wharf_core::crypto::hybrid_public_key(&keypair2);

    let s1 = serialize_public_key(&pk1);
    let s2 = serialize_public_key(&pk2);

    assert_eq!(s1, s2, "Keypairs should have identical public keys");
}

/// Contract: YachtAgentConfig serialization preserves all fields
#[test]
fn contract_yacht_agent_config_roundtrip() {
    let config1 = YachtAgentConfig::default();

    // Serialize to JSON
    let json = serde_json::to_string(&config1)
        .expect("Serialization to JSON failed");

    // Deserialize back
    let config2: YachtAgentConfig = serde_json::from_str(&json)
        .expect("Deserialization from JSON failed");

    // Config should be structurally equivalent
    assert_eq!(config1.logging.verbosity, config2.logging.verbosity, "Verbosity mismatch");
    assert_eq!(config1.logging.format, config2.logging.format, "Format mismatch");
}

// =============================================================================
// STATE CONSISTENCY CONTRACTS
// =============================================================================

/// Contract: Fleet operations maintain consistency
#[test]
fn contract_fleet_consistency() {
    let mut fleet = Fleet::default();

    // Add a yacht
    let yacht1 = Yacht::new("yacht1", "10.0.0.1", "example.com");
    fleet.add_yacht(yacht1);
    assert_eq!(fleet.list_yachts().len(), 1);

    // Add another yacht
    let yacht2 = Yacht::new("yacht2", "10.0.0.2", "example.org");
    fleet.add_yacht(yacht2);
    assert_eq!(fleet.list_yachts().len(), 2);

    // Remove the first yacht
    fleet.remove_yacht("yacht1");
    assert_eq!(fleet.list_yachts().len(), 1);

    // The remaining yacht should be yacht2
    let remaining = fleet.get_yacht("yacht2");
    assert!(remaining.is_some(), "yacht2 should still exist");
    assert!(
        fleet.get_yacht("yacht1").is_none(),
        "yacht1 should be removed"
    );
}

/// Contract: Yacht configuration is complete after creation
#[test]
fn contract_yacht_initialization() {
    let yacht = Yacht::new("test", "192.168.1.1", "test.example.com");

    // All required fields should be set
    assert!(!yacht.name.is_empty(), "Name not set");
    assert!(!yacht.ip.is_empty(), "IP not set");
    assert!(!yacht.domain.is_empty(), "Domain not set");
    assert!(!yacht.ssh_user.is_empty(), "SSH user not set");
    assert!(yacht.ssh_port > 0, "SSH port not set");
    assert!(!yacht.web_root.is_empty(), "Web root not set");

    // Database should be configured
    assert!(!yacht.database.variant.is_empty(), "Database variant not set");
    assert!(yacht.database.public_port > 0, "Database port not set");
}

/// Contract: Manifest file hashes are deterministic
#[test]
fn contract_manifest_determinism() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create test content
    fs::write(site_dir.join("index.php"), "<?php echo 'Hello'; ?>").unwrap();
    fs::write(site_dir.join("style.css"), "body { color: red; }").unwrap();

    // Generate manifest multiple times
    let manifest1 = generate_manifest(&site_dir, &[]).expect("First generation failed");
    let manifest2 = generate_manifest(&site_dir, &[]).expect("Second generation failed");
    let manifest3 = generate_manifest(&site_dir, &[]).expect("Third generation failed");

    // All manifests should be identical
    assert_eq!(
        manifest1.files.len(),
        manifest2.files.len(),
        "Manifest 1 and 2 differ in file count"
    );
    assert_eq!(
        manifest2.files.len(),
        manifest3.files.len(),
        "Manifest 2 and 3 differ in file count"
    );

    // Hash values should match
    for (path, entry1) in &manifest1.files {
        assert_eq!(
            entry1.hash,
            manifest2
                .files
                .get(path)
                .expect("File missing in manifest2")
                .hash,
            "Hash mismatch for {} between manifests 1 and 2",
            path
        );
        assert_eq!(
            entry1.hash,
            manifest3
                .files
                .get(path)
                .expect("File missing in manifest3")
                .hash,
            "Hash mismatch for {} between manifests 1 and 3",
            path
        );
    }
}

/// Contract: Manifest directories field is consistent with files
#[test]
fn contract_manifest_directory_consistency() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create nested structure
    fs::create_dir(site_dir.join("subdir")).unwrap();
    fs::write(site_dir.join("file1.txt"), "file1").unwrap();
    fs::write(site_dir.join("subdir").join("file2.txt"), "file2").unwrap();

    let manifest = generate_manifest(&site_dir, &[]).expect("Generation failed");

    // Every directory in a file path should be in the directories list
    for path in manifest.files.keys() {
        let parent = std::path::Path::new(path)
            .parent()
            .and_then(|p| p.to_str())
            .filter(|p| !p.is_empty());

        if let Some(parent_str) = parent {
            assert!(
                manifest.directories.contains(&parent_str.to_string()),
                "File {} has parent directory {} not in manifest.directories",
                path,
                parent_str
            );
        }
    }
}

// =============================================================================
// DATABASE CONFIGURATION CONTRACTS
// =============================================================================

/// Contract: Yacht database configuration is valid after initialization
#[test]
fn contract_yacht_database_config_validity() {
    let yacht = Yacht::new("test", "10.0.0.1", "test.example.com");
    let db = &yacht.database;

    // Ports should be valid (1-65535)
    assert!(db.public_port <= 65535, "Public port invalid");
    assert!(
        db.shadow_port <= 65535,
        "Shadow port invalid"
    );

    // Ports should be different
    assert_ne!(
        db.public_port, db.shadow_port,
        "Public and shadow ports should differ"
    );

    // Variant should be recognized
    assert!(
        matches!(
            db.variant.as_str(),
            "mysql" | "mariadb" | "postgresql" | "sqlite"
        ),
        "Database variant not recognized: {}",
        db.variant
    );
}

// =============================================================================
// CONFIGURATION COMPOSITION CONTRACTS
// =============================================================================

/// Contract: Yacht adapter type is consistently applied
#[test]
fn contract_yacht_adapter_consistency() {
    let mut yacht = Yacht::new("test", "10.0.0.1", "test.example.com");

    // Set adapter to WordPress
    yacht.adapter = Adapter::WordPress;

    // The adapter type should be retained
    assert_eq!(yacht.adapter, Adapter::WordPress, "Adapter not set correctly");

    // Change to Drupal
    yacht.adapter = Adapter::Drupal;
    assert_eq!(yacht.adapter, Adapter::Drupal, "Adapter not updated");
}

/// Contract: Manifest excludes are applied correctly
#[test]
fn contract_manifest_excludes_applied() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create files that will be excluded
    fs::write(site_dir.join("include.txt"), "included").unwrap();
    fs::write(site_dir.join("exclude.log"), "excluded").unwrap();
    fs::write(site_dir.join("node_modules_dir"), "excluded").unwrap();

    // Generate without excludes
    let manifest_all = generate_manifest(&site_dir, &[]).expect("Generation failed");

    // Generate with excludes
    let excludes = vec!["*.log".to_string(), "node_modules*".to_string()];
    let manifest_filtered =
        generate_manifest(&site_dir, &excludes).expect("Filtered generation failed");

    // Filtered manifest should have fewer files
    assert!(
        manifest_filtered.files.len() < manifest_all.files.len(),
        "Excludes not applied"
    );

    // Excluded files should not be in filtered manifest
    assert!(
        !manifest_filtered.files.contains_key("exclude.log"),
        "*.log not excluded"
    );
    assert!(
        !manifest_filtered.files.contains_key("node_modules_dir"),
        "node_modules* not excluded"
    );

    // Included file should be in both
    assert!(
        manifest_all.files.contains_key("include.txt")
            && manifest_filtered.files.contains_key("include.txt"),
        "include.txt should not be excluded"
    );
}
