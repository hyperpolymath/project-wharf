// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! # Property-Based Tests for Wharf Core
//!
//! Uses proptest to generate random valid inputs and verify invariants hold.
//! Tests that operations compose correctly and maintain algebraic properties.

use proptest::prelude::*;
use std::fs;
use tempfile::TempDir;

use wharf_core::crypto::{
    generate_hybrid_keypair, sign_hybrid, hybrid_public_key, verify_with_scheme, SignatureScheme, hash_blake3,
};
use wharf_core::fleet::{Fleet, Yacht};

// =============================================================================
// CONFIG ROUND-TRIP PROPERTIES
// =============================================================================

/// Property: Any valid TOML config can be parsed, serialized, and parsed again
/// Output: parse → serialize → parse should equal original parse
#[test]
fn prop_config_toml_roundtrip() {
    proptest!(|(
        port in 1024u16..65535u16,
        debug in prop::bool::ANY,
    )| {
        let toml_str = format!(
            r#"
port = {}
debug = {}
"#,
            port, debug
        );

        // Parse once
        let parsed1: toml::Table = toml::from_str(&toml_str).expect("Parse 1");

        // Serialize
        let serialized = parsed1.to_string();

        // Parse again
        let parsed2: toml::Table = toml::from_str(&serialized).expect("Parse 2");

        // Both should have same values
        assert_eq!(
            parsed1.get("port"),
            parsed2.get("port"),
            "Port value mismatch"
        );
        assert_eq!(
            parsed1.get("debug"),
            parsed2.get("debug"),
            "Debug value mismatch"
        );
    });
}

// =============================================================================
// CRYPTOGRAPHIC PROPERTIES
// =============================================================================

/// Property: Any message signed with a keypair can be verified with its public key
/// ∀ message: sign(keypair, message) → verify(public_key, message, sig) = Ok
#[test]
fn prop_signature_verify_correct_key() {
    proptest!(|(data in ".*")| {
        let keypair = generate_hybrid_keypair().expect("Key gen");
        let message = data.as_bytes();

        // Sign
        let signature = sign_hybrid(&keypair, message);

        // Verify with correct public key
        let public_key = hybrid_public_key(&keypair);
        let result = verify_with_scheme(
            &public_key,
            message,
            &signature,
            SignatureScheme::MlDsa87Only,
        );

        prop_assert!(result.is_ok(), "Valid signature should verify");
    });
}

/// Property: Signature verification is deterministic
/// ∀ message, keypair: verify(pk, msg, sig) always returns same result
#[test]
fn prop_signature_deterministic() {
    proptest!(|(data in ".*")| {
        let keypair = generate_hybrid_keypair().expect("Key gen");
        let message = data.as_bytes();
        let public_key = hybrid_public_key(&keypair);

        // Sign once
        let signature = sign_hybrid(&keypair, message);

        // Verify multiple times
        let result1 = verify_with_scheme(
            &public_key,
            message,
            &signature,
            SignatureScheme::MlDsa87Only,
        );
        let result2 = verify_with_scheme(
            &public_key,
            message,
            &signature,
            SignatureScheme::MlDsa87Only,
        );
        let result3 = verify_with_scheme(
            &public_key,
            message,
            &signature,
            SignatureScheme::MlDsa87Only,
        );

        // All results should be identical
        prop_assert_eq!(
            result1.is_ok(),
            result2.is_ok(),
            "Signature verification not deterministic (1 vs 2)"
        );
        prop_assert_eq!(
            result2.is_ok(),
            result3.is_ok(),
            "Signature verification not deterministic (2 vs 3)"
        );
    });
}

/// Property: Hash function is deterministic
/// ∀ data: hash_blake3(data) = hash_blake3(data)
#[test]
fn prop_hash_deterministic() {
    proptest!(|(data in ".*")| {
        let bytes = data.as_bytes();

        let hash1 = hash_blake3(bytes);
        let hash2 = hash_blake3(bytes);
        let hash3 = hash_blake3(bytes);

        prop_assert_eq!(
            &hash1, &hash2,
            "BLAKE3 hash not deterministic (1 vs 2)"
        );
        prop_assert_eq!(
            &hash2, &hash3,
            "BLAKE3 hash not deterministic (2 vs 3)"
        );
    });
}

/// Property: Hash function produces different outputs for different inputs
/// ∀ data1, data2: data1 ≠ data2 → hash_blake3(data1) ≠ hash_blake3(data2)
/// (with negligible collision probability)
#[test]
fn prop_hash_different_inputs_different_outputs() {
    proptest!(|(
        data1 in ".*",
        data2 in ".*"
    )| {
        if data1 == data2 {
            return Ok(());
        }

        let hash1 = hash_blake3(data1.as_bytes());
        let hash2 = hash_blake3(data2.as_bytes());

        // Hashes should be different (avalanche effect)
        prop_assert_ne!(
            hash1, hash2,
            "Different inputs produced same hash"
        );
    });
}

// =============================================================================
// FLEET MANAGEMENT PROPERTIES
// =============================================================================

/// Property: Fleet add/remove operations are idempotent and consistent
/// ∀ yacht: add(yacht) → get(yacht.name) = Some(yacht)
#[test]
fn prop_fleet_add_retrieve() {
    proptest!(|(
        name in r"[a-z]{1,20}",
        ip in r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        domain in r"[a-z]{3,10}\.com",
    )| {
        // Only test valid-looking IPs
        if ip.split('.').any(|p| p.parse::<u32>().unwrap_or(256) > 255) {
            return Ok(());
        }

        let mut fleet = Fleet::default();
        let yacht = Yacht::new(&name, &ip, &domain);

        fleet.add_yacht(yacht.clone());

        let retrieved = fleet.get_yacht(&name);
        prop_assert!(
            retrieved.is_some(),
            "Added yacht not retrievable"
        );
        prop_assert_eq!(
            &retrieved.unwrap().name,
            &yacht.name,
            "Retrieved yacht name mismatch"
        );
    });
}

/// Property: Removing a yacht makes it unretrievable
/// ∀ yacht: add(yacht) → remove(yacht.name) → get(yacht.name) = None
#[test]
fn prop_fleet_remove_consistency() {
    proptest!(|(
        name in r"[a-z]{1,20}",
        ip in r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        domain in r"[a-z]{3,10}\.com",
    )| {
        if ip.split('.').any(|p| p.parse::<u32>().unwrap_or(256) > 255) {
            return Ok(());
        }

        let mut fleet = Fleet::default();
        let yacht = Yacht::new(&name, &ip, &domain);

        fleet.add_yacht(yacht);
        fleet.remove_yacht(&name);

        let retrieved = fleet.get_yacht(&name);
        prop_assert!(
            retrieved.is_none(),
            "Removed yacht still retrievable"
        );
    });
}

/// Property: Fleet list count matches add/remove operations
/// ∀ operations: count(list()) = initial_count + adds - removes
#[test]
fn prop_fleet_count_consistency() {
    proptest!(|(
        add_count in 1usize..10,
        remove_count in 0usize..5,
    )| {
        if remove_count > add_count {
            return Ok(());
        }

        let mut fleet = Fleet::default();

        // Add yachts
        for i in 0..add_count {
            let yacht = Yacht::new(
                &format!("yacht{}", i),
                &format!("10.0.0.{}", i),
                &format!("yacht{}.example.com", i),
            );
            fleet.add_yacht(yacht);
        }

        // Remove some yachts
        for i in 0..remove_count {
            fleet.remove_yacht(&format!("yacht{}", i));
        }

        let expected_count = add_count - remove_count;
        let actual_count = fleet.list_yachts().len();

        prop_assert_eq!(
            actual_count, expected_count,
            "Fleet count mismatch"
        );
    });
}

// =============================================================================
// FILE INTEGRITY PROPERTIES
// =============================================================================

/// Property: Manifest file count equals number of files created
#[test]
fn prop_manifest_file_count() {
    proptest!(|(
        file_count in 1usize..10,
    )| {
        let temp = TempDir::new().expect("Temp dir");
        let site_dir = temp.path().join("site");
        fs::create_dir(&site_dir).expect("Create dir");

        // Create files
        for i in 0..file_count {
            fs::write(
                site_dir.join(format!("file{}.txt", i)),
                format!("content {}", i),
            ).expect("Write file");
        }

        let manifest =
            wharf_core::integrity::generate_manifest(&site_dir, &[])
            .expect("Generate manifest");

        prop_assert_eq!(
            manifest.files.len(),
            file_count,
            "Manifest file count mismatch"
        );
    });
}

/// Property: Manifest directory list matches file structure
#[test]
fn prop_manifest_directory_structure() {
    proptest!(|(
        dir_count in 1usize..5,
        file_count in 1usize..3,
    )| {
        let temp = TempDir::new().expect("Temp dir");
        let site_dir = temp.path().join("site");
        fs::create_dir(&site_dir).expect("Create dir");

        // Create nested directory structure
        for d in 0..dir_count {
            let dir = site_dir.join(format!("dir{}", d));
            fs::create_dir(&dir).expect("Create subdir");

            for f in 0..file_count {
                fs::write(
                    dir.join(format!("file{}.txt", f)),
                    format!("content"),
                ).expect("Write file");
            }
        }

        let manifest =
            wharf_core::integrity::generate_manifest(&site_dir, &[])
            .expect("Generate manifest");

        // Should have at least dir_count directories
        prop_assert!(
            manifest.directories.len() >= dir_count,
            "Not all directories tracked"
        );
    });
}

// =============================================================================
// DATABASE POLICY PROPERTIES
// =============================================================================

/// Property: SELECT queries are deterministically allowed
/// ∀ SELECT query: analyze(query) produces consistent result
#[test]
fn prop_select_query_consistency() {
    proptest!(|(
        table_name in r"wp_[a-z]+",
        column_count in 1usize..5,
    )| {
        use wharf_core::db_policy::{DatabasePolicy, PolicyEngine};

        let engine = PolicyEngine::new(DatabasePolicy::default());

        // Build a SELECT query
        let columns = (0..column_count)
            .map(|i| format!("col{}", i))
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!("SELECT {} FROM {}", columns, table_name);

        let result1 = engine.analyze(&query);
        let result2 = engine.analyze(&query);

        // Both results should match
        match (result1, result2) {
            (Ok(a), Ok(b)) => {
                prop_assert_eq!(a, b, "Inconsistent query analysis");
            }
            (Err(_), Err(_)) => {
                // Both errored, OK
            }
            _ => {
                prop_assert!(false, "Inconsistent error behavior");
            }
        }
    });
}
