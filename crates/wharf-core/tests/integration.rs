// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Integration Tests for Wharf Core
//!
//! Tests the full stack: fleet management, integrity manifests, and sync preparation.

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use wharf_core::fleet::{Fleet, Yacht, Adapter};
use wharf_core::integrity::{generate_manifest, verify_manifest, save_manifest, load_manifest};

/// Test fleet configuration management
#[test]
fn test_fleet_management() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let fleet_path = temp.path().join("fleet.json");

    // Create a new fleet
    let mut fleet = Fleet::default();
    assert!(fleet.list_yachts().is_empty());

    // Add a yacht
    let yacht = Yacht::new("test-yacht", "192.168.1.100", "example.com");
    fleet.add_yacht(yacht);
    assert_eq!(fleet.list_yachts().len(), 1);

    // Save and reload
    fleet.save(&fleet_path).expect("Failed to save fleet");
    let loaded = Fleet::load(&fleet_path).expect("Failed to load fleet");
    assert_eq!(loaded.list_yachts().len(), 1);

    // Verify yacht properties
    let yacht = loaded.get_yacht("test-yacht").expect("Yacht not found");
    assert_eq!(yacht.ip, "192.168.1.100");
    assert_eq!(yacht.domain, "example.com");
    assert_eq!(yacht.ssh_port, 22);
}

/// Test fleet with multiple yachts
#[test]
fn test_fleet_multiple_yachts() {
    let mut fleet = Fleet::default();

    // Add multiple yachts with different adapters
    let mut wp = Yacht::new("wordpress-site", "10.0.0.1", "blog.example.com");
    wp.adapter = Adapter::WordPress;

    let mut drupal = Yacht::new("drupal-site", "10.0.0.2", "cms.example.com");
    drupal.adapter = Adapter::Drupal;

    let mut moodle = Yacht::new("moodle-site", "10.0.0.3", "learn.example.com");
    moodle.adapter = Adapter::Moodle;

    fleet.add_yacht(wp);
    fleet.add_yacht(drupal);
    fleet.add_yacht(moodle);

    assert_eq!(fleet.list_yachts().len(), 3);
    assert_eq!(fleet.list_enabled().len(), 3);

    // Remove a yacht
    fleet.remove_yacht("drupal-site");
    assert_eq!(fleet.list_yachts().len(), 2);
    assert!(fleet.get_yacht("drupal-site").is_none());
}

/// Test integrity manifest generation
#[test]
fn test_integrity_manifest_generation() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create test files
    fs::write(site_dir.join("index.php"), "<?php echo 'Hello'; ?>").unwrap();
    fs::write(site_dir.join("style.css"), "body { color: black; }").unwrap();

    // Create subdirectory with files
    let wp_content = site_dir.join("wp-content");
    fs::create_dir(&wp_content).unwrap();
    fs::write(wp_content.join("plugin.php"), "<?php /* Plugin */").unwrap();

    // Generate manifest
    let manifest = generate_manifest(&site_dir, &[]).expect("Failed to generate manifest");

    // Verify manifest contents
    assert_eq!(manifest.files.len(), 3);
    assert!(manifest.files.contains_key("index.php"));
    assert!(manifest.files.contains_key("style.css"));
    assert!(manifest.files.contains_key("wp-content/plugin.php"));

    // Verify directories
    assert!(manifest.directories.contains(&"wp-content".to_string()));
}

/// Test integrity manifest with excludes
#[test]
fn test_integrity_manifest_excludes() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create test files
    fs::write(site_dir.join("index.php"), "<?php echo 'Hello'; ?>").unwrap();
    fs::write(site_dir.join("debug.log"), "DEBUG: test").unwrap();
    fs::write(site_dir.join(".htaccess"), "RewriteEngine On").unwrap();

    // Create cache directory
    let cache = site_dir.join("cache");
    fs::create_dir(&cache).unwrap();
    fs::write(cache.join("temp.dat"), "cached data").unwrap();

    // Generate manifest with excludes
    let excludes = vec!["*.log".to_string(), "cache".to_string()];
    let manifest = generate_manifest(&site_dir, &excludes).expect("Failed to generate manifest");

    // Should only have index.php and .htaccess
    assert_eq!(manifest.files.len(), 2);
    assert!(manifest.files.contains_key("index.php"));
    assert!(manifest.files.contains_key(".htaccess"));
    assert!(!manifest.files.contains_key("debug.log"));
    assert!(!manifest.files.contains_key("cache/temp.dat"));
}

/// Test manifest save and load
#[test]
fn test_manifest_persistence() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create test file
    fs::write(site_dir.join("test.txt"), "Hello, World!").unwrap();

    // Generate and save manifest
    let manifest = generate_manifest(&site_dir, &[]).expect("Failed to generate");
    let manifest_path = temp.path().join("manifest.json");
    save_manifest(&manifest, &manifest_path).expect("Failed to save");

    // Load and verify
    let loaded = load_manifest(&manifest_path).expect("Failed to load");
    assert_eq!(loaded.files.len(), manifest.files.len());
    assert_eq!(
        loaded.files.get("test.txt").map(|f| &f.hash),
        manifest.files.get("test.txt").map(|f| &f.hash)
    );
}

/// Test manifest verification - clean state
#[test]
fn test_manifest_verification_clean() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create test files
    fs::write(site_dir.join("index.html"), "<html></html>").unwrap();
    fs::write(site_dir.join("app.js"), "console.log('test')").unwrap();

    // Generate manifest
    let manifest = generate_manifest(&site_dir, &[]).expect("Failed to generate");

    // Verify - should pass
    let result = verify_manifest(&site_dir, &manifest, false).expect("Verification failed");
    assert!(result.is_ok(), "Verification should pass for unmodified files");
    assert_eq!(result.passed.len(), 2);
    assert!(result.mismatched.is_empty());
    assert!(result.missing.is_empty());
}

/// Test manifest verification - modified file
#[test]
fn test_manifest_verification_modified() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create test file
    fs::write(site_dir.join("config.php"), "original content").unwrap();

    // Generate manifest
    let manifest = generate_manifest(&site_dir, &[]).expect("Failed to generate");

    // Modify the file
    fs::write(site_dir.join("config.php"), "HACKED content").unwrap();

    // Verify - should detect modification
    let result = verify_manifest(&site_dir, &manifest, false).expect("Verification failed");
    assert!(!result.is_ok(), "Verification should fail for modified files");
    assert_eq!(result.mismatched.len(), 1);
    assert!(result.mismatched.iter().any(|(path, _, _)| path == "config.php"));
}

/// Test manifest verification - missing file
#[test]
fn test_manifest_verification_missing() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create test files
    fs::write(site_dir.join("keep.php"), "kept").unwrap();
    fs::write(site_dir.join("delete.php"), "deleted").unwrap();

    // Generate manifest
    let manifest = generate_manifest(&site_dir, &[]).expect("Failed to generate");

    // Delete one file
    fs::remove_file(site_dir.join("delete.php")).unwrap();

    // Verify - should detect missing
    let result = verify_manifest(&site_dir, &manifest, false).expect("Verification failed");
    assert!(!result.is_ok(), "Verification should fail for missing files");
    assert_eq!(result.missing.len(), 1);
    assert!(result.missing.contains(&"delete.php".to_string()));
}

/// Test manifest verification - unexpected file
#[test]
fn test_manifest_verification_unexpected() {
    let temp = TempDir::new().expect("Failed to create temp dir");
    let site_dir = temp.path().join("site");
    fs::create_dir(&site_dir).expect("Failed to create site dir");

    // Create test file
    fs::write(site_dir.join("original.php"), "original").unwrap();

    // Generate manifest
    let manifest = generate_manifest(&site_dir, &[]).expect("Failed to generate");

    // Add unexpected file
    fs::write(site_dir.join("backdoor.php"), "<?php eval($_GET['x']); ?>").unwrap();

    // Verify - should detect unexpected
    let result = verify_manifest(&site_dir, &manifest, false).expect("Verification failed");
    assert!(!result.is_ok(), "Verification should fail for unexpected files");
    assert_eq!(result.unexpected.len(), 1);
    assert!(result.unexpected.contains(&"backdoor.php".to_string()));
}

/// Test yacht SSH destination formatting
#[test]
fn test_yacht_ssh_destination() {
    let yacht = Yacht::new("test", "192.168.1.1", "test.example.com");
    assert_eq!(yacht.ssh_destination(), "wharf@192.168.1.1");
    assert_eq!(yacht.rsync_destination(), "wharf@192.168.1.1:/var/www/html");
}

/// Test yacht with custom SSH settings
#[test]
fn test_yacht_custom_ssh() {
    let mut yacht = Yacht::new("test", "10.0.0.1", "custom.example.com");
    yacht.ssh_user = "webadmin".to_string();
    yacht.ssh_port = 2222;
    yacht.web_root = "/srv/www".to_string();

    assert_eq!(yacht.ssh_destination(), "webadmin@10.0.0.1");
    assert_eq!(yacht.rsync_destination(), "webadmin@10.0.0.1:/srv/www");
    assert_eq!(yacht.ssh_port, 2222);
}

/// Test database port masquerading configuration
#[test]
fn test_yacht_database_config() {
    let yacht = Yacht::new("test", "10.0.0.1", "db.example.com");

    // Default is MariaDB with port masquerading
    assert_eq!(yacht.database.variant, "mariadb");
    assert_eq!(yacht.database.public_port, 3306);
    assert_eq!(yacht.database.shadow_port, 33060);
}

/// Test sync config excludes
#[test]
fn test_sync_excludes() {
    use wharf_core::sync::SyncConfig;
    use std::path::PathBuf;

    let config = SyncConfig {
        source: PathBuf::from("/local/site"),
        destination: "user@server:/var/www".to_string(),
        ssh_port: 22,
        identity_file: None,
        excludes: vec![
            ".git".to_string(),
            "*.log".to_string(),
            "node_modules".to_string(),
        ],
        dry_run: false,
        delete: false,
    };

    assert_eq!(config.excludes.len(), 3);
    assert!(config.excludes.contains(&".git".to_string()));
}
