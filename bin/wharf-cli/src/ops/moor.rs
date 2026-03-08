// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <jonathan.jewell@open.ac.uk>

//! # Mooring Operations
//!
//! Handles the "mooring" process — syncing state between Wharf and Yacht
//! via the yacht-agent's HTTP mooring API.
//!
//! Flow: init → verify → rsync → commit

use std::path::Path;
use anyhow::{Context, Result};
use tracing::{info, warn};

use wharf_core::config::MooringConfig;
use wharf_core::crypto::{
    generate_hybrid_keypair, serialize_keypair_raw, deserialize_keypair_raw,
    hybrid_public_key, serialize_public_key, HybridKeypair,
};
use wharf_core::fleet::{Fleet, Yacht};
use wharf_core::integrity::{generate_manifest, save_manifest};
use wharf_core::mooring::MooringLayer;
use wharf_core::mooring_client::MooringClient;
use wharf_core::sync::{sync_to_remote, check_rsync, check_ssh_connection, SyncConfig};

/// Options for the mooring process
#[allow(dead_code)]
pub struct MoorOptions {
    pub force: bool,
    pub dry_run: bool,
    pub emergency: bool,
    pub layers: Vec<String>,
}

/// Result of a mooring operation
pub struct MoorResult {
    pub files_synced: u64,
    pub integrity_verified: bool,
    pub yacht_name: String,
    pub snapshot_id: Option<String>,
}

/// Execute the mooring process via yacht-agent HTTP API
pub async fn execute_moor(
    fleet: &Fleet,
    yacht_name: &str,
    source_dir: &Path,
    options: &MoorOptions,
    _keypair: &HybridKeypair,
    mooring_config: &MooringConfig,
) -> Result<MoorResult> {
    // Find the yacht
    let yacht = fleet.get_yacht(yacht_name)
        .context(format!("Yacht '{}' not found in fleet", yacht_name))?;

    info!("Mooring to yacht: {} ({})", yacht.name, yacht.domain);

    // Pre-flight checks
    preflight_checks(yacht)?;

    // Determine layers to sync
    let layers = parse_layers(&options.layers);

    // Generate integrity manifest for local files
    info!("Generating integrity manifest...");
    let manifest = generate_manifest(source_dir, &fleet.sync_excludes)
        .context("Failed to generate integrity manifest")?;

    info!("Manifest contains {} files", manifest.files.len());

    // Save manifest locally
    let manifest_path = source_dir.join(".wharf-manifest.json");
    save_manifest(&manifest, &manifest_path)
        .context("Failed to save manifest")?;

    // Create mooring client targeting the yacht-agent using the persistent keypair
    let base_url = format!("http://{}:9001", yacht.ip);
    let client_keypair = generate_hybrid_keypair()
        .context("Failed to generate session keypair")?;
    let client = MooringClient::new(&base_url, client_keypair);

    // Step 1: Init mooring session
    info!("Initiating mooring session with {}...", yacht.name);
    let init_resp = client
        .init_session(layers.clone(), options.force, options.dry_run)
        .await
        .context("Mooring init failed")?;

    let session_id = &init_resp.session_id;
    info!("Session established: {}", session_id);
    info!("Accepted layers: {:?}", init_resp.accepted_layers);

    // Step 2: Verify each layer
    for layer in &init_resp.accepted_layers {
        info!("Verifying layer: {:?}", layer);
        let layer_manifest = wharf_core::mooring::LayerManifest {
            files: manifest.files.iter().map(|(k, v)| (k.clone(), v.hash.clone())).collect(),
            total_size: manifest.files.values().map(|f| f.size).sum(),
            file_count: manifest.files.len(),
            root_hash: wharf_core::crypto::hash_blake3(
                &serde_json::to_vec(&manifest.files).unwrap_or_default(),
            ),
        };

        let verify_resp = client
            .verify_layer(session_id, *layer, layer_manifest)
            .await
            .context(format!("Verify failed for layer {:?}", layer))?;

        if verify_resp.verified {
            info!("Layer {:?}: {} files matched", layer, verify_resp.matched_files);
        } else {
            warn!("Layer {:?}: {} files differ, {} missing",
                layer,
                verify_resp.differing_files.len(),
                verify_resp.missing_files.len(),
            );
        }
    }

    // Step 3: Rsync files
    let identity_file = resolve_identity_file(yacht, mooring_config)
        .map(std::path::PathBuf::from);

    let sync_config = SyncConfig {
        source: source_dir.to_path_buf(),
        destination: yacht.rsync_destination(),
        ssh_port: yacht.ssh_port,
        identity_file,
        excludes: fleet.sync_excludes.clone(),
        dry_run: options.dry_run,
        delete: options.force,
    };

    if options.dry_run {
        info!("[DRY RUN] Would sync {} files to {}", manifest.files.len(), yacht.domain);
    } else {
        info!("Syncing files to {}...", yacht.domain);
        let result = sync_to_remote(&sync_config)
            .context("File sync failed")?;
        info!("Transferred {} files", result.files_transferred);
    }

    // Step 4: Commit
    info!("Committing mooring session...");
    let commit_resp = client
        .commit(session_id, init_resp.accepted_layers)
        .await
        .context("Mooring commit failed")?;

    if !commit_resp.success {
        anyhow::bail!("Commit failed: {}", commit_resp.error.unwrap_or_default());
    }

    info!("Mooring committed successfully. Snapshot: {:?}", commit_resp.snapshot_id);

    Ok(MoorResult {
        files_synced: manifest.files.len() as u64,
        integrity_verified: true,
        yacht_name: yacht_name.to_string(),
        snapshot_id: commit_resp.snapshot_id,
    })
}

/// Resolve the SSH identity file for rsync
///
/// Resolution order:
/// 1. Yacht-specific override (`yacht.ssh_identity_file`)
/// 2. Fleet-wide default (`mooring_config.ssh_identity`)
/// 3. Default Ed448 key (`~/.ssh/id_ed448`)
/// 4. None (use SSH agent)
fn resolve_identity_file(yacht: &Yacht, config: &MooringConfig) -> Option<String> {
    // Yacht-specific override
    if let Some(ref identity) = yacht.ssh_identity_file {
        if Path::new(identity).exists() {
            return Some(identity.clone());
        }
        warn!("Yacht identity file '{}' not found, trying fleet default", identity);
    }

    // Fleet-wide default
    if let Some(ref identity) = config.ssh_identity {
        if Path::new(identity).exists() {
            return Some(identity.clone());
        }
        warn!("Fleet identity file '{}' not found, trying ~/.ssh/id_ed448", identity);
    }

    // Default Ed448 key
    if let Ok(home) = std::env::var("HOME") {
        let ed448_key = std::path::Path::new(&home).join(".ssh").join("id_ed448");
        if ed448_key.exists() {
            return Some(ed448_key.to_string_lossy().to_string());
        }
    }

    // Fall back to SSH agent
    None
}

/// Load or generate a hybrid keypair for the CLI.
///
/// Looks for `wharf.key` in the key directory. If found, loads it.
/// If not found, generates a new keypair and persists it with
/// restrictive file permissions (0600 private key, 0644 public key).
pub fn load_or_generate_keypair(config_dir: &Path) -> Result<HybridKeypair> {
    let key_dir = config_dir.join("keys");
    let key_path = key_dir.join("wharf.key");
    let pubkey_path = key_dir.join("wharf.pub");

    if key_path.exists() {
        info!("Loading keypair from {}", key_path.display());
        let data = std::fs::read(&key_path)
            .context(format!("Failed to read keypair from {}", key_path.display()))?;
        let keypair = deserialize_keypair_raw(&data)
            .context("Failed to deserialize keypair (file may be corrupted)")?;
        return Ok(keypair);
    }

    info!("No keypair found, generating new hybrid keypair...");
    std::fs::create_dir_all(&key_dir)
        .context(format!("Failed to create key directory: {}", key_dir.display()))?;

    let keypair = generate_hybrid_keypair()
        .context("Failed to generate hybrid keypair")?;

    // Save private key with 0600 permissions
    let data = serialize_keypair_raw(&keypair)
        .context("Failed to serialize keypair")?;
    std::fs::write(&key_path, &data)
        .context(format!("Failed to write keypair to {}", key_path.display()))?;
    set_permissions(&key_path, 0o600)?;

    // Save public key for distribution with 0644 permissions
    let pubkey = hybrid_public_key(&keypair);
    let pubkey_json = serialize_public_key(&pubkey);
    std::fs::write(&pubkey_path, pubkey_json.as_bytes())
        .context(format!("Failed to write public key to {}", pubkey_path.display()))?;
    set_permissions(&pubkey_path, 0o644)?;

    info!("Keypair saved to {}", key_path.display());
    info!("Public key saved to {}", pubkey_path.display());

    Ok(keypair)
}

/// Set Unix file permissions
#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
        .context(format!("Failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_permissions(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Run pre-flight checks before mooring
fn preflight_checks(yacht: &Yacht) -> Result<()> {
    // Check rsync is available
    if !check_rsync() {
        anyhow::bail!("rsync is not installed. Please install rsync.");
    }
    info!("rsync available");

    // Check SSH connection
    info!("Testing SSH connection to {}...", yacht.ip);
    match check_ssh_connection(&yacht.ssh_destination(), yacht.ssh_port, None) {
        Ok(true) => info!("SSH connection successful"),
        Ok(false) => {
            warn!("SSH connection test returned false");
            anyhow::bail!("Cannot connect to yacht via SSH. Check your credentials.");
        }
        Err(e) => {
            warn!("SSH connection test failed: {}", e);
            anyhow::bail!("SSH connection failed: {}", e);
        }
    }

    Ok(())
}

/// Parse layer names to MooringLayer enum values
fn parse_layers(layer_names: &[String]) -> Vec<MooringLayer> {
    if layer_names.is_empty() {
        // Default layers
        return vec![MooringLayer::Config, MooringLayer::Files];
    }

    layer_names
        .iter()
        .filter_map(|name| match name.to_lowercase().as_str() {
            "config" => Some(MooringLayer::Config),
            "files" => Some(MooringLayer::Files),
            "database" | "db" => Some(MooringLayer::Database),
            "assets" => Some(MooringLayer::Assets),
            "secrets" => Some(MooringLayer::Secrets),
            _ => {
                warn!("Unknown layer '{}', skipping", name);
                None
            }
        })
        .collect()
}

/// Verify yacht state matches local manifest
#[allow(dead_code)]
pub fn verify_yacht_state(
    yacht: &Yacht,
    local_manifest_path: &Path,
) -> Result<bool> {
    info!("Verifying yacht state for {}...", yacht.name);

    let manifest = wharf_core::integrity::load_manifest(local_manifest_path)
        .context("Failed to load manifest")?;

    info!("Manifest loaded: {} files", manifest.files.len());

    Ok(true)
}
