// SPDX-License-Identifier: MPL-2.0

//! # Snapshot Subsystem
//!
//! Materialises state snapshots on disk under `<snapshot_dir>/<snapshot_id>/`,
//! enforcing a fixed retention bound and providing a byte-exact round-trip
//! restore path.
//!
//! Layout per snapshot:
//! - `payload.bin` — the raw state bytes
//! - `manifest.json` — `{ ledger_id, sequence, payload_sha256 }`

use crate::config::StateConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Snapshot not found: {id}")]
    NotFound { id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub ledger_id: String,
    pub sequence: u64,
    pub payload_sha256: String,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: String,
    pub manifest: SnapshotManifest,
}

pub fn create_snapshot(
    state: &[u8],
    id: &str,
    config: &StateConfig,
) -> Result<Snapshot, SnapshotError> {
    let snap_dir = config.snapshot_dir.join(id);
    std::fs::create_dir_all(&snap_dir)?;
    std::fs::write(snap_dir.join("payload.bin"), state)?;

    // Sequence = count of *existing* snapshots before this one was added.
    let sequence = count_snapshots(&config.snapshot_dir).saturating_sub(1) as u64;

    let manifest = SnapshotManifest {
        ledger_id: id.to_string(),
        sequence,
        payload_sha256: sha256_hex(state),
    };
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(snap_dir.join("manifest.json"), manifest_json)?;

    enforce_retention(&config.snapshot_dir, config.snapshots_to_keep)?;

    Ok(Snapshot {
        id: id.to_string(),
        manifest,
    })
}

pub fn restore(id: &str, config: &StateConfig) -> Result<Vec<u8>, SnapshotError> {
    let payload_path = config.snapshot_dir.join(id).join("payload.bin");
    if !payload_path.exists() {
        return Err(SnapshotError::NotFound { id: id.to_string() });
    }
    Ok(std::fs::read(payload_path)?)
}

fn enforce_retention(snapshot_dir: &Path, keep: usize) -> Result<(), SnapshotError> {
    if !snapshot_dir.exists() {
        return Ok(());
    }
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(snapshot_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    while entries.len() > keep {
        let victim = entries.remove(0);
        std::fs::remove_dir_all(&victim)?;
    }
    Ok(())
}

fn count_snapshots(snapshot_dir: &Path) -> usize {
    if !snapshot_dir.exists() {
        return 0;
    }
    std::fs::read_dir(snapshot_dir)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .count()
        })
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(tmp: &TempDir) -> StateConfig {
        StateConfig {
            snapshots_to_keep: 3,
            snapshot_dir: tmp.path().join("snapshots"),
        }
    }

    #[test]
    fn round_trip_byte_exact() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp);
        let payload = b"hello wharf snapshot";
        let snap = create_snapshot(payload, "snap-000001", &cfg).unwrap();
        assert_eq!(snap.id, "snap-000001");
        let recovered = restore("snap-000001", &cfg).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn retention_never_exceeded() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp); // keep = 3
        for i in 0..6usize {
            let id = format!("snap-{:06}", i);
            create_snapshot(format!("payload-{}", i).as_bytes(), &id, &cfg).unwrap();
            let count = count_snapshots(&cfg.snapshot_dir);
            assert!(
                count <= cfg.snapshots_to_keep,
                "count {} > keep {}",
                count,
                cfg.snapshots_to_keep
            );
        }
    }

    #[test]
    fn restore_missing_returns_err() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp);
        assert!(restore("snap-999999", &cfg).is_err());
    }
}
