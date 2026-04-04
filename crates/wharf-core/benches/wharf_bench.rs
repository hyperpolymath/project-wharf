// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! # Benchmarks for Project Wharf
//!
//! Performance baselines for critical operations:
//! - Configuration parsing
//! - Cryptographic operations
//! - Manifest generation
//! - SQL analysis

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::fs;
use tempfile::TempDir;

use wharf_core::crypto::{
    hash_blake3, generate_hybrid_keypair, sign_hybrid,
};
use wharf_core::integrity::generate_manifest;

// =============================================================================
// CRYPTOGRAPHIC BENCHMARKS
// =============================================================================

fn benchmark_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_hash");

    for size in [1024, 10240, 102400].iter() {
        let data = black_box(vec![0x42u8; *size]);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| hash_blake3(&data))
        });
    }

    group.finish();
}

fn benchmark_keypair_generation(c: &mut Criterion) {
    c.bench_function("crypto_keypair_gen", |b| {
        b.iter(|| generate_hybrid_keypair())
    });
}

fn benchmark_signing(c: &mut Criterion) {
    let keypair = generate_hybrid_keypair().expect("Key gen");
    let message = b"test message for signing";

    c.bench_function("crypto_sign", |b| {
        b.iter(|| sign_hybrid(&keypair, black_box(message)))
    });
}

// =============================================================================
// FILE INTEGRITY BENCHMARKS
// =============================================================================

fn benchmark_manifest_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrity_manifest");

    for file_count in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}files", file_count)),
            file_count,
            |b, &file_count| {
                let temp = TempDir::new().expect("Temp dir");
                let site_dir = temp.path().join("site");
                fs::create_dir(&site_dir).expect("Create dir");

                // Pre-create files for this benchmark
                for i in 0..file_count {
                    fs::write(
                        site_dir.join(format!("file{}.txt", i)),
                        format!("content {}", i),
                    ).expect("Write file");
                }

                b.iter(|| {
                    generate_manifest(black_box(&site_dir), &[])
                        .expect("Generate manifest")
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// CONFIGURATION BENCHMARKS
// =============================================================================

fn benchmark_config_parsing(c: &mut Criterion) {
    use wharf_core::config::YachtAgentConfig;

    let config_json = r#"{
        "port": 3000,
        "bind_address": "0.0.0.0",
        "log_level": "info",
        "database": {
            "variant": "mariadb",
            "public_port": 3306,
            "shadow_port": 33060,
            "username": "wharf"
        }
    }"#;

    c.bench_function("config_parse_json", |b| {
        b.iter(|| {
            serde_json::from_str::<YachtAgentConfig>(black_box(config_json))
        })
    });
}

// =============================================================================
// SQL ANALYSIS BENCHMARKS
// =============================================================================

fn benchmark_sql_analysis(c: &mut Criterion) {
    use wharf_core::db_policy::{DatabasePolicy, PolicyEngine};

    let queries = [
        "SELECT * FROM wp_posts WHERE post_status = 'publish' LIMIT 10",
        "INSERT INTO wp_comments (comment_content) VALUES ('Great post!')",
        "UPDATE wp_comments SET comment_approved = '1' WHERE comment_ID = 42",
        "DELETE FROM wp_commentmeta WHERE meta_key = '_old_value'",
    ];

    let mut group = c.benchmark_group("db_policy");

    for (idx, query) in queries.iter().enumerate() {
        let engine = PolicyEngine::new(DatabasePolicy::default());

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("query_{}", idx)),
            query,
            |b, q| {
                b.iter(|| engine.analyze(black_box(q)))
            },
        );
    }

    group.finish();
}

// =============================================================================
// CRITERION CONFIGURATION
// =============================================================================

criterion_group!(
    benches,
    benchmark_hash,
    benchmark_keypair_generation,
    benchmark_signing,
    benchmark_manifest_generation,
    benchmark_config_parsing,
    benchmark_sql_analysis,
);

criterion_main!(benches);
