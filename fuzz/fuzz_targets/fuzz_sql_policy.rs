// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
//
//! Fuzz target for SQL policy engine
//! Tests the PolicyEngine's ability to handle arbitrary SQL input

#![no_main]

use libfuzzer_sys::fuzz_target;
use wharf_core::db_policy::{PolicyConfig, PolicyEngine, TableZone};

fuzz_target!(|data: &[u8]| {
    // Try to interpret fuzzer input as UTF-8 SQL
    if let Ok(sql) = std::str::from_utf8(data) {
        // Create a basic policy config for testing
        let config = PolicyConfig {
            mutable_tables: vec!["wp_comments".to_string(), "wp_posts".to_string()],
            immutable_tables: vec!["wp_users".to_string(), "wp_options".to_string()],
            hybrid_tables: vec![],
            default_zone: TableZone::Mutable,
        };

        let engine = PolicyEngine::new(config);

        // Fuzz the evaluate function - it should handle any input gracefully
        let _ = engine.evaluate(sql);
    }
});
