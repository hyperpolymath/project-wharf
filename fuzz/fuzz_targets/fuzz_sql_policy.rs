// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <jonathan.jewell@open.ac.uk>
//
//! Fuzz target for SQL policy engine
//!
//! Tests the PolicyEngine's ability to handle arbitrary SQL input without
//! panicking, crashing, or exhibiting undefined behavior. The engine must
//! gracefully handle malformed SQL, edge-case encodings, and adversarial
//! query patterns.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wharf_core::db_policy::{DatabasePolicy, PolicyEngine};

fuzz_target!(|data: &[u8]| {
    // Try to interpret fuzzer input as UTF-8 SQL
    if let Ok(sql) = std::str::from_utf8(data) {
        // Use the default WordPress policy (mutable + immutable table sets)
        let engine = PolicyEngine::new(DatabasePolicy::default());

        // The analyze function must handle any input gracefully —
        // returning Ok(action) or Err(PolicyError), never panicking.
        let _ = engine.analyze(sql);
    }
});
