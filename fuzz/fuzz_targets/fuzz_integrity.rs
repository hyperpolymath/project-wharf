// SPDX-License-Identifier: PMPL-1.0
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
//
//! Fuzz target for integrity manifest parsing
//! Tests handling of arbitrary manifest JSON input

#![no_main]

use libfuzzer_sys::fuzz_target;
use wharf_core::integrity::Manifest;

fuzz_target!(|data: &[u8]| {
    // Try to interpret fuzzer input as JSON manifest
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Attempt to deserialize - should handle any input gracefully
        let _: Result<Manifest, _> = serde_json::from_str(json_str);
    }
});
