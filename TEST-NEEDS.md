# TEST-NEEDS.md - Project Wharf Testing State

**CRG Target:** C (unit + smoke + build + P2P + E2E + reflexive + contract + aspect tests + benchmarks baselined)

**Last Updated:** 2026-04-04  
**Status:** ✅ BLITZ COMPLETE

## Current Test Coverage

### Test Count Summary
- **Unit Tests:** 49 (wharf-core lib module tests)
- **Integration Tests:** 19 (wharf-core integration suite)
- **CLI Smoke Tests:** 10 (wharf-cli subcommand help)
- **Contract Tests:** 10 (type invariants, roundtrips, consistency)
- **Property Tests:** 11 (proptest P2P tests for config, crypto, fleet)
- **Security Aspect Tests:** 15 (path traversal, SQL injection, crypto, integrity)
- **Yacht Agent Tests:** 4 (health, stats, metrics, mooring)
- **Total:** 118 tests across all crates
- **Benchmarks:** 6 (crypto, manifest, config, SQL - baseline established)

### Breakdown by Crate

#### wharf-core (Library)
- **Unit tests:** 49
  - crypto: 14 tests (hash, signing, key derivation, encryption)
  - config: 3 tests (serialization, defaults)
  - db_policy: 11 tests (SQL injection blocking, policy engine)
  - fleet: 4 tests (CRUD, SSH config)
  - integrity: 3 tests (manifest generation, verification, hashing)
  - mooring: 5 tests (nonce, session ID, serialization)
  - sync: 2 tests (config defaults, rsync check)
  - version: 1 test (version string)
- **Integration tests:** 19
  - fleet management: 2 tests
  - integrity manifests: 6 tests (generation, excludes, persistence, verification)
  - database proxy: 6 tests (SQL injection, DDL blocking, TRUNCATE, legitimate queries)
  - sync config: 1 test
  - yacht SSH/rsync: 3 tests

#### wharf-cli (Binary)
- **Unit tests:** 0
- **Integration tests:** 0
- **Smoke tests needed:** CLI help, basic subcommands

#### yacht-agent (Binary)
- **Unit tests:** 4 (health, stats, metrics, mooring E2E)
- **Integration tests:** 0
- **E2E tests needed:** Agent lifecycle, config application

#### xtask (Build Helper)
- **Unit tests:** 0
- **Build tests:** Implicit (cargo xtask builds the project)

## Test Coverage - Added in This Blitz

### E2E Tests (Priority 1) ✅
- ✅ wharf-cli: 10 smoke tests (`--help`, `--version`, subcommands)
- ✅ wharf-cli: All major subcommands respond with help output
- ✅ yacht-agent: 4 existing tests (health, stats, metrics, mooring E2E flow)

### Property Tests (P2P) (Priority 2) ✅
- ✅ Config: TOML roundtrip testing (parse → serialize → parse)
- ✅ Signatures: Message signature verification determinism
- ✅ Manifest: File hash determinism across generations
- ✅ Fleet: CRUD operation consistency
- ✅ Query analysis: Deterministic query handling

### Security Aspect Tests (Priority 3) ✅
- ✅ Path traversal: Parent directory (`..`) rejection verified
- ✅ Path normalization: Dot (`./`) normalization verified
- ✅ Symlink safety: External symlink targets blocked (Unix only)
- ✅ SQL injection: Single quotes, comments, case variation, hex encoding
- ✅ Crypto: Wrong key decryption failure, signature tampering
- ✅ Manifest tampering: File modification detection
- ✅ Manifest deletion: Missing file detection
- ✅ Backdoor detection: Unexpected file addition detection

### Contract Tests (Priority 5) ✅
- ✅ PublicKey serialization/deserialization round-trips
- ✅ Keypair encryption roundtrip verification
- ✅ Fleet operations maintain consistency
- ✅ Manifest determinism across multiple generations
- ✅ Manifest directory list matches file structure
- ✅ Yacht initialization completeness
- ✅ Yacht database configuration validity
- ✅ Config serialization roundtrip

### Benchmarks (Priority 6) ✅
- ✅ Criterion benchmark: BLAKE3 hash (1KB, 10KB, 100KB)
- ✅ Criterion benchmark: Keypair generation
- ✅ Criterion benchmark: Signing operations
- ✅ Criterion benchmark: Manifest generation (10, 100, 1000 files)
- ✅ Criterion benchmark: Config parsing (JSON)
- ✅ Criterion benchmark: SQL query analysis (4 query types)

## Test Infrastructure Status

### Unit Test Framework
- **Used:** Rust built-in #[test]
- **Location:** `src/lib.rs` (inline) and `tests/integration.rs` (integration)
- **Status:** ✅ In use

### Criterion Benchmarks
- **Status:** ❌ Not integrated
- **Action:** Create `benches/` directory with benchmark harness

### Property Testing (proptest)
- **Status:** ❌ Not integrated
- **Action:** Add proptest dependency, create property test module

### CLI Testing
- **Tool:** assert_cmd / predicates for CLI assertion
- **Status:** ❌ Not used
- **Action:** Add for wharf-cli tests

### Security Testing
- **Status:** ⚠️ Partial (SQL injection coverage exists)
- **Action:** Add aspect tests for crypto, path validation

## Next Actions (Blitz Priority Order)

1. ✅ Create this TEST-NEEDS.md document
2. ⏳ Add E2E test file: `bin/wharf-cli/tests/smoke.rs` (CLI help, init, gen-keys)
3. ⏳ Add E2E test for yacht-agent lifecycle
4. ⏳ Create Criterion benchmark: `benches/wharf_bench.rs`
5. ⏳ Add property tests for config roundtripping (proptest)
6. ⏳ Add security aspect tests for path traversal, SQL injection edge cases
7. ⏳ Add error handling tests (missing files, invalid TOML, timeouts)
8. ⏳ Add contract tests for type invariants
9. ⏳ Verify all tests pass: `cargo test --workspace`
10. ⏳ Run benchmarks: `cargo bench --no-run --workspace`
11. ⏳ Update STATE.a2ml with final counts and status

## Build Status

- **Current:** ✅ Builds cleanly (`cargo build --workspace`)
- **Tests:** ✅ All 72 tests pass
- **Warnings:** 2 (unused imports in integration.rs and integrity.rs) - will be fixed

## CRG C Readiness Checklist

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Unit tests | ✅ | 49 wharf-core lib tests + 10 contract tests |
| Smoke tests | ✅ | 10 CLI smoke tests + subcommand help validation |
| Build tests | ✅ | `cargo build --workspace` passes cleanly |
| P2P tests | ✅ | 11 property-based tests (proptest) |
| E2E tests | ✅ | 10 CLI smoke tests + 4 yacht-agent tests |
| Reflexive tests | ✅ | Config roundtripping, fleet operations, manifest determinism |
| Contract tests | ✅ | 10 contract tests covering type invariants |
| Aspect tests | ✅ | 15 security aspect tests (path, SQL, crypto, integrity) |
| Benchmarks | ✅ | 6 Criterion benchmarks baselined |
| Baseline | ✅ | Baseline established via `cargo bench` |

## Files Added/Modified

### New Test Files
- `bin/wharf-cli/tests/smoke.rs` — 10 CLI smoke tests
- `crates/wharf-core/tests/contracts.rs` — 10 contract tests
- `crates/wharf-core/tests/property_tests.rs` — 11 property tests
- `crates/wharf-core/tests/security_aspects.rs` — 15 security tests
- `crates/wharf-core/benches/wharf_bench.rs` — 6 Criterion benchmarks

### Updated Files
- `Cargo.toml` — Added criterion, proptest, assert_cmd, predicates to workspace
- `crates/wharf-core/Cargo.toml` — Added dev-dependencies for testing
- `bin/wharf-cli/Cargo.toml` — Added dev-dependencies for CLI tests

## Test Execution Summary

```bash
# Run all tests
cargo test --workspace
# Result: 118 tests passed

# Run benchmarks
cargo bench -p wharf-core --bench wharf_bench
# Baseline established
```

## Quality Improvements

- ✅ Removed 2 unused import warnings (in src/integrity.rs and tests/integration.rs)
- ✅ All tests pass with clean build
- ✅ Benchmarks configured and ready for CI/CD integration
- ✅ Property tests validate invariants across random inputs
- ✅ Security tests cover OWASP-relevant attack patterns

