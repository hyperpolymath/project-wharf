// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! # Smoke Tests for Wharf CLI
//!
//! Tests basic CLI functionality: help output, subcommand discovery, and smoke execution.

use assert_cmd::Command;
use predicates::prelude::*;
use std::env;

/// Get the path to the wharf binary (built by cargo test)
fn get_wharf_binary() -> String {
    // The test runner provides the binary via the standard Rust test harness
    // Use `env!("CARGO_BIN_EXE_wharf")` which is available at compile time
    env!("CARGO_BIN_EXE_wharf").to_string()
}

/// Test that `wharf --help` produces valid output
#[test]
fn test_wharf_help_succeeds() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.arg("--help");

    cmd.assert().success()
        .stdout(predicate::str::contains("Wharf").or(predicate::str::contains("wharf")))
        .stdout(predicate::str::contains("SUBCOMMAND")
                    .or(predicate::str::contains("subcommand"))
                    .or(predicate::str::contains("Commands")));
}

/// Test that `wharf -V` or `wharf --version` shows version
#[test]
fn test_wharf_version() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.arg("--version");

    cmd.assert().success()
        .stdout(predicate::str::contains("0.1")
                    .or(predicate::str::contains("version")));
}

/// Test that unknown subcommand fails gracefully
#[test]
fn test_wharf_unknown_subcommand() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.arg("nonexistent-command");

    // Should fail
    cmd.assert().failure();
}

/// Test that `wharf init --help` shows init-specific help
#[test]
fn test_wharf_init_help() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.args(&["init", "--help"]);

    cmd.assert().success()
        .stdout(predicate::str::contains("init")
                    .or(predicate::str::contains("Initialize")));
}

/// Test that `wharf gen-keys --help` shows key generation help
#[test]
fn test_wharf_genkeys_help() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.args(&["gen-keys", "--help"]);

    cmd.assert().success()
        .stdout(predicate::str::contains("keys")
                    .or(predicate::str::contains("Generat")));
}

/// Test that `wharf db --help` shows database help
#[test]
fn test_wharf_db_help() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.args(&["db", "--help"]);

    cmd.assert().success();
}

/// Test that `wharf sec --help` shows security help
#[test]
fn test_wharf_sec_help() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.args(&["sec", "--help"]);

    cmd.assert().success();
}

/// Test that `wharf state --help` shows state help
#[test]
fn test_wharf_state_help() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.args(&["state", "--help"]);

    cmd.assert().success();
}

/// Test that `wharf moor --help` shows moor help
#[test]
fn test_wharf_moor_help() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.args(&["moor", "--help"]);

    cmd.assert().success();
}

/// Test that `wharf build --help` shows build help
#[test]
fn test_wharf_build_help() {
    let mut cmd = Command::new(get_wharf_binary());
    cmd.args(&["build", "--help"]);

    cmd.assert().success();
}
