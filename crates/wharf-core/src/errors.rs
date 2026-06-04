// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! Common error types for Project Wharf

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WharfError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Database policy violation: {0}")]
    PolicyViolation(String),

    #[error("File integrity check failed for: {path}")]
    IntegrityViolation { path: String },

    #[error("Mooring failed: {0}")]
    MooringError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
