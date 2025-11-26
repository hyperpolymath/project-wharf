// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! Database Policy Engine
//!
//! This module implements the "Virtual Sharding" logic for the database proxy.
//! It uses AST (Abstract Syntax Tree) parsing to analyze SQL queries and enforce
//! security policies without relying on fragile regex patterns.
//!
//! ## Security Model
//!
//! Queries are classified into three zones:
//! - **Mutable (Blue)**: Allowed to write (e.g., wp_comments, wp_woocommerce_orders)
//! - **Immutable (Red)**: Read-only, writes blocked unless from Wharf (e.g., wp_users, wp_options)
//! - **Hybrid (Grey)**: Conditional based on specific columns/values (e.g., transient caches in wp_options)

use sqlparser::ast::{Statement, SetExpr, TableFactor};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("SQL parse error: {0}")]
    ParseError(String),

    #[error("Policy violation: write to immutable table '{table}'")]
    ImmutableTableViolation { table: String },

    #[error("Policy violation: blocked column pattern '{pattern}' in table '{table}'")]
    BlockedColumnPattern { table: String, pattern: String },
}

/// The action to take for a query
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryAction {
    /// Allow the query to pass through
    Allow,
    /// Block the query (return error to client)
    Block,
    /// Log the query for audit purposes, then allow
    Audit,
}

/// A rule for the hybrid zone (conditional allow/deny)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridRule {
    /// The action to take if this rule matches
    pub action: String,
    /// The column to check
    pub column: String,
    /// Regex pattern to match against the value
    pub matches: String,
}

/// Database security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabasePolicy {
    /// Tables that are fully writable (content tables)
    pub allow_write: Vec<String>,

    /// Tables that are fully immutable (config tables)
    pub lock_down: Vec<String>,

    /// Hybrid rules for tables like wp_options
    pub hybrid_rules: Vec<HybridRule>,
}

impl Default for DatabasePolicy {
    fn default() -> Self {
        Self {
            // Default WordPress content tables
            allow_write: vec![
                "wp_comments".to_string(),
                "wp_commentmeta".to_string(),
                "wp_woocommerce_orders".to_string(),
                "wp_woocommerce_order_items".to_string(),
            ],
            // Default WordPress config tables
            lock_down: vec![
                "wp_users".to_string(),
                "wp_usermeta".to_string(),
                "wp_posts".to_string(),
                "wp_options".to_string(),
            ],
            hybrid_rules: vec![],
        }
    }
}

/// The Database Policy Engine
pub struct PolicyEngine {
    policy: DatabasePolicy,
    dialect: MySqlDialect,
}

impl PolicyEngine {
    pub fn new(policy: DatabasePolicy) -> Self {
        Self {
            policy,
            dialect: MySqlDialect {},
        }
    }

    /// Analyze a SQL query and determine the action to take
    pub fn analyze(&self, sql: &str) -> Result<QueryAction, PolicyError> {
        let ast = Parser::parse_sql(&self.dialect, sql)
            .map_err(|e| PolicyError::ParseError(e.to_string()))?;

        for statement in ast {
            match &statement {
                Statement::Insert { table_name, .. } => {
                    let table = table_name.to_string();
                    return self.check_write_permission(&table);
                }
                Statement::Update { table, .. } => {
                    let table_name = self.extract_table_name(table);
                    return self.check_write_permission(&table_name);
                }
                Statement::Delete { from, .. } => {
                    if let Some(table) = from.first() {
                        let table_name = self.extract_table_factor(&table.relation);
                        return self.check_write_permission(&table_name);
                    }
                }
                Statement::Drop { .. } => {
                    // DROP is always blocked from the yacht
                    return Ok(QueryAction::Block);
                }
                Statement::AlterTable { .. } => {
                    // ALTER is always blocked from the yacht
                    return Ok(QueryAction::Block);
                }
                // SELECT and other read operations are always allowed
                _ => {}
            }
        }

        Ok(QueryAction::Allow)
    }

    fn check_write_permission(&self, table: &str) -> Result<QueryAction, PolicyError> {
        // Normalize table name (remove schema prefix, backticks, etc.)
        let normalized = table.trim_matches('`').to_lowercase();

        // Check if explicitly allowed
        if self.policy.allow_write.iter().any(|t| normalized.contains(&t.to_lowercase())) {
            return Ok(QueryAction::Allow);
        }

        // Check if explicitly locked
        if self.policy.lock_down.iter().any(|t| normalized.contains(&t.to_lowercase())) {
            return Err(PolicyError::ImmutableTableViolation { table: normalized });
        }

        // Default: audit and allow (fail-open for unknown tables)
        // In production, you might want this to be Block (fail-closed)
        Ok(QueryAction::Audit)
    }

    fn extract_table_name(&self, table: &sqlparser::ast::TableWithJoins) -> String {
        self.extract_table_factor(&table.relation)
    }

    fn extract_table_factor(&self, factor: &TableFactor) -> String {
        match factor {
            TableFactor::Table { name, .. } => name.to_string(),
            _ => "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_allowed() {
        let engine = PolicyEngine::new(DatabasePolicy::default());
        let result = engine.analyze("SELECT * FROM wp_users").unwrap();
        assert_eq!(result, QueryAction::Allow);
    }

    #[test]
    fn test_insert_to_comments_allowed() {
        let engine = PolicyEngine::new(DatabasePolicy::default());
        let result = engine.analyze("INSERT INTO wp_comments (comment_content) VALUES ('test')").unwrap();
        assert_eq!(result, QueryAction::Allow);
    }

    #[test]
    fn test_insert_to_users_blocked() {
        let engine = PolicyEngine::new(DatabasePolicy::default());
        let result = engine.analyze("INSERT INTO wp_users (user_login) VALUES ('hacker')");
        assert!(result.is_err());
    }
}
