#!/bin/bash
# SPDX-License-Identifier: PMPL-1.0-or-later
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <jonathan.jewell@open.ac.uk>
#
# Project Wharf — SQL Injection Verification
# ===========================================
# Proves the yacht-agent SQL firewall blocks dangerous queries while
# allowing legitimate WordPress operations.
#
# Usage: cd deploy && bash verify-sqli.sh

set -euo pipefail

DB_USER="wordpress"
DB_PASS="${MARIADB_PASSWORD:-wharf-demo-pass-2026}"
DB_NAME="wordpress"

PASS=0
FAIL=0

# Get the db container name/ID
DB_CONTAINER=$(podman compose ps --format '{{.Names}}' | grep -E '_db_|_db$' | head -1)
if [ -z "$DB_CONTAINER" ]; then
    echo "ERROR: Could not find db container. Is the stack running?"
    echo "  Run: podman compose up -d"
    exit 1
fi

echo "======================================"
echo "  Wharf SQL Injection Verification"
echo "======================================"
echo ""
echo "  DB container: $DB_CONTAINER"
echo "  Queries routed through: agent:3306 (yacht-agent proxy)"
echo ""

# Helper: run SQL through the agent proxy (from the db container)
run_sql() {
    podman exec "$DB_CONTAINER" \
        mysql -h agent -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "$1" 2>&1
}

# -------------------------------------------------------------------------
# Test 1: SELECT should PASS (normal WordPress read)
# -------------------------------------------------------------------------
echo "--- Test 1: SELECT (should PASS) ---"
RESULT=$(run_sql "SELECT 1 AS test;" 2>&1) || true
if echo "$RESULT" | grep -q "test"; then
    echo "  PASS: SELECT query succeeded"
    PASS=$((PASS + 1))
else
    echo "  FAIL: SELECT query was blocked or errored"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi
echo ""

# -------------------------------------------------------------------------
# Test 2: INSERT into wp_users should be BLOCKED
# -------------------------------------------------------------------------
echo "--- Test 2: INSERT INTO wp_users (should be BLOCKED) ---"
RESULT=$(run_sql "INSERT INTO wp_users (user_login, user_pass) VALUES ('hacker', 'pwned');" 2>&1) || true
if echo "$RESULT" | grep -qi "blocked\|denied\|error\|reject"; then
    echo "  PASS: INSERT into wp_users was BLOCKED"
    PASS=$((PASS + 1))
else
    echo "  FAIL: INSERT into wp_users was NOT blocked!"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi
echo ""

# -------------------------------------------------------------------------
# Test 3: DROP TABLE should be BLOCKED (always)
# -------------------------------------------------------------------------
echo "--- Test 3: DROP TABLE (should be BLOCKED) ---"
RESULT=$(run_sql "DROP TABLE wp_posts;" 2>&1) || true
if echo "$RESULT" | grep -qi "blocked\|denied\|error\|reject"; then
    echo "  PASS: DROP TABLE was BLOCKED"
    PASS=$((PASS + 1))
else
    echo "  FAIL: DROP TABLE was NOT blocked!"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi
echo ""

# -------------------------------------------------------------------------
# Test 4: ALTER TABLE should be BLOCKED (always)
# -------------------------------------------------------------------------
echo "--- Test 4: ALTER TABLE (should be BLOCKED) ---"
RESULT=$(run_sql "ALTER TABLE wp_options ADD COLUMN backdoor TEXT;" 2>&1) || true
if echo "$RESULT" | grep -qi "blocked\|denied\|error\|reject"; then
    echo "  PASS: ALTER TABLE was BLOCKED"
    PASS=$((PASS + 1))
else
    echo "  FAIL: ALTER TABLE was NOT blocked!"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi
echo ""

# -------------------------------------------------------------------------
# Test 5: TRUNCATE should be BLOCKED (always)
# -------------------------------------------------------------------------
echo "--- Test 5: TRUNCATE TABLE (should be BLOCKED) ---"
RESULT=$(run_sql "TRUNCATE TABLE wp_posts;" 2>&1) || true
if echo "$RESULT" | grep -qi "blocked\|denied\|error\|reject"; then
    echo "  PASS: TRUNCATE was BLOCKED"
    PASS=$((PASS + 1))
else
    echo "  FAIL: TRUNCATE was NOT blocked!"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi
echo ""

# -------------------------------------------------------------------------
# Test 6: UNION-based injection attempt (classic SQLi)
# -------------------------------------------------------------------------
echo "--- Test 6: UNION SELECT injection (should be BLOCKED) ---"
RESULT=$(run_sql "SELECT * FROM wp_posts WHERE ID=1 UNION SELECT user_login, user_pass, 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 FROM wp_users;" 2>&1) || true
if echo "$RESULT" | grep -qi "blocked\|denied\|error\|reject"; then
    echo "  PASS: UNION injection was BLOCKED"
    PASS=$((PASS + 1))
else
    echo "  FAIL: UNION injection was NOT blocked!"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi
echo ""

# -------------------------------------------------------------------------
# Check agent stats
# -------------------------------------------------------------------------
echo "--- Agent Stats ---"
STATS=$(curl -sf http://localhost:9001/stats 2>&1) || true
if [ -n "$STATS" ]; then
    echo "  $STATS"
else
    echo "  WARNING: Could not fetch agent stats"
fi
echo ""

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo "======================================"
echo "  Results: $PASS/$TOTAL passed"
echo "======================================"

if [ "$FAIL" -gt 0 ]; then
    echo "  $FAIL test(s) FAILED"
    exit 1
else
    echo "  All tests passed — SQL injection is provably blocked"
    exit 0
fi
