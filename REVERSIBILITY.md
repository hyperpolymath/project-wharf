# Reversibility Principles

Project Wharf is designed with reversibility as a core architectural principle.
Every operation should be undoable without data loss.

## Design Philosophy

> "Thermodynamic reversibility over algorithmic reversibility"

We prefer operations that naturally preserve state over those that require
explicit undo logic.

## Reversibility Guarantees

### Database Operations

| Operation | Reversibility | Mechanism |
|-----------|--------------|-----------|
| Schema migration | ✅ Full | Up/down migrations |
| Data modification | ✅ Full | Transaction rollback |
| Policy change | ✅ Full | Policy versioning |

The database proxy maintains a transaction log that allows point-in-time
recovery.

### Filesystem Operations

| Operation | Reversibility | Mechanism |
|-----------|--------------|-----------|
| File modification | ✅ Full | OverlayFS snapshots |
| File deletion | ✅ Full | Trash with retention |
| Permission change | ✅ Full | Permission history |

The Yacht filesystem uses OverlayFS, allowing instant rollback to any
previous state.

### Configuration Changes

| Operation | Reversibility | Mechanism |
|-----------|--------------|-----------|
| Nickel config | ✅ Full | Git versioning |
| DNS zone | ✅ Full | Serial-based rollback |
| Security policy | ✅ Full | Policy snapshots |

All configuration is version-controlled and can be rolled back via Git.

### Network Operations

| Operation | Reversibility | Mechanism |
|-----------|--------------|-----------|
| Firewall rule | ✅ Full | Rule versioning |
| Certificate rotation | ✅ Full | Certificate history |
| Nebula key rotation | ✅ Full | Key archival |

## Implementation Patterns

### 1. Snapshot Before Modify

```rust
// Before any modification, capture the current state
let snapshot = current_state.snapshot();

// Attempt the modification
match perform_modification() {
    Ok(result) => commit(result),
    Err(_) => restore(snapshot),
}
```

### 2. Event Sourcing

Configuration changes are stored as events, not states:

```nickel
{
  events = [
    { timestamp = "2025-01-01T00:00:00Z", action = "set", key = "header.csp", value = "default-src 'self'" },
    { timestamp = "2025-01-02T00:00:00Z", action = "modify", key = "header.csp", value = "default-src 'self' cdn.example.com" },
  ]
}
```

The current state is derived by replaying events. To "undo", simply replay
fewer events.

### 3. Soft Deletes

Nothing is permanently deleted immediately:

```sql
-- Instead of DELETE
UPDATE records SET deleted_at = NOW() WHERE id = 123;

-- Actual deletion after retention period (30 days)
DELETE FROM records WHERE deleted_at < NOW() - INTERVAL 30 DAY;
```

## User-Facing Reversibility

### CLI Commands

All destructive commands require `--confirm` and offer `--dry-run`:

```bash
# Preview what would happen
just moor primary --dry-run

# Require explicit confirmation
just deploy-zone example.db /var/named/ --confirm

# Undo the last operation
just undo-last
```

### Web Interface (if applicable)

- Undo button available for 30 seconds after any change
- History view shows all changes with rollback option
- "Dangerous" actions require two-step confirmation

## Audit Trail

All reversible operations are logged:

```json
{
  "timestamp": "2025-11-26T12:00:00Z",
  "actor": "jonathan@nebula",
  "operation": "policy_update",
  "target": "database.ncl",
  "previous_hash": "abc123...",
  "new_hash": "def456...",
  "reversible": true,
  "reversal_command": "git checkout abc123 -- configs/policies/database.ncl"
}
```

## Limitations

Some operations are intentionally irreversible for security:

| Operation | Reversible | Reason |
|-----------|------------|--------|
| Key revocation | ❌ No | Security - compromised keys must stay revoked |
| Audit log entries | ❌ No | Integrity - audit trail must be immutable |
| Security incident markers | ❌ No | Compliance - incidents must be recorded |

## Recovery Procedures

### Full System Recovery

```bash
# From complete backup
just recover --from-backup /path/to/backup.tar.gz

# From Git history
git checkout <commit> -- configs/
just rebuild
just deploy
```

### Point-in-Time Recovery

```bash
# Database
just db-recover --point-in-time "2025-11-26T11:00:00Z"

# Filesystem
just fs-recover --snapshot "snap-20251126-1100"
```

## Testing Reversibility

Our test suite includes reversibility tests:

```rust
#[test]
fn test_policy_change_reversible() {
    let original = load_policy();

    apply_change(&policy, change);

    revert_change(&policy);

    assert_eq!(load_policy(), original);
}
```

## Related Documents

- [SECURITY.md](SECURITY.md) - Security implications of reversibility
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - Technical implementation
- [CONTRIBUTING.adoc](CONTRIBUTING.adoc) - How to contribute reversibility tests
