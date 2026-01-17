# proven Integration Plan

This document outlines the recommended [proven](https://github.com/hyperpolymath/proven) modules for Project Wharf.

## Recommended Modules

| Module | Purpose | Priority |
|--------|---------|----------|
| SafeCapability | Capability-based security with delegation proofs for the sovereign web hypervisor's permission model | High |
| SafeTransaction | ACID transactions with isolation proofs for stateful web operations | High |
| SafePath | Filesystem access that prevents path traversal attacks in sandboxed environments | High |
| SafeSQL | SQL injection prevention for database operations | Medium |
| SafePolicy | Zone-based policy enforcement for hypervisor security boundaries | Medium |
| SafeZone | (Custom) Security zone management with boundary enforcement | Medium |

## Integration Notes

Project Wharf as a sovereign web hypervisor requires strong security guarantees:

- **SafeCapability** is essential for managing permissions between isolated web contexts. The hypervisor must ensure capabilities cannot be escalated or leaked between zones.

- **SafeTransaction** ensures that web operations maintain ACID properties, critical for stateful interactions that span multiple components.

- **SafePath** prevents sandboxed applications from escaping their designated directories through path traversal attacks.

- **SafeSQL** should wrap any database interactions to guarantee injection-proof queries.

- **SafePolicy** enables AST-level policy enforcement, ensuring zone boundaries are respected at the code level.

The combination of these modules provides defense-in-depth for the hypervisor's security model.

## Related

- [proven library](https://github.com/hyperpolymath/proven)
- [Idris 2 documentation](https://idris2.readthedocs.io/)
