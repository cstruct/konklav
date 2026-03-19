# Managed Config Software Item

This file defines stable implementation-contract requirements owned by `conclave-managed-config`.

## Canonical bundle boundary

r[item.managed-config.root-bundle]
The `conclave-managed-config` crate MUST define one canonical root managed-configuration bundle type that operator and server workflows share for local loading, validation, plan, apply, and bootstrap boundaries.

r[item.managed-config.directory-assembly]
The `conclave-managed-config` crate MUST support deterministic assembly of one managed bundle from multiple Styx fragments in filename-sorted order, while excluding colocated server runtime config files from the managed bundle.

r[item.managed-config.required-catalog]
The `conclave-managed-config` crate MUST reject a managed bundle that omits the action-catalog portion of the canonical root schema.
