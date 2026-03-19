# Control-Plane API Software Item

This file defines stable implementation-contract requirements owned by `conclave-controlplane-api`.

## Shared DTO boundary

r[item.controlplane-api.shared-dto-boundary]
The `conclave-controlplane-api` crate MUST define the shared Rust DTO boundary for the current Conclave control-plane HTTP contract used by the server and Rust clients.

r[item.controlplane-api.managed-ops-payloads]
The shared DTO boundary for managed validate, plan, and apply operations MUST carry the canonical managed-configuration root type rather than a duplicated alternate desired-state shape.

r[item.controlplane-api.subject-and-relying-dtos]
The `conclave-controlplane-api` crate MUST define shared DTOs for the current invite, login, revision-discovery, and action-catalog operations used across the control-plane and relying-system surfaces.
