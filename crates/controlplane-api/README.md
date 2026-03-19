# Control-Plane API

`conclave-controlplane-api` is the Rust crate and shared API surface for the current Conclave control-plane HTTP contract.

It gives the server and its clients one common serialization boundary for managed-configuration operations, invite and login flows, revision discovery, and action-catalog lookup.

## Responsibilities

- Define the current request and response DTOs for the Conclave control-plane contract.
- Keep managed-config request and response shapes stable across the client/server boundary.
- Reuse shared token and catalog response types where relying-system behavior overlaps with control-plane flows.

Out of scope:

- serving the HTTP API
- executing control-plane operations
- owning the underlying managed-config or JWT logic

## Public Interface

Primary entry point:

- `src/lib.rs`
  - Defines the shared request and response types for managed-config, invite, login, revision, and action-catalog operations.

Interface overview:

- Managed configuration
  - `ManagedValidateRequest`, `ManagedValidateResponse`
  - `ManagedPlanRequest`, `ManagedPlanResponse`
  - `ManagedApplyRequest`, `ManagedApplyResponse`
- Subject and invite flows
  - `InviteCreateRequest`, `InviteCreateResponse`
  - `RedeemInviteRequest`, `RedeemInviteResponse`
  - `LoginRequest`, `LoginResponse`
- Relying metadata
  - `CurrentRevisionsResponse`
  - `ActionCatalogResponse`

See [`src/lib.rs`](src/lib.rs) for the current DTO set.

## Relationships

### Dependency Summary

| Software item | Relationship |
| --- | --- |
| `conclave-core` | Provides shared value types reused inside API-facing DTOs. |
| `conclave-managed-config` | Provides the managed desired-state type embedded in managed-config request payloads. |
| `conclave-relying-auth` | Provides shared token-claims and action-catalog entry types reused in API responses. |

### Dependent Summary

| Software item | Relationship |
| --- | --- |
| `conclave-cli` | Uses these DTOs when calling the control-plane surface. |
| `conclave-server` | Uses these DTOs as the current HTTP contract for request parsing and response serialization. |

## Usage

Use these types at the network boundary between the server and any Rust client.

```rust
use conclave_controlplane_api::ManagedPlanRequest;
use conclave_managed_config::ManagedConfig;

let managed = ManagedConfig::load_from_str("catalog { actions () }")?;
let request = ManagedPlanRequest { managed };
```

## Running

This software item is a library crate and is not run directly as its own process.

It is exercised through other software items:

- `conclave-server`
  - uses these types for HTTP handlers and responses
- `conclave-cli`
  - uses these types for outbound control-plane requests
- tests in this crate and in downstream crates

## Testing

Run this software item's crate-local tests with:

```sh
cargo test -p conclave-controlplane-api
```

Coverage shape:

- Direct coverage
  - This crate's direct tests check that API types serialize and deserialize cleanly with managed-config payloads.
- Indirect coverage
  - `conclave-server` exercises these DTOs through request handling and response generation.
  - `conclave-cli` uses these DTOs in real request construction during local workflows.

## Behavior Notes

- This crate is intentionally a transport boundary, not a server-internal model crate.
- Shared DTOs here reduce drift between the server and Rust clients without forcing either side to share deeper internal state.

## Traceability And Related Docs

- [Platform spec](../../docs/spec/platform.md)
- [Managed configuration spec](../../docs/spec/managed-configuration.md)
- [Authentication and authorization spec](../../docs/spec/authn-and-authz.md)
- [Tokens and claims spec](../../docs/spec/tokens-and-claims.md)
- [Repository traceability guidance](../../docs/traceability-guidance.md)
- [Software-item README guidance](../../docs/software-item-readmes.md)
- [Project nomenclature](../../docs/nomenclature.md)
