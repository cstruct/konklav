# Core

`conclave-core` is the Rust crate that holds the smallest stable set of shared Conclave value types.

Today it is intentionally tiny: it provides common aliases for identifiers, keys, revisions, and a shared error type so the rest of the workspace can share basic vocabulary without collapsing into one large catch-all model crate.

## Responsibilities

- Define stable shared aliases for common Conclave identifiers and revisions.
- Provide a lightweight shared error type alias used across workspace crates.
- Keep the shared foundation small enough that domain models stay owned by the software items that actually use them.

Out of scope:

- owning transport DTOs
- owning full managed-config trees
- owning compiled authorization or tenant models

## Public Interface

Primary entry point:

- `src/lib.rs`
  - Defines the shared type aliases exported by this crate.

Current shared aliases include:

- `DynError`
- `ActionName`
- `CatalogRevision`
- `PolicyRevision`
- `RoleKey`
- `ScopeId`
- `ScopeKind`
- `SubjectId`
- `TemplateKey`
- `TenantId`

See [`src/lib.rs`](src/lib.rs) for the current alias set.

## Relationships

### Dependency Summary

| Software item | Relationship |
| --- | --- |
| None | This crate is intentionally dependency-free inside the workspace. |

### Dependent Summary

| Software item | Relationship |
| --- | --- |
| `conclave-managed-config` | Reuses shared IDs, keys, and revision-like aliases in the managed desired-state model. |
| `conclave-controlplane-api` | Reuses stable shared value types in transport DTOs. |
| `conclave-relying-auth` | Reuses shared IDs, action names, and revision aliases in token and verification types. |
| `conclave-server` | Reuses shared values across config, auth, tenancy, and managed-state code. |

## Usage

Use `conclave-core` when multiple software items need the same stable value type.

```rust
use conclave_core::{CatalogRevision, TenantId};

let tenant_id: TenantId = "tenant-a".to_owned();
let revision: CatalogRevision = 4;
```

## Running

This software item is a library crate and is not run directly as its own process.

It is exercised through every downstream workspace crate that reuses its shared aliases.

## Testing

Run this software item's crate-local tests with:

```sh
cargo test -p conclave-core
```

Coverage shape:

- Direct coverage
  - This crate currently has no crate-local test cases.
  - Its surface is intentionally limited to shared type aliases.
- Indirect coverage
  - Every downstream workspace crate compiles and exercises these aliases as part of its own tests and runtime paths.

## Behavior Notes

- This crate is intentionally small by design.
- If a representation is domain-specific, it should usually stay with the software item that owns that domain rather than move into `conclave-core`.

## Traceability And Related Docs

- [Platform spec](../../docs/spec/platform.md)
- [Repository traceability guidance](../../docs/traceability-guidance.md)
- [Software-item README guidance](../../docs/software-item-readmes.md)
- [Project nomenclature](../../docs/nomenclature.md)
