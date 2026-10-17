# conclave-core

Library crate with the identifiers and small value types that several Conclave software items have to agree on.

## Responsibilities

- Typed UUID identifiers: `TenantId`, `SubjectId`, `MembershipId`, `SessionId`. They are time-ordered (UUID v7) when generated.
- `Cursor`, the position of an event in the change feed.

It doesn't own domain models, persistence types or HTTP DTOs. Those stay with the software item that owns them.

## Relationships

| Software item | Relationship |
|---|---|
| `conclave-store` | Uses these identifiers in repositories |
| `conclave-server` | Uses them at the HTTP boundary (from M2) |

## Running

This is a library and can't run on its own. It is exercised through its dependents.

## Testing

```sh
cargo test -p conclave-core
```

- Direct coverage: identifier round-trips, serde shape and ordering.
- Indirect coverage: the store and server tests.

## Traceability and related docs

- [Nomenclature](../../docs/nomenclature.md)
- [v2 overview](../../docs/architecture/v2-overview.md)
