# konklav-api

Library crate for the transport types of Konklav's HTTP surfaces: the request and response bodies that the server and Konklav's own clients share, each with an OpenAPI schema.

So far it covers the whole control-plane surface (tenants, memberships, subjects, credentials, sessions, signing keys, the action catalog, templates, roles, role assignments, entitlements, explanations, shares, registered scopes, invites, OIDC clients and imports) and the error envelope every surface uses.

## Responsibilities

- Transport types that serialize and deserialize to the same JSON, such as `Tenant`, `Membership`, `MembershipDetail`, `TenantPage`, `CreateTenant` and `CreateMembership`.
- `CatalogDocument`, `Role`, `Template`, `AssignRole`, `ExplainDecision`, `Share`, `RegisteredScope` and the other authorization requests and responses.
- `CreateInvite`, `OidcClient`, `OidcClientDefinition` and the import records (`ImportedSubject`, `ImportedCredential`, `ImportedFactor`, `ImportedSession`).
- Re-exports of `konklav-authz`'s wire types, such as `Policy`, `Scope`, `Entitlements`, `Explanation`, `DecisionExplanation` and `Requirements`, which the relying core reads too. They aren't mirrored here, so both read one definition.
- `Written<T>`: a write's result together with its change-feed cursor.
- `ErrorCode`, `ErrorResponse` and `ErrorBody`: the stable error codes, each code's HTTP status, and the error envelope.
- OpenAPI schemas (utoipa `ToSchema` and `IntoParams`) for every type. The server builds its API document from them.

Out of scope:

- Storage models. These stay in `konklav-store`, and the server converts them to transport types at the boundary (`items/server/src/transport.rs`).
- HTTP clients and I/O of any kind.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-core` | Identifier and cursor types, with their schemas (`openapi` feature) |
| `konklav-authz` | Authorization wire types, re-exported with their schemas (`openapi` feature, which also enables `konklav-token`'s for `TokenKind`) |
| `konklav-server` | Returns these types and generates the control-plane API document from them |
| `konklav-cli` (planned) | Will read and write the control plane with these types |
| `konklav-control-plane` (planned, Python) | Generated from the API document, not from this crate |

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p konklav-api
```

- Direct coverage: round trips of the tenant, membership, subject, credential, session, signing-key, written and error types, the tagged `AssignmentTarget`, the catalog with its flattened groups, roles, templates, entitlements and explanations, shares with their flattened terms, registered-scope changes, invites, OIDC clients with their flattened definitions, imports with their tagged material, and the mapping from error codes to HTTP statuses.
- Indirect coverage: the server's integration-test harness checks every control-plane response it receives against the committed document, so a type that drifts from what a handler returns fails those tests. The server's `openapi` test fails when `items/server/openapi/control-plane.json` no longer matches these types. To rewrite the document after a deliberate change, run:

  ```sh
  KONKLAV_UPDATE_OPENAPI=1 cargo test -p konklav-server --lib openapi
  ```

## Traceability and related docs

- [Item spec](../../docs/spec/software-items/api.md)
- [Platform spec](../../docs/spec/platform.md) (errors and write cursors)
- [Nomenclature](../../docs/nomenclature.md) (`transport types`, `API document`)
