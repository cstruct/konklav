# konklav-authz

Library crate for Konklav authorization without I/O. It compiles role assignments into entitlement sets, and evaluates an operation's requirements against a token and an entitlement set.

## Responsibilities

- `compile`: turns active assignments (global, tenant-wide, scoped), together with role and template policies and the catalog's action groups, into `Entitlements`.
  - A role's policy overrides its template's policy for the same action.
  - Scope-bound policies stay at the assignment's scope.
  - Groups expand to their members and their own name.
  - The highest priority wins, and deny wins ties.
  - A deny only cancels allows at its own level.
  - Higher levels subsume lower ones.
- `evaluate`: decides `Requirements` (token kinds, actions per level and scope, restrictive and assertive session flags, step-up) to `Allow`, `Deny { reason }` or `StepUp { requirement }`.

The server compiles; relying systems evaluate locally (M4) using the same `evaluate`, so local and central decisions agree.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-token` | `AccessClaims` and `TokenKind` in evaluation |
| `konklav-store` | Loads compile input (`compile_input`) and catalog types |
| `konklav-server` | Serves entitlement sets and the check API |
| `konklav-relying` (planned) | Evaluates locally |

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p konklav-authz
```

- Direct coverage:
  - golden compilation cases pinning precedence, deny levels, scope binding, subsumption, template overrides and group expansion
  - evaluation of actions, token kinds, flags and step-up
- Indirect coverage: the server's check-equivalence test compares local evaluation with `/v1/check`.

## Traceability and related docs

- [Authorization spec](../../docs/spec/authorization.md)
- [Entitlements and decisions](../../docs/architecture/entitlements-and-decisions.md)
- [Nomenclature](../../docs/nomenclature.md)
