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
  - The set carries the catalog's vouches for the vouching actions it grants, with groups expanded. A vouch grants nothing by itself.
- `evaluate`: decides `Requirements` (token kinds, actions per level and scope, restrictive and assertive session flags, step-up, tenant facts) to `Allow`, `Deny { reason }` or `StepUp { requirement }`.
  - Requirements at registered scopes are decided from `RegisteredScopes`, the records the caller resolved: in the scope's own tenant, from grants tenant-wide, at the scope or at any one of its containing scopes; from another tenant, only through shares of those. Unknown or removed scopes deny with `unknown_scope`.
  - Confined flags are decided from `Confinements`, the catalog's confinements with the tenant's current portable facts: a confined session whose tenant doesn't match, or whose token targets no tenant, denies with `confined_session`, whatever the operation admits or the session holds globally.
  - Tenant fact requirements (`{"tenant_facts": {"tenant_type": ["client"]}}`) match the same facts the way confinements do, and deny with `tenant_facts` naming the first failing predicate, also for a token without a tenant. Reading them refuses predicates without values or with values that aren't strings, integers or booleans, without consulting the catalog, so the check API and the relying core refuse the same ones.
- `evaluate_with_route_authority`: `evaluate` for a request's later decisions, made with the `RouteAuthority` its allowed route decision vouched for. An allow names what it vouches for, per placement where a vouching action was required, and never at another tenant's scope. A decision made with route authority counts a covered action as granted, whatever the set holds or denies: global covers every placement, tenant-wide the tenant and its scopes, and a scope itself and the registered scopes recorded in it. Every other check is made as usual, and such an allow vouches for nothing.
- `explain_decision`: explains a decision for the control plane. Given the route's requirements as `ExplainInput::route`, it explains a later decision of a request: the route decision and what it vouches for (`RouteExplanation`), and each action the route authority grants as `Reason::Vouched`, naming the vouching action, where the route required it and why it would be granted or not without it.
- The wire types the control plane returns or accepts, such as `Policy`, `Entitlements`, `Explanation`, `DecisionExplanation` and `Requirements`, describe themselves as OpenAPI schemas with the optional `openapi` feature. Relying systems don't need it.

The server compiles; relying systems evaluate locally (M4) using the same `evaluate`, so local and central decisions agree.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-token` | `AccessClaims` and `TokenKind` in evaluation |
| `konklav-store` | Loads compile input (`compile_input`) and catalog types |
| `konklav-server` | Serves entitlement sets and the check API |
| `konklav-api` | Re-exports the wire types with their schemas (`openapi` feature) |
| `konklav-relying` (planned) | Evaluates locally |

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p konklav-authz
```

- Direct coverage:
  - golden compilation cases pinning precedence, deny levels, scope binding, subsumption, template overrides and group expansion
  - route authority: compiled vouches, what allows vouch for, coverage per placement and for contained registered scopes, the deny override and non-transitivity, and their explanations (`tests/route_authority.rs`)
  - evaluation of actions, token kinds, flags and step-up
- Indirect coverage: the server's check-equivalence test compares local evaluation with `/v1/check`.

## Traceability and related docs

- [Authorization spec](../../docs/spec/authorization.md) and [item spec](../../docs/spec/software-items/authz.md)
- [Entitlements and decisions](../../docs/architecture/entitlements-and-decisions.md)
- [Nomenclature](../../docs/nomenclature.md)
