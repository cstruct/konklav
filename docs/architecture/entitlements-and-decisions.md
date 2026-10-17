# Entitlements and decisions

## Entitlement set

```
EntitlementSet {
  subject, tenant, revision,
  global:  Set<Action>,                  // from global assignments
  tenant:  Set<Action>,                  // tenant-wide in `tenant`
  scoped:  Map<(ScopeKind, ScopeId), Set<Action>>,
}
```

## Compilation

`conclave-authz` is a pure function from rows to entitlement sets.

1. Collect the active assignments of the subject: global assignments, plus
   the membership's assignments in the tenant.
2. For each role, resolve its effective policies: the template's policies,
   overridden per action by the role's own policies.
3. Expand action groups.
4. Place each policy at a level:
   - global, for a global role
   - tenant-wide, for a tenant-wide assignment, or for a policy that is not
     scope-bound
   - the assignment's scope, for a scope-bound policy on a scoped assignment
5. For each (level, action), keep the policy from the highest-priority role.
   At equal priority, deny wins.
6. Remove denied actions.
7. Remove actions already granted at a higher level (global, then tenant).

Steps 5–7 reproduce the semantics that existing relying systems commonly
implement with a ranked SQL view plus deny subtraction in application code.
Golden tests pin them. A specificity-ordered precedence model (from v1) can
be offered later as an explicit catalog option.

Open detail, to settle with golden tests before implementation: whether a
deny at a higher level also removes allows at lower levels, or only the
same action at the same level.

## Decision path in the relying SDK

```
token ──verify (JWKS)──▶ claims
        │
        ├─ session (sid, sv) ── cached state from `session.changed`
        │
        ├─ entitlements (sub, tid) ── cache ── miss/stale ─▶ GET /v1/entitlements
        │
        └─ evaluate requirements locally
              actions ⊆ granted per level and scope
              token kind allowed
              restrictive flags admitted, assertive flags present
              step-up (amr count/set, auth_time age)
```

When the cache is untrusted (feed lagging or disconnected), every decision
goes to `POST /v1/check`. Without Conclave, the result is deny.

## Cache freshness

- TTL is 15 minutes. That bound only matters if the feed silently misses
  events, which `reset` handling is designed to prevent.
- Debounced background refresh (500 ms window, coalesced per key) keeps busy
  entries warm and turns bursts of events into one fetch.
- An invalidated entry is usable only within the debounce window, so a
  removed grant stays effective for at most about 1 s (window plus fetch).
- `session.changed` events apply immediately.
- Read-your-writes: control-plane responses include the cursor they
  produced. The relying system calls `await_cursor(c)`, and the SDK blocks
  until it has applied the events up to `c` and synchronously refreshed the
  entries they invalidated.

## Why not snapshots in tokens

Tokens in v1 carried compiled bitsets (`az`). That suits relying systems
which tolerate token-lifetime staleness and have few scopes per subject.
v2 targets systems that need revocation within seconds and subjects with
many scopes, so grants travel separately and the token stays small. Adding
an optional snapshot claim later for low-stakes relying systems would not
conflict with this design.
