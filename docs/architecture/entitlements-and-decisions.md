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

`konklav-authz` is a pure function from rows to entitlement sets.

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
Golden tests in `items/authz/tests/golden.rs` pin them. A specificity-ordered
precedence model (from v1) can be offered later as an explicit catalog
option.

Decided details:

- Ranking is per placement and action, so priorities never compete across
  levels.
- A deny cancels allows only at its own placement
  (`r[authz.compile.deny-level]`).
- Overrides match a role policy against template policies by the
  unexpanded name. A role denying one action does not replace a template's
  group; both apply, and the deny wins only where it ties or outranks.
- Groups grant their own name, because existing relying systems require
  names such as `sys:all` directly.
- Groups expand the same way at every level. The reference model expanded
  only `sys:all` for global roles. Global roles never used `tenant:all`
  there, so importers should flag that case rather than reproduce it.

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
goes to `POST /v1/check`. Without Konklav, the result is deny.

## Compiling on read, invalidating by trigger

Entitlement sets are compiled on demand: one repeatable-read transaction
loads the subject's active assignments, the role, template and catalog
definitions, and the newest event cursor (the set's revision).

Invalidation is reactive. Database triggers append `entitlements.changed`
in the writing transaction:

- row triggers on memberships, role assignments and subject state name the
  affected subject (and tenant)
- statement triggers on catalog, template and role tables invalidate
  everything
- tenant state changes invalidate the tenant

Triggers mean no write path can skip invalidation, including bulk SQL from
importers. Compiling inside triggers was rejected: it would duplicate the
precedence rules in PL/pgSQL, and fan definition changes out to every
affected subject inside the admin transaction. If compile cost ever
matters, a worker fed by the outbox can materialize sets asynchronously
with the same Rust compiler.

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
