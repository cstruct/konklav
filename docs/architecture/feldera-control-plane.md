# Feldera Control-Plane Architecture

This note describes the first end-to-end operator and subject flow that uses Feldera-backed managed state together with Conclave control-plane APIs.

## Surfaces

- `control-plane`
  - Used by operators and the CLI for validation, planning, apply, and invite creation.
- `subject`
  - Used for invite redemption, login, and delegated tenant assumption.
- `relying-system`
  - Used for JWKS publication, current revision metadata, and action-catalog metadata needed for offline JWT authorization.

## State model

The first persisted-state model is temporal and append-only:

- every logical mutation belongs to one `apply_id`
- every durable row records `valid_from`, `valid_to`, `row_version`, and audit metadata
- current-state projections only consider committed rows
- history remains introspectible rather than being rewritten in place
- the server may keep an in-memory runtime cache, but Feldera is the authoritative persisted store for managed control-plane state in this phase

When the control-plane store is empty, the server bootstraps it from the managed configuration directory at startup. On later restarts, the server reloads managed state from Feldera instead of treating the local managed directory as the source of truth. This keeps the initial operator and subject flow testable without requiring the CLI to run first.

## Atomic visibility

Logical apply atomicity is modeled with a publish barrier:

1. stage all rows with a shared `apply_id`
2. validate compilation against the staged state
3. publish the `apply_id`
4. current-state projections switch visibility from the previous committed state to the new committed state

This allows the control-plane model, subject flows, and relying-system metadata to observe one coherent state transition.
