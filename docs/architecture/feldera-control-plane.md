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

Invite records, linked local credentials, and tenant-aware sessions follow the same persisted-history approach even though they are not declarative managed resources. This keeps the initial subject lifecycle auditable and restart-safe while preserving a clear separation between managed desired state and runtime-auth state.

## Managed read model

Managed control-plane reads use Feldera as the authority when the Feldera-backed store is enabled:

- request-time managed snapshots load from typed `current_*` Feldera views
- compiled authorization and tenant projections are derived from those loaded rows
- revision metadata, action-catalog reads, and `effective_grants` reads use the Feldera authz pipeline as the authoritative source once the server has refreshed that pipeline on startup or after managed apply
- server-local runtime-auth state remains in memory only for invite, credential, and session mutation planning
- the server does not keep an authoritative in-memory managed mirror in Feldera mode
- the in-memory managed fallback exists only when Feldera is disabled, and compiled-authz request paths fail closed rather than rebuilding a Rust snapshot when the Feldera authz pipeline is missing or stale

This keeps the in-process state bounded to the runtime-auth working set while still allowing request handlers to compile the derived models they need. The current implementation does not keep a derived managed snapshot cache in Feldera mode, so managed read freshness comes from read-through loading rather than cache invalidation. If a derived managed snapshot cache is introduced later, it must remain bounded, non-authoritative, and invalidated by the latest committed `apply_id`.

## Atomic visibility

Logical apply atomicity is modeled with a publish barrier:

1. stage all rows with a shared `apply_id`
2. validate compilation against the staged state
3. publish the `apply_id`
4. current-state projections switch visibility from the previous committed state to the new committed state

This allows the control-plane model, subject flows, and relying-system metadata to observe one coherent state transition.
