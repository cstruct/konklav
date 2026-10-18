# Conclave v2 overview

Status: accepted as direction for v2. This note is not normative; the specs
in `docs/spec/` are.

## Why v2

v1 (tag `v1`) proved the domain model and the vocabulary, but three choices
made it hard to finish and hard to adopt:

- **Feldera as the authoritative store.** Append-only temporal tables,
  publish barriers and experimental transactions dominated the design.
  Testing needed a fake pipeline manager, and real-pipeline tests never
  landed.
- **Grant snapshots in access tokens (`az`).** Offline decisions are cheap,
  but grants then stay stale for the token's lifetime and tokens grow with
  the number of scopes. Relying systems that need fast revocation still had
  to call back.
- **Scope drift.** The history ended with a general-purpose configuration
  library. That work now lives in `ordna`, which v2 uses.

v2 keeps the vocabulary and the ideas that held up: subjects, tenants as a
tree with no implicit parent access, memberships, templates and roles,
compiled entitlements, actor chains, Ed25519 keys published through JWKS,
and spec-first development with Tracey.

## Decisions

| Area | v2 decision | Note |
|---|---|---|
| Storage | Postgres owned by Conclave, accessed with Diesel (`diesel-async`) | [storage](storage.md) |
| HTTP | axum, one binary, three separately routable surfaces | |
| Config | `ordna`, Styx files with secrets kept separate | |
| Tokens | Ed25519 JWTs that carry session data but no grants | [sessions and tokens](sessions-and-tokens.md) |
| Decisions | Relying SDK with a local entitlement cache, invalidated by the change feed, with the check API as fallback; fails closed | [entitlements and decisions](entitlements-and-decisions.md) |
| Feed | Transactional outbox served over SSE, resumable by cursor | [change feed](change-feed.md) |
| Relying SDK | Sans-I/O Rust core; pyo3 binding first, wasm later | [relying SDK](relying-sdk.md) |
| Tenants | Conclave is authoritative; relying systems keep projections | [tenant projections](tenant-projections.md) |
| Messaging | Conclave emits delivery requests; relying systems send the messages | [change feed](change-feed.md) |
| Federation | OIDC in both roles (identity providers and OpenID provider) with claim mapping; Conclave instances federate, optionally peering through the change feed | [OIDC and federation](oidc-and-federation.md), [proof of possession](proof-of-possession.md) |
| Managed config | Deferred; catalog and templates go through the control-plane API first | |

## Software items

| Item | Responsibility |
|---|---|
| `conclave-core` | Identifiers, nomenclature types, action names and selectors |
| `conclave-store` | Diesel schema, migrations, repositories, event outbox |
| `conclave-authz` | Pure compilation of entitlement sets and evaluation of requirements |
| `conclave-token` | Access-token claims, EdDSA JWS signing and verification, JWKS (shared by the issuer and the relying core) |
| `conclave-authn` | Password and secret-key hashing, refresh tokens; TOTP and challenges later |
| `conclave-server` | axum surfaces, wiring, background workers |
| `conclave-relying` | Sans-I/O relying core |
| `conclave-relying-client` | Native Rust host binding (reqwest + tokio) |
| `conclave-py` | pyo3 host binding |
| `conclave-cli` | Admin tooling and importers |

Dependencies point inward: `server` → `authn`/`authz`/`store` → `core`.
`relying` depends only on `core`, `token` and `authz` (for evaluation), and
the bindings depend only on `relying`.

The control-plane surface is authorized by built-in `konklav:`
capabilities that operators hold through global roles:

- `konklav:control:all`, or one per area: `subjects`, `tenants`, `authz`,
  `sessions`, `keys`, `invites`
- `konklav:subject:impersonate` and `konklav:delivery:read` for the
  matching flows

An optional bootstrap token from the secrets file is accepted for
everything. It exists to create the first operator and should then be
removed.

## Adoption path for an existing relying system

A relying system that already has its own authentication and authorization
typically adopts Conclave like this:

1. Introduce narrow ports in front of its current implementation.
2. Switch to asymmetric tokens.
3. Import its data with a one-off importer that preserves identifiers.
4. Replay a recorded corpus of decisions against the check API until there
   are no diffs.
5. Switch the ports over to Conclave.

Conclave's side of this is the import API (`/v1/import/*`, capability
`konklav:import`) plus the idempotent control-plane endpoints. Mapping
the relying system's tables onto them, and comparing its access decisions
with Conclave's entitlement sets, belongs in that system's own tooling.

Compilation semantics are pinned by golden tests
(`r[authz.compile.reference-semantics]`) so that a zero-diff replay stays
meaningful.
