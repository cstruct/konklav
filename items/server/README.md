# Server

`conclave-server` is the server that runs the Conclave control plane.

It loads server and managed configuration, bootstraps runtime state, exposes the control-plane, subject-facing, and relying-system HTTP surfaces, and coordinates managed-state and runtime-auth flows.

## Responsibilities

- Start the authoritative Conclave control-plane runtime.
- Load typed server config and managed configuration during startup.
- Expose the three HTTP surfaces used by operators, subjects, and relying systems.
- Compile and serve current authorization and tenant state.
- Reconcile managed configuration through validate, plan, and apply operations.
- Bootstrap and reload persisted state through the Feldera-backed managed store when enabled.
- Issue, validate, and publish JWT-related artifacts needed by Conclave subjects and relying systems.

Out of scope:

- defining operator-facing managed-config input types
- acting as the offline JWT validation library for relying systems
- replacing the CLI as the primary operator interface for local workflow ergonomics

## Public Interface

Primary entry points:

- `src/main.rs`
  - Starts the runtime, loads config, loads managed state, and binds the three HTTP surfaces.
- `src/config.rs`
  - Defines the typed server config, startup overrides, and schema generation for server config.
- `src/http.rs`
  - Defines the HTTP routes and splits them across the three server surfaces.

HTTP surface overview:

- Control-plane surface
  - health and readiness
  - runtime metadata
  - managed configuration validate, plan, and apply
  - invite creation
- Subject-facing surface
  - invite redemption
  - login
  - assumed tenant token issuance
  - token validation
- Relying-system surface
  - revision discovery
  - action-catalog lookup
  - JWKS publication

Representative endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /v1/meta`
- `POST /v1/managed/validate`
- `POST /v1/managed/plan`
- `POST /v1/managed/apply`
- `POST /v1/invites`
- `POST /v1/invites/redeem`
- `POST /v1/login`
- `POST /v1/auth/tokens/assume`
- `POST /v1/auth/tokens/validate`
- `GET /v1/revisions`
- `GET /v1/authz/catalog`
- `GET /.well-known/jwks.json`

See [`src/http.rs`](src/http.rs) for the route definitions.

## Relationships

### Dependency Summary

| Software item | Relationship |
| --- | --- |
| `conclave-controlplane-api` | Provides shared request and response types for the control-plane HTTP contract. |
| `conclave-core` | Provides shared value types used across config, auth, tenancy, and managed state. |
| `conclave-managed-config` | Provides the managed desired-state model and directory-loading support used at startup and during validate, plan, and apply workflows. |
| `conclave-relying-auth` | Provides JWT signing, verification, JWKS publication, and action-catalog response types used by the relying-system surface. |
| `Feldera manager` | Acts as the authoritative persisted store for managed control-plane state when the Feldera-backed mode is enabled. |

### Dependent Summary

| Software item | Relationship |
| --- | --- |
| `conclave-cli` | Talks to this server's control-plane surface for validate, plan, apply, and invite workflows. |
| External relying systems | Use the relying-system surface for JWKS, revision metadata, and action-catalog metadata needed for offline token evaluation. |
| External subjects and operators | Interact with the subject-facing and control-plane surfaces for login, invite redemption, and managed operations. |

## Running

Run the server with:

```sh
cargo run -p conclave-server
```

By default the server loads:

- server config from `config/server.styx`
- managed configuration from the config file's adjacent managed-config directory, which is `config/` by default

Common startup overrides:

- `CONCLAVE_CONFIG`
- `CONCLAVE_MANAGED_DIR`
- `CONCLAVE_CONTROL_PLANE_HOST`
- `CONCLAVE_CONTROL_PLANE_PORT`
- `CONCLAVE_SUBJECT_HOST`
- `CONCLAVE_SUBJECT_PORT`
- `CONCLAVE_RELYING_HOST`
- `CONCLAVE_RELYING_PORT`
- `CONCLAVE_BOOTSTRAP_SUBJECT`
- `CONCLAVE_BOOTSTRAP_TOKEN`
- `CONCLAVE_JWT_ISSUER`
- `CONCLAVE_JWT_DEFAULT_AUDIENCE`
- `CONCLAVE_JWT_SIGNING_PRIVATE_KEY`
- `CONCLAVE_JWT_TTL_SECONDS`
- `CONCLAVE_FELDERA_ENABLED`
- `CONCLAVE_FELDERA_BASE_URL`
- `CONCLAVE_FELDERA_PIPELINE_PREFIX`
- `CONCLAVE_FELDERA_READINESS_PROBE`
- `CONCLAVE_FELDERA_API_KEY`
- `CONCLAVE_FELDERA_COMPILE_PROFILE`
- `CONCLAVE_FELDERA_AUTO_START`
- `CONCLAVE_FELDERA_START_INITIAL`

See [`src/config.rs`](src/config.rs) for the full set of startup overrides and default values.

## Testing

Run the default server test suite with:

```sh
cargo test -p conclave-server
```

Run the ignored live-Feldera tests with:

```sh
CONCLAVE_COMPONENT_FELDERA_URL=http://127.0.0.1:18080 cargo test -p conclave-server -- --ignored
```

Coverage shape:

- Direct coverage
  - unit-style tests for config loading, control-plane state, authz compilation, tenant compilation, Feldera SQL and pipeline sync behavior, and the Feldera-backed managed store
  - `actix-web` tests for control-plane, subject-facing, and relying-system HTTP flows
- Indirect coverage
  - `conclave-cli` exercises the control-plane surface during managed-config workflows
  - repository-level examples and local development flows exercise server startup against the default `config/*.styx` files

## Behavior Notes

- The server always binds three separate HTTP surfaces even when they run in one process.
- Startup loads managed configuration before the runtime begins serving requests.
- When Feldera-backed managed state is enabled, the server bootstraps the store if empty and then treats Feldera as the authoritative persisted source of managed state.
- In Feldera-backed mode, relying-system revision metadata, action-catalog reads, and effective-grant reads come from the Feldera authz pipeline and fail closed if that compiled state is unavailable.
- In Feldera-backed mode, JWKS publication and server-side JWT validation read persisted signing keys from the control-plane store rather than trusting only the active in-memory signer.
- `readyz` can optionally perform a live Feldera manager reachability check when readiness probing is enabled.

## Traceability And Related Docs

- [Platform spec](../../docs/spec/platform.md)
- [Managed configuration spec](../../docs/spec/managed-configuration.md)
- [Feldera control-plane architecture](../../docs/architecture/feldera-control-plane.md)
- [Typed temporal store note](../../docs/architecture/typed-temporal-store.md)
- [Repository traceability guidance](../../docs/traceability-guidance.md)
- [Software-item README guidance](../../docs/software-item-readmes.md)
- [Project nomenclature](../../docs/nomenclature.md)
