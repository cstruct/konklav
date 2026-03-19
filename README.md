# Conclave

Conclave is a spec-driven identity and access management monorepo aimed at a federated, multi-tenant control plane. The shape is intentionally close to "Keycloak-esque", but biased toward clear tenancy boundaries, decentralized authorization decisions, and explicit traceability from requirement to code.

## Goals

- Multi-tenant identity, user, and organization management.
- Authentication and SSO flows that can span local and federated identities.
- IAM primitives that can support roles, permissions, policy, and delegation.
- Authorization data that can travel in JWTs or similar artifacts so downstream services can make decisions without a round-trip to a central policy engine for every request.
- A repo structure that stays workable as the project moves from hobby code to production concerns.

## Repository shape

This repo is organized around Tracey specifications:

- Specs live in `docs/spec/`.
- Shared terminology lives in `docs/nomenclature.md`.
- Rust implementation code lives in `items/`.
- Tracey configuration lives in `.config/tracey/config.styx`.

The repository keeps normative requirements in specs, shared vocabulary in nomenclature, and implementation code in workspace crates.

## Spec map

- `docs/nomenclature.md`: shared project terminology for subjects, operators, service principals, and relying systems.
- `docs/spec/platform.md`: repo shape, traceability, and server bootstrap.
- `docs/spec/managed-configuration.md`: declarative control-plane management, three-way reconciliation, and apply semantics.
- `docs/spec/tenancy-and-identity.md`: tenants, identities, memberships, and delegated tenant administration.
- `docs/spec/authn-and-authz.md`: sessions, SSO, actions, roles, policies, compiled authorization, and assumption flows.
- `docs/spec/tokens-and-claims.md`: JWT shape, authorization snapshots, and downstream token usage.
- `docs/spec/federation-and-protocols.md`: brokered identity, directory sync, OIDC, and SAML.

## Server

The server uses:

- `actix-web` as the HTTP framework
- `Styx` for typed local config in `config/server.styx`
- `Feldera` as an external incremental-compute dependency accessed over HTTP

This keeps the server on a thin client boundary to Feldera rather than coupling the control plane to embedded-database assumptions.

To run the server:

```bash
cargo run -p conclave-server
```

The server exposes three HTTP surfaces:

- control-plane surface
  - health and readiness
  - runtime metadata
  - managed configuration validate, plan, and apply
  - invite creation
- subject-facing surface
  - invite redemption
  - direct login
  - tenant assumption token issuance
  - token validation
- relying-system surface
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

See [items/server/src/http.rs](items/server/src/http.rs) for the route definitions and how they are split across the three surfaces.

Config defaults live in `config/server.styx`, and the managed playground data lives in the adjacent managed-config directory. Common local overrides include:

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
- `CONCLAVE_BOOTSTRAP_DISPLAY_NAME`
- `CONCLAVE_JWT_ISSUER`
- `CONCLAVE_JWT_DEFAULT_AUDIENCE`
- `CONCLAVE_JWT_SIGNING_KEY_ID`
- `CONCLAVE_JWT_SIGNING_SEED`
- `CONCLAVE_JWT_TTL_SECONDS`
- `CONCLAVE_FELDERA_ENABLED`
- `CONCLAVE_FELDERA_BASE_URL`
- `CONCLAVE_FELDERA_PIPELINE_PREFIX`
- `CONCLAVE_FELDERA_READINESS_PROBE`
- `CONCLAVE_FELDERA_API_KEY`
- `CONCLAVE_FELDERA_COMPILE_PROFILE`
- `CONCLAVE_FELDERA_AUTO_START`
- `CONCLAVE_FELDERA_START_INITIAL`

See [items/server/src/config.rs](items/server/src/config.rs) for the full set of startup overrides and default values.

The local development model is compile-first:

- the action catalog gets a system-managed revision and stable bit positions from config content
- export templates and assignable local roles are modeled separately
- template lineage is resolved locally, including deterministic selector-based overrides
- tenant-managed authz config can define `tenant:` and `sys:` actions, but not built-in `conclave:` control-plane capabilities
- Conclave control-plane capabilities are modeled separately from tenant-managed authz, with child-tenant assumption authorized through explicit assumption grants
- the root tenant and tenant tree are bootstrapped from config
- memberships compile tenant-local effective grants up front
- explicit parent-to-child assumption grants mint time-bounded target-tenant tokens
- JWTs carry a compact `az` snapshot with catalog revision, policy revision, tenant bits, scoped bits, and portable facts
- offline token validation checks signature, expiry, tenant context, current revisions, and optional scoped action access
- the compiled result is exposed over HTTP
- a Feldera SQL program is generated from that compiled state so we can iterate on schema and incremental views before wiring persistence

The Feldera integration can now also:

- compare the desired authz pipeline against a live Feldera pipeline
- report a sync plan
- create the pipeline if it does not exist
- patch it if it exists and is stopped
- refuse code updates while the remote pipeline is not stopped
- request pipeline start using the configured initial mode

The sample bundles to look at are:

- `config/authz.styx`: action catalog, export templates, and tenant-local roles
- `config/tenants.styx`: root tenant, child tenants, memberships, and delegated assumption grants
