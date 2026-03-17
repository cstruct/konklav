# Conclave

Conclave is a spec-driven identity and access management monorepo aimed at a federated, multi-tenant control plane. The shape is intentionally close to "Keycloak-esque", but biased toward clear tenancy boundaries, decentralized authorization decisions, and explicit traceability from requirement to code.

## Goals

- Multi-tenant identity, user, and organization management.
- Authentication and SSO flows that can span local and federated identities.
- IAM primitives that can support roles, permissions, policy, and delegation.
- Authorization data that can travel in JWTs or similar artifacts so downstream services can make decisions without a round-trip to a central policy engine for every request.
- A repo structure that stays workable as the project moves from hobby code to production concerns.

## Working model

This repo is set up to be driven by Tracey specifications:

- Specs live in `docs/spec/`.
- Shared terminology lives in `docs/nomenclature.md`.
- Rust implementation code lives in `crates/`.
- Tracey configuration lives in `.config/tracey/config.styx`.

The current scaffold is intentionally thin. The first implementation target is a Rust server component in `crates/server`, while the specifications establish the initial problem boundaries before deeper design and code land.

## Initial spec map

- `docs/nomenclature.md`: shared project terminology for subjects, operators, service principals, and relying systems.
- `docs/spec/platform.md`: repo shape, traceability, and server bootstrap.
- `docs/spec/managed-configuration.md`: declarative control-plane management, three-way reconciliation, and apply semantics.
- `docs/spec/tenancy-and-identity.md`: tenants, identities, memberships, and delegated tenant administration.
- `docs/spec/authn-and-authz.md`: sessions, SSO, actions, roles, policies, compiled authorization, and assumption flows.
- `docs/spec/tokens-and-claims.md`: JWT shape, authorization snapshots, and downstream token usage.
- `docs/spec/federation-and-protocols.md`: brokered identity, directory sync, OIDC, and SAML.

## Server sandbox

The first server slice now uses:

- `actix-web` as the HTTP framework
- `Styx` for typed local config in `config/server.styx`
- `Feldera` as an external incremental-compute dependency accessed over HTTP

This is deliberate. Feldera looks more like a control-plane managed dataflow engine than an embedded Rust database, so the server starts with a thin client boundary instead of coupling the app to assumptions that are likely wrong.

To run the server:

```bash
cargo run -p conclave-server
```

Useful endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /v1/meta`
- `GET /v1/meta/config-schema`
- `GET /v1/meta/authz-schema`
- `GET /v1/meta/tenant-schema`
- `GET /v1/authz/catalog`
- `GET /v1/authz/managed`
- `GET /v1/authz/templates`
- `GET /v1/authz/roles`
- `GET /v1/conclave/capabilities`
- `GET /v1/tenants`
- `GET /v1/tenants/managed`
- `GET /v1/tenants/memberships`
- `GET /v1/tenants/assumptions`
- `POST /v1/auth/tokens/direct`
- `POST /v1/auth/tokens/assume`
- `POST /v1/auth/tokens/validate`
- `GET /v1/feldera/sql/authz`
- `GET /v1/feldera/authz/plan`
- `GET /v1/feldera/authz/status`
- `POST /v1/feldera/authz/sync`
- `POST /v1/feldera/authz/start`
- `GET /v1/feldera/pipelines`

Config defaults live in `config/server.styx`, and the managed authz playground data lives in `config/authz.styx`. For local overrides, set:

- `CONCLAVE_CONFIG`
- `CONCLAVE_SERVER_HOST`
- `CONCLAVE_SERVER_PORT`
- `CONCLAVE_JWT_ISSUER`
- `CONCLAVE_JWT_DEFAULT_AUDIENCE`
- `CONCLAVE_JWT_SIGNING_SECRET`
- `CONCLAVE_JWT_TTL_SECONDS`
- `CONCLAVE_AUTHZ_CONFIG`
- `CONCLAVE_TENANTS_CONFIG`
- `CONCLAVE_FELDERA_ENABLED`
- `CONCLAVE_FELDERA_BASE_URL`
- `CONCLAVE_FELDERA_API_KEY`
- `CONCLAVE_FELDERA_COMPILE_PROFILE`
- `CONCLAVE_FELDERA_AUTO_START`
- `CONCLAVE_FELDERA_START_INITIAL`

The current playground is intentionally compile-first:

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

## Suggested next steps

1. Add plan/apply semantics for the tenant bundle instead of treating it as static bootstrap data.
2. Push compiled tenant grants into Feldera the same way the authz catalog, templates, and roles are now projected.
3. Replace raw role-key membership assignment with explicit role/assignment storage once the runtime model settles.
4. Extend the token model into actual issuer keys and JWKS instead of the current development HS256 secret.
