# Konklav

Konklav is a standalone identity and access service. It owns subjects,
credentials, sessions, tokens, tenants, memberships, roles and policies.
Relying systems verify its tokens offline and get authorization decisions
through a small SDK that caches entitlements and keeps them fresh from a
change feed.

It is designed around:

- **clear tenancy boundaries:** a tenant tree in which a parent grants
  nothing implicitly
- **agnosticism:** actions, scope kinds, facts and session flags are catalog
  data; Konklav knows nothing about any relying system's domain
- **fast revocation without callbacks:** session and entitlement changes
  reach relying systems over SSE within about a second, and relying systems
  fall back to a central check API and fail closed when they can't keep up
- **traceability:** requirements live in Tracey-managed specs and are linked
  from code and tests

## Status

Milestones M0–M8 are done in code. The cutover itself is an operation the
relying system's runbook describes, and it remains: publish the Python
binding, ship the frontends, rehearse, switch over, then clean up.

Beyond the milestones, Konklav federates through OpenID Connect in both
directions:
- signing in through identity providers, with claim mapping
- acting as an OpenID provider, with client credentials, revocation and
  logout
- peering between Konklav instances
- workload tokens

See [OIDC and federation](docs/architecture/oidc-and-federation.md).

By milestone:

- M8: the relying system runs on Konklav behind a flag, and a cutover
  runbook lives in that system's repository. The integration covers:
  - token verification and decisions through the Python binding
  - a transactional sync of its admin writes to the control plane
  - invites that name their membership
  - secret-key rotation on re-import
  - retired sign-in routes
  - delivery
  - a legacy refresh exchange
- M7: a capability-gated bulk import of subjects, Argon2-hashed
  credentials, MFA seeds and sessions that keeps existing ids and can be
  re-run.
- M6: a control plane authorized by capabilities instead of a static token,
  with listings and entitlement explanations.
- M5: MFA, step-up, passwordless login, invites, password reset and change,
  impersonation, and delivery requests.
- M4: the change feed (SSE with resume, reset and batches) and the relying
  SDK: a sans-I/O core that also builds for wasm, with a native Rust client
  and a Python binding.
- M3: tenants and memberships with facts, the action catalog, templates,
  roles and assignments, entitlement compilation, tenant selection at
  login, session flags, and the entitlements and check APIs.
- M1–M2:
  - subjects, and credentials in one JSON-Schema-validated table
  - password and secret-key login
  - server-side sessions with refresh rotation and reuse detection
  - browser cookies with CSRF checks
  - Ed25519 tokens with JWKS
  - control-plane administration of all of the above

v1, a prototype backed by Feldera, is preserved at tag `v1`.

## Repository layout

- `docs/nomenclature.md`: the shared vocabulary. Read this first.
- `docs/spec/`: normative, Tracey-managed requirements.
- `docs/architecture/`: rationale and design notes, starting with
  [`v2-overview.md`](docs/architecture/v2-overview.md).
- `items/`: software items:
  - `core`: identifiers
  - `token`: claims, JWS, JWKS
  - `authn`: hashing, refresh tokens
  - `authz`: entitlement compilation and evaluation
  - `bootstrap`: reading bootstrap sets (CSV tables and Styx documents)
  - `store`: Postgres, migrations, repositories
  - `server`: the binary
  - `relying`: the sans-I/O relying core
  - `relying-client`: the native Rust host
  - `py`: the Python binding (maturin)
  - `console`: the operators' web UI (Leptos, WASM)
  - `test-support`: shared test helpers
- `config/`: development configuration.
- `examples/`: runnable examples that start real servers and that the tests
  also run (see [`examples/README.md`](examples/README.md)):
  - email-link sign-in, delivered over SMTP by a reference delivery worker
  - one Konklav signing people in to another
  - seeding a deployment with `bootstrap`
  - the example bootstrap sets, nested and flat
- `dev/`: local services for development.
- `.agents/`: agent skills and the planning standard.

## Development environment

[mise](https://mise.jdx.dev) manages the toolchain, the environment and the
local services. It covers Rust, Tracey and Diesel's CLI (which bundles libpq,
so no system Postgres client is needed).

```sh
mise trust && mise install
mise run db:up      # Postgres 18 with pg_jsonschema in Docker on localhost:55432
```

mise sets `DATABASE_URL`, `KONKLAV_CONFIG` and `KONKLAV_SECRETS` for the
local setup. Everyday tasks:

- `mise run serve` starts Postgres, migrates it and serves on ports 8080 to
  8082.
- `mise run console:serve` serves the operators' console on
  <http://127.0.0.1:8083> against that server. Trunk, installed by mise,
  builds it. `console:build` makes a release build. See
  [`items/console`](items/console/README.md).
- `mise run test` runs every test, each database test in its own database.
  OIDC interoperability tests run against independent implementations:
  - Ory Hydra, installed by mise, as an identity provider for Konklav
    (`items/server/tests/hydra.rs`; skipped if `hydra` isn't on the PATH)
  - the `openidconnect` client library against Konklav as an OpenID
    provider (`items/server/tests/openidconnect.rs`)
- `mise run example <name>` runs one of the examples in `examples/`, such as
  `smtp-delivery`, against servers it starts on fresh databases.
- `mise run hydra` runs Hydra in memory (public `:4444`, admin `:4445`) for
  trying identity-provider logins by hand.
- `mise run lint` checks formatting, clippy (warnings are errors, including
  for the console's WASM target), Tracey validation and the GitHub Actions
  workflows (actionlint).
- `mise run migrate` applies migrations; `mise run db:schema` regenerates the
  Diesel schema.
- `cargo run -p konklav-server -- bootstrap [--dry-run] <paths>` loads
  tenants, people and grants from CSV tables or Styx documents, for seeding
  a database or moving another system's data in. See
  [`items/bootstrap`](items/bootstrap/README.md).

Other database tasks:

- `db:down` stops Postgres and keeps its data.
- `db:reset` stops it and deletes the data.
- `db:status` shows its status.
- `db:logs` follows its logs.
- `db:psql` opens psql inside the container.

To use another port, set `KONKLAV_DEV_PG_PORT`, for example in an untracked
`mise.local.toml`.

## CI and releases

GitHub Actions runs `mise run lint` and `mise run test` on every push to
`main` and every pull request (`.github/workflows/ci.yml`), and checks that
the container image builds.

To release, set `version` under `[workspace.package]` in `Cargo.toml`, then
push a matching `v<version>` tag. The release workflow:

1. Runs CI again.
2. Builds `konklav-server` for x86_64 and aarch64 Linux and aarch64 macOS,
   and the console as a static bundle.
3. Pushes a linux/amd64 and linux/arm64 image to Docker Hub. The repository is
   the `DOCKERHUB_IMAGE` variable; the `deploy` environment holds
   `DOCKERHUB_USERNAME` and the `DOCKERHUB_TOKEN` secret.
4. Publishes a GitHub release with the archives and `SHA256SUMS`.

A version with a pre-release part, such as `0.2.0-rc.1`, makes a
pre-release, and its image gets only that exact tag.

The image runs `serve` as a non-root user. Mount `config.styx`,
`secrets.styx` and the key files they name at `/etc/konklav`:

```sh
docker run --rm -v ./deploy:/etc/konklav:ro konklav/konklav migrate
docker run -v ./deploy:/etc/konklav:ro -p 8080-8082:8080-8082 konklav/konklav
```

Konklav's schema needs PostgreSQL 18 with the
[`pg_jsonschema`](https://github.com/supabase/pg_jsonschema) extension;
`dev/postgres` builds such an image.

## Stack

- Rust, axum, tokio
- PostgreSQL via Diesel (`diesel-async`, embedded forward-only migrations)
- `ordna` for layered configuration with separate secrets
- Ed25519 JWTs published through JWKS
- pyo3 for the Python relying binding
- Leptos and Trunk for the console

## License

Konklav is licensed under the [MIT License](LICENSE).
