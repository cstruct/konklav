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

## Quickstart

This runs Konklav locally, opens the operators' console and creates the
first operator. You need [mise](https://mise.jdx.dev), Docker and the
OpenSSL headers (for example `brew install openssl@3`).

1. Install the toolchain and start the server:

   ```sh
   mise trust && mise install
   mise run serve
   ```

   This starts Postgres in Docker, applies migrations, creates a development
   signing key and serves the three surfaces:
   - subject-facing on `127.0.0.1:8080`
   - relying on `:8081`
   - control-plane on `:8082`

2. In a second terminal, start the console:

   ```sh
   mise run console:serve
   ```

   Open <http://localhost:8083>. Use `localhost` rather than `127.0.0.1`,
   because passkeys don't work on IP addresses.

3. Sign in with the bootstrap token. The development one is
   `control.bootstrap_token` in
   [`config/dev.secrets.styx`](config/dev.secrets.styx). The control plane
   accepts it for everything, and it is only meant for creating the first
   operator.

4. Create the first operator, a human subject with a password credential
   and the built-in `konklav.admin` global role. You can do this in the
   console, or with the control-plane API:

   ```sh
   TOKEN=konklav-dev-control-token-0123456789
   ID=$(uuidgen | tr A-Z a-z)
   curl -X PUT localhost:8082/v1/subjects/$ID \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"kind": "human"}'
   curl -X POST localhost:8082/v1/subjects/$ID/credentials \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"kind": "password", "identifier": "ada@example.com", "password": "correct horse"}'
   curl -X POST localhost:8082/v1/subjects/$ID/global-assignments \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"role": "konklav.admin"}'
   ```

   A `409` means the identifier is already taken in your database. Pick
   another, or start over with an empty database with `mise run db:reset`.

5. Sign out of the console and sign in again as `ada@example.com`. To get
   an access token without the console:

   ```sh
   curl -X POST localhost:8080/v1/login/password \
     -H 'Content-Type: application/json' \
     -d '{"identifier": "ada@example.com", "password": "correct horse"}'
   ```

   In a real deployment, remove the bootstrap token from the secrets file
   once an operator exists.

To start from a populated database instead, seed it with the example
bootstrap set:

```sh
cargo run -p konklav-server -- bootstrap examples/bootstrap/nested/seed.styx
```

## Where next

- **Vocabulary:** [`docs/nomenclature.md`](docs/nomenclature.md) defines
  subjects, tenants, memberships, roles, entitlement sets and the rest.
  Konklav's docs and APIs use these terms precisely.
- **How it fits together:** the
  [v2 overview](docs/architecture/v2-overview.md), then the other notes in
  [`docs/architecture/`](docs/architecture/).
- **Runnable scenarios:** [`examples/`](examples/README.md) has email-link
  sign-in with a delivery worker, one Konklav signing people in to another,
  and seeding a deployment. Run one with `mise run example <name>`.
- **Integrating a relying system:** the relying SDK, as the
  [Python binding](items/py/README.md) or the
  [native Rust client](items/relying-client/README.md), on top of the
  [relying core](items/relying/README.md).
- **Operating it:** the [server](items/server/README.md) (commands,
  configuration, every endpoint), the [console](items/console/README.md),
  and [bootstrap sets](items/bootstrap/README.md) for seeding and
  importing.
- **Federation:** [OIDC and federation](docs/architecture/oidc-and-federation.md),
  for signing in through identity providers and acting as an OpenID
  provider.
- **Exact behavior:** the normative specs in [`docs/spec/`](docs/spec/README.md).

## What it does

- **Subjects and credentials:** humans and service principals; passwords,
  secret keys, passkeys, email links and phone codes; MFA (TOTP and email
  codes), step-up, invites, password reset and change, and impersonation.
- **Sessions and tokens:** server-side sessions with refresh rotation and
  reuse detection, browser cookies with CSRF checks, and Ed25519 access
  tokens published through JWKS.
- **Tenancy and authorization:** tenants and memberships with facts, the
  action catalog, templates, roles and assignments, compiled entitlement
  sets, session flags, and the entitlements and check APIs.
- **Change feed and relying SDK:** SSE with resume, reset and batches; a
  sans-I/O relying core that also builds for wasm, with a native Rust client
  and a Python binding.
- **Messaging:** Konklav never sends messages. It emits delivery requests
  on the change feed for a relying system's worker to send.
- **Control plane:** authorized by `konklav:` capabilities, with listings,
  entitlement explanations and an operators' console.
- **Import:** a bulk import API and a `bootstrap` command that keep existing
  ids and can be re-run, including Argon2 password hashes, MFA seeds and
  sessions.
- **Federation:** OpenID Connect in both directions: signing in through
  identity providers with claim mapping; acting as an OpenID provider with
  client credentials, revocation and logout; peering between Konklav
  instances; and workload tokens.

The Python binding isn't published to PyPI yet. v1, a prototype backed by
Feldera, is preserved at tag `v1`.

## Repository layout

- `docs/nomenclature.md`: the shared vocabulary.
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
so no system Postgres client is needed). Docker runs the local Postgres, and
building the server needs the OpenSSL headers.

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

## Running in a container

The image runs `serve` as a non-root user. Mount `config.styx`,
`secrets.styx` and the key files they name at `/etc/konklav`:

```sh
docker run --rm -v ./deploy:/etc/konklav:ro konklav/konklav migrate
docker run -v ./deploy:/etc/konklav:ro -p 8080-8082:8080-8082 konklav/konklav
```

[`config/dev.styx`](config/dev.styx) and
[`config/dev.secrets.styx`](config/dev.secrets.styx) show the shape of both
files, and [`items/server`](items/server/README.md) describes the settings.

Konklav's schema needs PostgreSQL 18 with the
[`pg_jsonschema`](https://github.com/supabase/pg_jsonschema) extension;
`dev/postgres` builds such an image.

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

## Stack

- Rust, axum, tokio
- PostgreSQL via Diesel (`diesel-async`, embedded forward-only migrations)
- `ordna` for layered configuration with separate secrets
- Ed25519 JWTs published through JWKS
- pyo3 for the Python relying binding
- Leptos and Trunk for the console

## License

Konklav is licensed under the [MIT License](LICENSE).
