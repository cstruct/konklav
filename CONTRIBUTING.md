# Contributing to Konklav

This guide is for working on Konklav itself. To try it or run it, start
with the [README](README.md).

## Before you change things

- **Vocabulary:** read [`docs/nomenclature.md`](docs/nomenclature.md)
  before changing specs, API surfaces, auth models or documentation, and
  use its terms in code, tests and docs. A new project term goes there
  first.
- **Specs first:** requirements live in [`docs/spec/`](docs/spec/README.md)
  as Tracey rules (`r[...]`). Code and tests reference them as
  `r[impl ...]` and `r[verify ...]`; see
  [traceability guidance](docs/traceability-guidance.md).
- **Software items:** each item under `items/` has a README written to
  [this standard](docs/software-item-readmes.md). Keep it current when the
  item changes.
- **Larger work:** for complex features, substantial refactors or
  migrations, write a plan file following
  [`.agents/plans/PLANS.md`](.agents/plans/PLANS.md) before implementing.

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
  also run (see [`examples/README.md`](examples/README.md)).
- `dev/`: local services for development.
- `.agents/`: agent skills and the planning standard.

## Development environment

[mise](https://mise.jdx.dev) manages the toolchain, the environment and the
local services. It covers Rust, Tracey, Trunk, uv, Hydra and Diesel's CLI
(which bundles libpq, so no system Postgres client is needed). You also
need Docker for the local Postgres and the OpenSSL headers (for example
`brew install openssl@3`).

```sh
mise trust && mise install
mise run db:up      # Postgres 18 with pg_jsonschema in Docker on localhost:55432
```

mise sets `DATABASE_URL`, `KONKLAV_CONFIG` and `KONKLAV_SECRETS` for the
local setup. Everyday tasks:

- `mise run serve` starts Postgres, migrates it, creates an untracked
  development signing key if needed, and serves on ports 8080 to 8082.
- `mise run console:serve` serves the operators' console on
  <http://127.0.0.1:8083> against that server. `console:build` makes a
  release build. See [`items/console`](items/console/README.md).
- `mise run test` runs every test, each database test in its own database.
  OIDC interoperability tests run against independent implementations:
  - Ory Hydra as an identity provider for Konklav
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

Other database tasks:

- `db:down` stops Postgres and keeps its data.
- `db:reset` stops it and deletes the data.
- `db:status` shows its status.
- `db:logs` follows its logs.
- `db:psql` opens psql inside the container.

To use another port, set `KONKLAV_DEV_PG_PORT`, for example in an untracked
`mise.local.toml`.

## Pull requests

Run `mise run lint` and `mise run test` before opening one. GitHub Actions
runs both on every push to `main` and every pull request
(`.github/workflows/ci.yml`), and checks that the container image builds.

## Releases

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
