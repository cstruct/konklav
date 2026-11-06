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
  [`overview.md`](docs/architecture/overview.md).
- `items/`: software items:
  - `core`: identifiers
  - `api`: transport types of the HTTP surfaces
  - `token`: claims, JWS, JWKS
  - `authn`: hashing, refresh tokens
  - `authz`: entitlement compilation and evaluation
  - `bootstrap`: reading bootstrap sets (CSV tables and Styx documents)
  - `store`: Postgres, migrations, repositories
  - `server`: the binary
  - `relying`: the sans-I/O relying core
  - `relying-client`: the native Rust host
  - `py`: the Python binding (maturin)
  - `py-control-plane`: the Python control-plane client (pure Python)
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
mise run db:up      # Postgres 18 with pg_jsonschema in Docker on localhost:15432
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
(`.github/workflows/ci.yml`), and checks that the container image builds
and that the Python packages' wheels and sdists build and pass their tests
(`.github/workflows/python.yml`).

## Releases

Every release has one version, shared by the server, the console, the
Docker image, the Python packages (`konklav-relying` and the control-plane
client `konklav-control-plane`, both on PyPI) and the Rust crates on crates.io, and is made from one
`v<version>` tag. Konklav's clients are supported only against a server of
the same version. With a clean working tree, run
`mise run release:bump <version>`. It refuses to run with uncommitted
changes, then:

1. Sets `version` under `[workspace.package]` in `Cargo.toml`, in
   `items/py/Cargo.toml` (which maturin also uses for the Python package)
   and in `items/py-control-plane/pyproject.toml`,
   and the published crates' exact requirements on each other under
   `[workspace.dependencies]`, refreshes the lockfiles and regenerates the
   API document `items/server/openapi/control-plane.json`, which records the
   version.
2. Commits that as "Release <version>". On `main` it first pulls `main` and
   commits on a new `release/v<version>` branch, then pushes the branch,
   opens a pull request for it and switches back to `main`. On any other
   branch it commits there and pushes nothing, so the bump is released with
   the rest of that branch's pull request.

`release:bump` also stamps every pending bootstrap format under
`examples/bootstrap/formats/` with `released in <version>`, which freezes
it, as [the bootstrap crate's README](items/bootstrap/README.md#changing-the-format)
describes. The bootstrap format version is not the release version.

Once the pull request with the bump is merged, run `mise run release:tag` on `main` with a
clean working tree. It pulls `main`, reads the version from `Cargo.toml`,
refuses if that version is already tagged (as it is until the pull request
is merged), then tags the commit `v<version>` with an annotated tag
("Konklav <version>") and pushes the tag.

The release workflow then:

1. Checks the tag against the three manifests and the crates' requirements
   on each other, and runs CI again.
2. Builds `konklav-server` for x86_64 and aarch64 Linux and aarch64 macOS,
   and the console as a static bundle.
3. Builds the Python wheels (abi3, for Python 3.12 and later) for x86_64 and
   aarch64 Linux (manylinux_2_28 and musllinux_1_2) and aarch64 macOS, and
   an sdist, and runs the binding's tests against each, the musllinux ones
   on Alpine. Builds the control-plane client's wheel (pure Python) and
   sdist and runs its tests against each.
4. Pushes a linux/amd64 and linux/arm64 image to Docker Hub. The repository is
   the `DOCKERHUB_IMAGE` variable; the `deploy` environment holds
   `DOCKERHUB_USERNAME` and the `DOCKERHUB_TOKEN` secret.
5. Once everything has built, publishes `konklav-relying` and
   `konklav-control-plane` to PyPI through
   trusted publishing from the `pypi` environment, so no PyPI token is
   stored.
6. Publishes the crates with `publish = true` to crates.io, also through
   trusted publishing, from the `crates-io` environment. These are
   `konklav-core`, `konklav-token`, `konklav-authz`, `konklav-relying` and
   `konklav-relying-client`; every other crate inherits `publish = false`.
   Crates already on crates.io at that version are skipped, so a failed
   release can be rerun.
7. Publishes a GitHub release with the archives, the Python packages and
   `SHA256SUMS`.

A version with a pre-release part, such as `0.2.0-rc.1`, makes a
pre-release: its image gets only that exact tag, and the Python package is
published as the PEP 440 equivalent (`0.2.0rc1`), which pip installs only
with `--pre`.

Never move or delete a pushed release tag. Neither PyPI nor crates.io
accepts the same version twice, even after deleting or yanking it, so a
broken release is fixed by releasing the next patch version.

Trusted publishing can only be set up for a crate that already exists on
crates.io. To publish a new crate, set `publish = true` in its manifest
and give its entry under `[workspace.dependencies]` the exact release
version, as the others have. Then publish its first version by hand with
`cargo publish -p <crate>` and a crates.io token, and add a trusted
publisher for it on crates.io (repository `cstruct/konklav`, workflow
`release.yml`, environment `crates-io`). CI packages every published
crate and builds it from its packaged sources, so packaging problems show
up before a release.

A new PyPI project is published through a pending trusted publisher
registered for it on PyPI (repository `cstruct/konklav`, workflow
`release.yml`, environment `pypi`); `konklav-control-plane` was set up
that way.

`mise run py:build` builds the sdist and a wheel for this machine into
`items/py/dist` to check the packaging locally, and `mise run
py-control-plane:build` does the same for the control-plane client in
`items/py-control-plane/dist`. Pull requests build and test
every wheel and the sdist (`.github/workflows/python.yml`).
