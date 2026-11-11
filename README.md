<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/konklav-dark.svg">
    <img alt="Konklav" src="docs/brand/konklav-light.svg" height="52">
  </picture>
</h1>

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

This builds Konklav from a checkout, runs it locally with the development
configuration and creates the first operator. You need Rust 1.88 or later,
Docker, and OpenSSL with its headers (for example `brew install openssl@3`).
Run the commands from the repository root.

1. Start Postgres. Konklav needs PostgreSQL 18 with the
   [`pg_jsonschema`](https://github.com/supabase/pg_jsonschema) extension,
   and `dev/` builds and runs such a container on `localhost:15432`:

   ```sh
   docker compose -f dev/compose.yaml up -d --wait
   ```

2. Install `konklav-server`:

   ```sh
   cargo install --locked --path items/server
   ```

3. Point it at the development configuration, create a signing key, apply
   the migrations and serve:

   ```sh
   export KONKLAV_CONFIG=config/dev.styx KONKLAV_SECRETS=config/dev.secrets.styx
   openssl genpkey -algorithm Ed25519 -out config/dev.signing-key.pem
   konklav-server migrate
   konklav-server serve
   ```

   It serves the three surfaces:
   - subject-facing on `127.0.0.1:8080`
   - relying on `:8081`
   - control-plane on `:8082`

4. Create the first operator, a human subject with a password credential
   and the built-in `konklav.admin` global role. Until one exists, the
   control plane accepts only the bootstrap token, `control.bootstrap_token`
   in [`config/dev.secrets.styx`](config/dev.secrets.styx). In a second
   terminal:

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
   another one.

5. Sign in as the operator:

   ```sh
   curl -X POST localhost:8080/v1/login/password \
     -H 'Content-Type: application/json' \
     -d '{"identifier": "ada@example.com", "password": "correct horse"}'
   ```

   The response holds an access token for the control plane. In a real
   deployment, remove the bootstrap token from the secrets file once an
   operator exists.

To start from a populated database instead, seed it with the example
bootstrap set:

```sh
konklav-server bootstrap examples/bootstrap/nested/seed.styx
```

### The console

The operators' console is a browser UI over the control plane. To serve it
against the server above on <http://localhost:8083>:

```sh
rustup target add wasm32-unknown-unknown
cargo install --locked trunk
cd items/console && trunk serve
```

Use `localhost` rather than `127.0.0.1`, because passkeys don't work on IP
addresses. Sign in as the operator, or use the bootstrap token to create
one there instead of with `curl`.

## Where next

- **Vocabulary:** [`docs/nomenclature.md`](docs/nomenclature.md) defines
  subjects, tenants, memberships, roles, entitlement sets and the rest.
  Konklav's docs and APIs use these terms precisely.
- **How it fits together:** the
  [overview](docs/architecture/overview.md), then the other notes in
  [`docs/architecture/`](docs/architecture/).
- **A complete app:** the [notes app](examples/notes-app/README.md), in
  Docker Compose: single sign-on to a browser app and an admin page with
  DPoP-bound tokens, live roles, revocation and rate limits shared through
  Valkey.
- **Runnable scenarios:** [`examples/`](examples/README.md) has email-link
  sign-in with a delivery worker, one Konklav signing people in to another,
  and seeding a deployment.
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
- **Working on Konklav:** [`CONTRIBUTING.md`](CONTRIBUTING.md) covers the
  development environment, tests and releases.

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
- **Erasure and personal data reports:** an operator can erase a subject,
  which removes the personal data Konklav holds and tells relying systems
  through the change feed, and can read everything held about a subject as
  one report. Konklav holds no profile data, so each relying system erases
  its own. See [erasure](docs/architecture/erasure.md).
- **Import:** a bulk import API and a `bootstrap` command that keep existing
  ids and can be re-run, including Argon2 password hashes, MFA seeds and
  sessions.
- **Federation:** OpenID Connect in both directions: signing in through
  identity providers with claim mapping; acting as an OpenID provider with
  client credentials, revocation and logout; peering between Konklav
  instances; and workload tokens.

The Python binding isn't published to PyPI yet. v1, a prototype backed by
Feldera, is preserved at tag `v1`.

## Running in a container

The image runs `konklav-server serve` as a non-root user. Mount
`config.styx`, `secrets.styx` and the key files they name at
`/etc/konklav`:

```sh
docker run --rm -v ./deploy:/etc/konklav:ro konklav/konklav migrate
docker run -v ./deploy:/etc/konklav:ro -p 8080-8082:8080-8082 konklav/konklav
```

[`config/dev.styx`](config/dev.styx) and
[`config/dev.secrets.styx`](config/dev.secrets.styx) show the shape of both
files, and [`items/server`](items/server/README.md) describes the settings.
The database must be PostgreSQL 18 with `pg_jsonschema`;
[`dev/postgres`](dev/postgres/Dockerfile) builds such an image.

## Stack

- Rust, axum, tokio
- PostgreSQL via Diesel (`diesel-async`, embedded forward-only migrations)
- `ordna` for layered configuration with separate secrets
- Ed25519 JWTs published through JWKS
- pyo3 for the Python relying binding
- Leptos and Trunk for the console

## License

Konklav is licensed under the [MIT License](LICENSE).
