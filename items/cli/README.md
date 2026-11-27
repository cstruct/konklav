# Operator CLI

`konklav-cli` is the operator CLI for Konklav. Its binary is `konklav`. Operators use it to sign in to a Konklav deployment and work on its control plane from a terminal or a script: tenants, subjects, invites, roles, assignments, sessions, decision explanations, batches, and any other control-plane call through `konklav api`.

Every session it starts is bound to a DPoP key it makes on the operator's computer. Its tokens are useless without that key.

## Responsibilities

- Signing in:
  - `konklav login`: through the browser, with the native login hand-off (the default)
  - `konklav login --password`: at the terminal, with MFA
  - `konklav login --secret-key KEY_ID`: as a service principal, for CI
- Binding every session to a P-256 DPoP key, and sending a proof with every request (`item.cli.dpop-every-request`).
- Keeping each profile's key and tokens in the operating system's credential store, or with `--credential-store file`, in a file only the user can read (`item.cli.secrets-in-keyring`).
- Refreshing tokens one command at a time per profile, under a lock file. Two commands that rotated the same refresh token would look like token theft to Konklav, which would end the session.
- Correcting for clock skew once, from the `Date` of a refused proof.
- Typed control-plane commands over `konklav-api` types, with tables for people and `--json` for scripts.
- Signing out: revoking the session at Konklav, then deleting the local key and tokens even if that failed (`item.cli.logout`).

Out of scope:

- Anything that bypasses the HTTP surfaces: the CLI never reaches the database. The server's own CLI, `konklav-server`, handles migrations, bootstrap and export.
- Hardware-backed DPoP keys (Secure Enclave, TPM).
- Sign-in on a machine with no browser that can reach its loopback port. Use `--password` or `--secret-key` there.

## Public interface

- Global options: `--profile NAME` (or `KONKLAV_PROFILE`), and `--json`, which prints the result as JSON on standard output and nothing else there.
- Sessions: `login`, `logout`, `whoami`.
- Typed commands:
  - `tenants list|get|create|suspend|activate`
  - `subjects list|get|create|disable|enable`
  - `invites list|get|create|revoke`
  - `roles list|get|put|delete`
  - `assignments list|add|remove`
  - `sessions list|get|revoke`
  - `explain SUBJECT ACTION [--tenant T]`
  - `batch apply FILE [--idempotency-key KEY]`
- Raw calls: `konklav api METHOD PATH [--data JSON|@file|@-] [--subject]` sends one request to the control plane, or with `--subject`, to the subject-facing surface. It prints the response body and nothing else.
- Exit codes (`item.cli.exit-codes`):
  - 0 on success
  - 1 when Konklav refused, with its error on standard error
  - 2 for a usage error
  - 3 when not signed in, or the session has ended
  - 4 when Konklav can't be reached
- Configuration: `config.styx` in `KONKLAV_CONFIG_DIR`, or `konklav` in the platform's configuration directory (`~/Library/Application Support/konklav` on macOS, `~/.config/konklav` on Linux). It names profiles, each with:
  - `url`, the issuer
  - an optional `control_url`
  - `credential_store`

  The file holds no secrets.
- The library (`src/lib.rs`): `Context`, `Session` with the typed calls of `control`, `BrowserLogin`, and the password and secret-key logins. The binary is built from it, and the server's tests drive it.

## Relationships

### Dependency summary

| Software item | Relationship |
| --- | --- |
| `konklav-token` | Signs DPoP proofs, with its `sign` feature (`ProofSigner`) |
| `konklav-api` | The control plane's request and response types |
| `konklav-core` | Identifier types in those requests |
| `konklav-server` | Over HTTP only: the subject-facing surface (login, refresh, the native login hand-off, sign-out) and the control plane |
| `konklav-login` | The login page, or a deployment's own login application, where browser sign-in happens |

### Dependent summary

| Software item | Relationship |
| --- | --- |
| `konklav-server` (tests) | `tests/cli.rs` drives the library against a real server |

## Usage

Sign in through the browser, then work on the control plane:

```sh
konklav login --url https://id.example
konklav whoami
konklav tenants create --key acme-north
konklav invites create --email ada@example.com --tenant acme-north --role member
konklav explain 0193a2f1-7c1e-7000-8000-000000000000 docs:read --tenant acme-north
konklav api GET /v1/catalog
```

When the control plane has a base URL of its own, give it at login. That URL must be one of the server's `tokens.dpop_urls`, since proofs name it:

```sh
konklav login --url https://id.example --control-url https://admin.example/control
```

To sign in a service principal in CI, without a browser or keyring:

```sh
KONKLAV_SECRET_KEY=... konklav login --url https://id.example \
  --secret-key 0193a2f1-... --credential-store file
```

Browser sign-in needs the server's `browser.native_handoff` turned on. Without it, `konklav login` says so and suggests `--password`. `--no-browser` prints the sign-in URL instead of opening it, for a browser elsewhere on the same machine.

## Running

Install a release binary from the GitHub release (x86_64 and aarch64 Linux, aarch64 macOS, x86_64 Windows), or build from crates.io:

```sh
cargo install konklav-cli
```

From this repository:

```sh
cargo run -p konklav-cli -- login --url http://127.0.0.1:8080 --control-url http://127.0.0.1:8082
```

The dev configuration (`config/dev.styx`) turns on the login page and the native login hand-off, and lists the dev control plane's own port in `tokens.dpop_urls`.

## Testing

```sh
cargo test -p konklav-cli                  # profiles, credential files, the loopback listener, tables
cargo test -p konklav-server --test cli    # the library against a real server
```

- Direct coverage:
  - the configuration round trip and profile names
  - the private credential file
  - the loopback listener: other paths, other `state`s, and the one callback it waits for
  - path and query encoding
  - table layout
- Indirect coverage (`items/server/tests/cli.rs`):
  - password, MFA, secret-key and browser sign-in, each ending in a bound session
  - tokens refused without the key
  - refresh rotation, and concurrent commands sharing one refresh
  - sign-out
  - each typed command group

## Behavior notes

- The access token is kept in the credential store next to the refresh token, so commands run one after another don't each rotate the refresh token. It is as useless without the key as the refresh token is.
- `konklav login` ends the profile's earlier session first.
- `sessions revoke` keeps the CLI's own session.
- `batch apply` makes an idempotency key unless one is given, so a retried call applies the batch once.
- Before it opens the browser, `konklav login` checks that the server offers the native login hand-off. That probe starts nothing.

## Traceability and related docs

- [Operator CLI spec](../../docs/spec/software-items/cli.md)
- [Native login hand-off](../../docs/spec/authentication.md#native-login-hand-off) and [DPoP on Konklav's own surfaces](../../docs/architecture/proof-of-possession.md)
- [Traceability guidance](../../docs/traceability-guidance.md)
- [Nomenclature](../../docs/nomenclature.md)
