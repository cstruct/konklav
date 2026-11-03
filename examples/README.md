# konklav-examples

Runnable examples of Konklav deployments. Each scenario starts real `konklav-server` processes, every one on a fresh database and its own free ports, and drives them over HTTP the way an app, a browser or an operator would. The tests run the same scenarios, so the examples stay true.

## Scenarios

| Example | What it shows |
|---|---|
| `smtp-delivery` | Email-link sign-in. The reference delivery worker follows the change feed as a service principal holding `konklav.delivery` and sends the link over SMTP; the app completes the sign-in with the token from the email, and the link doesn't work twice. |
| `federation` | One Konklav signing people in to another. The upstream is an OpenID provider; the downstream creates the subject on first sign-in and grants a local role from the upstream's `groups` claim. The upstream gets names from a claims hook; the downstream passes them on as an OpenID provider itself, and a tool signing in through it reads the name from userinfo. The scenario plays the browser, both login pages, the hook and the tool, so every redirect is printed. |
| `bootstrap` | Seeding a new deployment from `bootstrap/nested`: a dry run, applying, re-applying without changes, then signing in with an imported password hash. |

Run one with:

```sh
mise run example smtp-delivery
```

## Python

[`python/read_your_writes.py`](python/read_your_writes.py) uses both Python packages: `konklav-control-plane` assigns a role, and `konklav-relying` waits for that write's cursor with `await_cursor` and then allows what the role grants. Neither package imports the other; the cursor, an `int`, is all they share. `mise run example:python` runs it against a server on a fresh database, as `mise run test` does. `examples/python` is its own uv project, installing both packages from their source trees.

That starts the development Postgres, builds `konklav-server` and runs the scenario, printing each step. Set `KONKLAV_SERVER_BIN` to run another build of the server.

## The delivery worker

Konklav never sends messages: it emits `delivery.requested` events with the code or link token to send. [`src/delivery.rs`](src/delivery.rs) is the smallest worker that turns them into email, and `delivery-worker` runs it against any Konklav:

```sh
KONKLAV_SUBJECT_URL=https://auth.example KONKLAV_RELYING_URL=https://auth-relying.example \
KONKLAV_DELIVERY_KEY=<key_id.secret> SMTP_HOST=smtp.example SMTP_USERNAME=... SMTP_PASSWORD=... \
MAIL_FROM='Example <no-reply@example.com>' LINK_BASE=https://app.example \
cargo run -p konklav-examples --bin delivery-worker
```

- **Service principal:** the key is a secret key of a service principal holding the `konklav.delivery` global role.
- **Links:** they point to `{LINK_BASE}/{email-link,reset-password,invite}?token=...`, pages of the app that complete the flow with Konklav.
- **Codes:** MFA email codes are sent as text.
- **Other channels:** phone requests are left to another worker.
- **Restarts:** the worker keeps its feed cursor in memory, so a restart reads the feed again from `KONKLAV_DELIVERY_AFTER`. Requests whose challenge has expired carry no material and are skipped.
- **Production:** keep the cursor durable.

To see its mail by hand, point it at a local catcher such as Mailpit with `SMTP_TLS=none`.

## OpenID conformance

`conformance` sets Konklav up for the [OpenID conformance suite](https://gitlab.com/openid/conformance-suite)'s Basic OP and Config OP plans. It:
- starts Konklav as an OpenID provider
- registers two static clients, one with RS256 and one with ES256 ID tokens
- serves a login page that the suite's browser can drive
- writes the plan configuration, including the overrides that upload screenshots for the tests a reviewer checks by eye

To run it against the suite's prebuilt images:

1. **Start the suite.** Use its `docker-compose-prebuilt.yml`, with `IMAGE_TAG=release-v5.3.4`. Give MongoDB a named volume if the compose directory is somewhere it can't write, as under `/tmp` on macOS.
2. **Start Konklav behind TLS.** The suite requires an HTTPS issuer.

   ```sh
   CONFORMANCE_ISSUER=https://host.docker.internal:9443 cargo run -p konklav-examples --bin conformance
   ```

   Then proxy port 9443 to the subject-facing port it prints:

   ```sh
   docker run -d -p 9443:9443 caddy:2.10.2 caddy reverse-proxy --internal-certs \
     --from https://host.docker.internal:9443 --to http://host.docker.internal:<port>
   ```
3. **Run the plans.** Use the suite's `scripts/run-test-plan.py` with `CONFORMANCE_DEV_MODE=1` and the written `conformance.json`:
   - `oidcc-config-certification-test-plan`
   - `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`

Last run with suite release v5.3.4, both plans had no failures, and the Basic OP plan no warnings.

- **Warning:** Konklav's `konklav_peer_*` discovery fields are reported as unexpected by the Config OP plan.
- **Profile claims** come from the example's claims hook, so the profile test runs.
- **Skipped:** the address and all-scopes tests, and request objects. Konklav doesn't support these.
- **Review:** the second sign-in and error-page screenshots, as for any provider.

## Layout

- `src/harness.rs`: starts servers. It writes config, secrets and keys to a temporary directory, creates a database, waits for readiness, and stops everything on drop.
- `src/scenario/`: the scenarios. The binaries in `src/bin/` and `items/server/tests/examples.rs` both call them.
- `src/smtp_sink.rs`: a minimal SMTP server that keeps what it receives, for the tests.
- `src/bin/test-server.rs`: starts one server for another language's tests, such as the Python control-plane client's integration tests. It prints the surfaces' URLs and the bootstrap token as one JSON line, and stops when its stdin closes.
- `bootstrap/`: the example bootstrap sets, nested and flat.

## Testing

```sh
mise run db:up
cargo test -p konklav-server --test examples
```

The tests live in the server's package, since only there does Cargo provide the path of the `konklav-server` binary it built.
