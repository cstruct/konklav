# konklav-examples

Runnable examples of Konklav deployments. Each scenario starts real `konklav-server` processes, every one on a fresh database and its own free ports, and drives them over HTTP the way an app, a browser or an operator would. The tests run the same scenarios, so the examples stay true.

## Scenarios

| Example | What it shows |
|---|---|
| `smtp-delivery` | Email-link sign-in. The reference delivery worker follows the change feed as a service principal holding `konklav.delivery` and sends the link over SMTP; the app completes the sign-in with the token from the email, and the link doesn't work twice. |
| `federation` | One Konklav signing people in to another. The upstream is an OpenID provider; the downstream creates the subject on first sign-in and grants a local role from the upstream's `groups` claim. The scenario plays the browser and the upstream's login page, so every redirect is printed. |
| `bootstrap` | Seeding a new deployment from `bootstrap/nested`: a dry run, applying, re-applying without changes, then signing in with an imported password hash. |

Run one with:

```sh
mise run example smtp-delivery
```

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

## Layout

- `src/harness.rs`: starts servers. It writes config, secrets and keys to a temporary directory, creates a database, waits for readiness, and stops everything on drop.
- `src/scenario/`: the scenarios. The binaries in `src/bin/` and `items/server/tests/examples.rs` both call them.
- `src/smtp_sink.rs`: a minimal SMTP server that keeps what it receives, for the tests.
- `bootstrap/`: the example bootstrap sets, nested and flat.

## Testing

```sh
mise run db:up
cargo test -p konklav-server --test examples
```

The tests live in the server's package, since only there does Cargo provide the path of the `konklav-server` binary it built.
