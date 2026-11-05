# Console

`konklav-console` is a browser UI for operating Konklav's control plane.
It's a client-side Leptos app, compiled to WASM and bundled by
[Trunk](https://trunkrs.dev). Operators sign in with their own Konklav
credentials, and the console calls the control plane with their access
token.

## Responsibilities

- Signing operators in through the subject-facing surface: password login
  as a browser client, MFA when the credential requires it, passkey login,
  and restoring the session from the refresh cookie on reload. The bootstrap token is
  accepted as a first-run option.
- The operator's own passkeys (**Passkeys** in the header): adding,
  listing and removing them, confirming with the password or a passkey
  first when Konklav asks for a fresher sign-in.
- Showing what the operator may do. `GET /v1/capabilities` lists their
  `konklav:` capabilities; areas they lack one for say which capability
  is missing, and so do control-plane refusals.
- Views over the control plane:
  - subjects, with their credentials (add, including a password from an
    Argon2id hash, revoke, replace a password, rotate a secret-key slot,
    mark break-glass), sessions, global roles and
    entitlements
  - tenants (create, facts, state, children) and memberships (create,
    facts, end, role assignments)
  - roles per tenant (the root tenant's are global, and built-in
    `konklav.` roles are shown read-only), templates, the catalog,
    entitlement explanations, and decision explanations, as of a past
    time when history is enabled
  - sessions, revoked one at a time or by filter
  - invites
  - OIDC clients: register or replace, issue a new secret, disable
  - signing keys, with break-glass revocation

Out of scope:

- Anything the HTTP API doesn't offer. The console adds no server
  endpoints of its own; it uses the subject-facing and control-plane
  surfaces like any other client.
- Bulk import (`/v1/import/*`), which is for migration tooling, and
  delivery (Konklav doesn't send messages).
- Serving itself in production. The build is static files.

## Public interface

- `mise run console:serve`: serves the console on
  <http://127.0.0.1:8083>, rebuilding on change, and proxies to the
  development server from `mise run serve`.
- `mise run console:build`: a release build into `target/console/dist`.
- The library's non-UI modules, which hold the logic that is tested
  natively:
  - `api`: requests as data (`Request`, `Surface`), every endpoint the
    console calls (`api::endpoints`), the error envelope (`ApiError`),
    DTOs (`api::types`) and the `fetch` transport
  - `grants`: which areas a set of capabilities opens (`Grants`,
    `Capability`)
  - `operator`: the signed-in operator and the decisions around their
    access token: reading claims, recovering from a rejected token, and
    what follows the first factor
  - `ids`: `UUIDv7`s for the resources the console creates with
    idempotent `PUT`s
- `ui`: the Leptos components, by area.

## Relationships

### Dependency summary

| Software item | Relationship |
| --- | --- |
| `konklav-server` (over HTTP) | The only backend. The console uses the subject-facing surface to sign in and the control-plane surface for everything else. It shares no Rust types with the server and keeps its own DTOs. |
| Leptos, `leptos_router` | Rendering, fine-grained reactivity and client-side routing. |
| Trunk | Compiles the WASM, runs `wasm-bindgen`, bundles the page, and proxies Konklav during development. |

### Dependent summary

None. Operators use it in a browser.

## Deployment

The console must reach Konklav on its own origin
(`r[item.console.same-origin]`):

- `/v1/` goes to the subject-facing surface, keeping its paths, because
  the refresh cookie is scoped to `/v1/refresh` and `/v1/sign-out`.
- `/control/v1/` goes to the control-plane surface's `/v1/`.
- Everything else serves the built files, with `index.html` as the
  fallback for client-side routes.

Same-origin requests keep the `SameSite=Strict` refresh cookie
first-party, and Konklav serves no CORS. Konklav still checks the
`Origin` of cookie requests, so add the console's origin to
`browser.allowed_origins`. Konklav also requires an `X-Konklav-Client`
header, which the console sends on every request. In development, Trunk
does the routing (see `Trunk.toml`), and `config/dev.styx` allows
`http://127.0.0.1:8083`.

The console's sessions are bound to a DPoP key (`r[item.console.dpop]`):
a non-extractable WebCrypto P-256 key, kept in IndexedDB, that signs a
proof for every request, so an access token taken from the page is useless
elsewhere. Konklav checks each proof's URL against `tokens.dpop_urls`, so
list the console's origin and its control-plane prefix there, such as
`("https://admin.example" "https://admin.example/control")`.
`browser { require_dpop true }` then refuses unbound browser sessions.

## Running

```sh
mise run serve            # Konklav on 8080–8082
mise run console:serve    # the console on http://127.0.0.1:8083
```

Passkeys need the console at `http://localhost:8083` instead: WebAuthn
doesn't accept IP addresses, and the dev config's relying party ID is
`localhost`.

On a fresh database, choose **Bootstrap token** and paste the
`control.bootstrap_token` from `config/dev.secrets.styx`. Then:

1. Create an operator: a human subject with a password credential.
2. Under **Authorization**, save a role in the root tenant whose policies
   allow `konklav:control:all` or narrower capabilities.
3. Assign that role on the subject's page, sign out, and sign in as the
   operator.

The console keeps tokens in memory only
(`r[item.console.token-in-memory]`). Reloading restores an operator's
session from the refresh cookie, but forgets the bootstrap token. Debug
builds are large, so the first load takes a few seconds.

## Testing

```sh
cargo test -p konklav-console   # request building, errors, DTOs, grants, token decisions
mise run console:smoke           # builds the app with trunk and checks the bundle
```

`mise run lint` also runs clippy for the `wasm32-unknown-unknown` target,
and `mise run test` includes the smoke build.

Coverage shape:

- Direct coverage
  - unit tests and doctests for everything outside `ui`, plus small pure
    helpers in `ui` (credential bodies, labels, summaries)
  - the smoke build, which compiles the components to WASM and bundles
    them
- Indirect coverage
  - the server's tests cover the endpoints the console relies on,
    including `GET /v1/capabilities`, factor listing for partial
    sessions, and the refresh cookie after MFA
  - the components themselves are checked by hand against
    `mise run serve`

## Behavior notes

- Refresh tokens rotate, and presenting a rotated one ends the session.
  So the console runs at most one refresh at a time, and a request whose
  token was replaced while it was in flight retries with the new token
  instead of refreshing again (`operator::after_rejection`).
- A refusal for a missing capability is shown as such. Any other
  `UNAUTHENTICATED` or `SESSION_ENDED` answer that a refresh can't fix
  signs the operator out.
- Secrets that Konklav shows only once (secret keys, rotated slots and
  OIDC client secrets) are shown once and never stored.
- Passkey ceremonies go through the browser's JSON forms
  (`PublicKeyCredential.parseCreationOptionsFromJSON`,
  `parseRequestOptionsFromJSON` and `toJSON()`, in `src/webauthn.rs`), so
  they need a browser that has them; older ones get a clear error.
- Destructive actions ask for confirmation, and the confirmation says
  what else ends, such as sessions, tokens or assignments.

## Traceability and related docs

- [Console spec](../../docs/spec/software-items/console.md)
- Product rules the console depends on: `session.browser.cookie`,
  `session.browser.csrf`, `session.browser.mfa`,
  `authn.mfa.partial-factors` and `authz.control-plane.own-capabilities`
  in [`docs/spec/`](../../docs/spec/)
- [Sessions and tokens](../../docs/architecture/sessions-and-tokens.md)
- [Traceability guidance](../../docs/traceability-guidance.md)
- [Nomenclature](../../docs/nomenclature.md)
