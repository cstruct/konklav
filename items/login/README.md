# Login page

`items/login` is the login page built into `konklav-server`: a small
[Svelte](https://svelte.dev) app, bundled by Vite, that the server embeds
and serves at `/login/` on the subject-facing surface when `login_page` is
configured. It is a login application for Konklav's OpenID provider, so
off-the-shelf OIDC clients (a Kubernetes cluster through `kubelogin`,
Harbor, Grafana, Argo CD and the like) can sign people in through Konklav
without the deployment writing a login application of its own.

## Responsibilities

- Answering login requests that Konklav hands off to it
  (`?login_request=<id>`), at `/v1/login-requests/{id}`, from OIDC clients
  and from native apps on the person's computer such as the operator CLI:
  - a native app's request is accepted only after the person confirms it
    on a page that names the app, even when they are already signed in
  - single sign-on: a person already signed in here is sent straight back
    to the client
  - `prompt=none` (refused with `login_required` when nobody is signed in)
    and `prompt=login` (a fresh sign-in, never an existing one)
  - `login_hint`, which fills in the email address
  - entering the tenant a `tenant:<id>` scope asks for, and, when the
    person isn't a member and the server takes access requests, asking for
    access, showing where the request stands, and withdrawing it
  - cancelling, which refuses the request with `access_denied`
- Signing in through the subject-facing surface as a browser client:
  - password, followed by MFA (TOTP or an emailed code) when the credential
    requires it
  - passkeys, when `passkeys` is configured
  - identity providers, OpenID providers and GitHub alike, one button
    each, with MFA afterwards when the provider requires local factors
- Without a login request, showing who is signed in, and signing out, which
  ends every client session started from that sign-in.

Out of scope:

- Choosing a tenant when the request names none: Konklav has no endpoint
  that lists a subject's memberships, so the client's session gets none.
- Deciding access requests: operators do that on the control plane.
- Email-link and phone-code sign-in, and password reset: they need a
  relying system that delivers challenges.
- Registration, consent screens (clients are pre-consented) and
  managing passkeys or MFA factors; the console does the latter for
  operators.

## Public interface

- The page learns the sign-in methods from `/login/config.json`. A relying
  system building its own sign-in screen reads the same list, without the
  page's settings, from the public `GET /v1/login/methods`.
- What the server serves under `/login/`: `index.html`, the hashed files in
  `assets/`, and `config.json`, which the server writes and the page reads
  on load (`src/lib/settings.ts`): the title, whether passkeys are
  configured, the identity providers and the URL they return to, and
  whether the server takes access requests.
- `src/lib/`, the logic apart from the components:
  - `api.ts`: calls to `/v1` with a DPoP proof each, Konklav's error
    envelope, and where `/v1` is relative to the page
  - `dpop.ts`: the page's non-extractable P-256 key and its proofs
  - `webauthn.ts`: passkey options and assertions to and from webauthn-rs'
    JSON
  - `login-request.ts`: the request id from the address, its kind, the
    requester's name, `prompt`, and keeping the id across an identity
    provider's round trip
  - `flow.ts`: what to do on load and after each step, without the DOM,
    and the access-request calls
- `src/*.svelte`: the views (`App`, `SignIn`, `Mfa`, `Confirm`, `RequestAccess`,
  `Account`).

## Relationships

### Dependency summary

| Software item | Relationship |
| --- | --- |
| `konklav-server` (over HTTP) | The only backend, called from the server's own origin. The page uses only the subject-facing surface's public endpoints, like any other login application. |
| Svelte 5, Vite, TypeScript | Components, bundling and types. Svelte compiles away, so the page ships about 20 kB of gzipped JavaScript and no framework runtime to speak of. |
| Vitest, `svelte-check` | Unit tests and type checking. |

### Dependent summary

| Software item | Relationship |
| --- | --- |
| `konklav-server` | Embeds `dist/` at build time (`items/server/build.rs`, feature `login-page`, on by default) and serves it. Without a build it embeds a placeholder page and warns; with `KONKLAV_REQUIRE_LOGIN_PAGE=1`, as release builds and the container image set, it fails instead. |

## Usage

Turn the page on in the server's configuration. `browser` is required, since
the page signs people in as a browser client:

```styx
tokens {
    issuer "https://id.example"
    // ...
}
browser {
    allowed_origins ("https://id.example")
}
oidc_provider {
    id_token_key_file "/etc/konklav/id-token-key.pem"
    // No login_url: authorization requests go to https://id.example/login/.
}
login_page {
    enabled true
    title "Example Corp"
}
```

With the page on, the server:

- makes `{issuer}/login/` the login URL of every client that registers none,
  unless `oidc_provider.login_url` says otherwise
- adds the issuer's origin to `browser.allowed_origins`, and to
  `passkeys.origins` when those are listed
- adds `{issuer}/login/` to every identity provider's `return_urls`

To offer GitHub, register an OAuth app (or a GitHub App) whose callback URL
is the provider's `redirect_uri`, and add it as an identity provider of
kind `github`, with its client secret in the secrets file:

```styx
identity_providers ({
    id github
    kind github
    name GitHub
    issuer "https://github.com"
    client_id "Iv1.0123456789abcdef"
    redirect_uri "https://id.example/v1/login/oidc/github/callback"
    // read:org adds the person's organizations and teams as `groups`.
    scopes (read:user user:email read:org)
    return_urls ()
    provisioning create
    link_verified_email_domains (example.com)
    local_mfa_factors 0
    grants ({claim groups, contains "example/platform", tenant "01936f4e-2b1a-7c3d-9e8f-0a1b2c3d4e5f", roles (admin)})
})
```

To let people who sign in for a client asking for a tenant they aren't a
member of request access, name the tenants that take requests; operators
then approve or deny on the control plane (`/v1/access-requests`), or a
tenant's own members holding `konklav:tenant:admit` there do, through a
relying system, at `/v1/tenants/{id}/access-requests`, and
`access_request.changed` on the change feed tells a relying system there is
something to decide:

```styx
access_requests {
    tenants ("01936f4e-2b1a-7c3d-9e8f-0a1b2c3d4e5f")
}
```

Then register clients through the control plane as usual. For a Kubernetes
cluster with `kubelogin`, a public client:

```json
{
  "kind": "public",
  "redirect_uris": ["http://localhost:8000", "http://localhost:18000"],
  "scopes": ["openid", "email", "groups"],
  "audience": "kubernetes"
}
```

with the API server's `--oidc-issuer-url` set to the issuer and
`--oidc-client-id` to the client's id. Harbor and other server-side
applications use a confidential client and its secret instead.

The page must be served from the issuer's origin at `/login/`. Behind a
reverse proxy that mounts Konklav under a path, the page finds `/v1` next to
itself, but proofs name that path, so list it in `tokens.dpop_urls`.

## Running

```sh
mise run login:build   # into items/login/dist, which the server embeds
mise run serve         # builds it too, then serves config/dev.styx
```

The development configuration turns the page on, so it is at
<http://127.0.0.1:8080/login/>. While changing it, `mise run login:dev`
serves it on <http://localhost:5174> with hot reloading and proxies `/v1`
to `mise run serve`, whose configuration allows that origin.

## Testing

```sh
mise run login:test    # svelte-check and the Vitest unit tests
cargo test -p konklav-server --test login_page
```

The unit tests cover the page's decisions (`src/lib/flow.test.ts`). The
server's tests check how the page is served and run a login request through
the calls the page makes.

## Behavior notes

- No token is kept in web storage. The refresh token is Konklav's HttpOnly
  cookie, the access token lives in memory, and sessions are bound to a
  non-extractable DPoP key kept in IndexedDB. Only the login request's id
  goes to `sessionStorage`, while an identity provider has the browser; it
  is no secret, since only the browser that started a request can finish
  it.
- The server sends a Content-Security-Policy allowing only the page's own
  scripts, styles and connections, forbids framing, and sends
  `Referrer-Policy: no-referrer`, since the address holds the login
  request. The build therefore inlines nothing.

## Traceability and related docs

- [`docs/spec/federation.md`](../../docs/spec/federation.md):
  `oidc.provider.login-page`, `oidc.provider.login-page.headers`,
  `oidc.provider.login-page.storage`, and the hand-off rules it follows
  (`oidc.provider.login-handoff`, `oidc.provider.login-refusal`,
  `oidc.provider.prompt`).
- [OIDC and federation](../../docs/architecture/oidc-and-federation.md#the-built-in-login-page).
