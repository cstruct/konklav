# OIDC and federation

Status: accepted and implemented through phase 5: identity providers,
claim mapping, break-glass, the OpenID provider with client credentials,
revocation and logout, peering, key pinning and workload federation.
What's left is listed under Open points. The rules are in
[`../spec/federation.md`](../spec/federation.md); this note explains them
and lists the decisions still open. It replaces the earlier "federation is
out of scope" position.

## Goals

1. **Sign in through identity providers.** Corporate IdPs, social logins,
   and national eID schemes through an OIDC broker, so that eID doesn't need
   native integrations.
2. **Be an identity provider.** Applications and tools sign in with
   standard OIDC libraries instead of Konklav's `/v1` API, and each gets
   its own audience and claims.
3. **Federate operators across instances.** One operators' instance holds
   the people who run the platform. Dev, staging and each production region
   run their own Konklav and trust it for operator sign-in and access,
   without copying end-user data between them.

## Topology for operators

```
              ┌──────────────────────────┐
              │ operators' Konklav      │  OpenID provider
              │ subjects: operators      │  clients: one per environment
              │ global roles: sre, dev…  │
              └──┬─────────┬─────────┬───┘
       OIDC +    │         │         │     optional: change feed (peering)
       feed      ▼         ▼         ▼
            ┌───────┐ ┌─────────┐ ┌──────────────┐
            │  dev  │ │ staging │ │ prod-eu, …   │  identity-provider clients
            └───────┘ └─────────┘ └──────────────┘
```

- Each environment registers the operators' instance as an identity
  provider. At the operators' instance, each environment is its own OIDC
  client, with its own redirect URIs, audience and visible groups.
- Operators exist once, upstream. Downstream, a local subject with a
  federated credential (`{provider, sub}`) represents them. It's created on
  first login if the provider's provisioning policy allows it.
- End-user data never moves between instances. Only operator identities and
  group claims travel, which keeps regional data residency intact.

## Konklav as a client of identity providers

1. `GET /v1/login/oidc/{provider}/start` creates a challenge holding
   `state`, `nonce` and the PKCE verifier, sets a short-lived cookie
   binding it to the browser, and redirects to the provider.
2. `GET /v1/login/oidc/{provider}/callback`:
   - checks `state` against the cookie and consumes the challenge
   - exchanges the code
   - validates the ID token
   - fetches UserInfo when the provider has an endpoint and returned an
     access token, and adds its claims (the ID token's win)
3. It then resolves the federated credential:
   - linked: use its subject
   - otherwise: link or provision per policy
   - neither allowed: fail with the same error as an unknown account
4. It maps `amr`/`acr` to Konklav methods, applies claim mapping, and
   starts an ordinary session, with the provider's session-lifetime cap.
5. It redirects to the configured return URL. The browser receives the
   refresh cookie exactly as for a password login.

Linking an extra provider to an existing subject happens while signed in:
`POST /v1/credentials/oidc/{provider}/link` (with the access token, an
allowed `Origin` and the client header) returns the provider URL and sets
the state cookie, and the callback links the account to that subject. Only
linking while signed in avoids account takeover through a provider that
reports an email it doesn't own.

Each provider states `local_mfa_factors`: how many of the subject's own
MFA factors a sign-in through it must also prove. `0` trusts the provider's
authentication alone; there is no default, so it is always a decision.
When it is above zero, the callback sets no refresh cookie. It redirects
with `signed_in=mfa_required` and leaves the partial session's access token
in a short-lived cookie, which the page exchanges once at
`POST /v1/login/oidc/partial` and then completes with `POST /v1/login/mfa`,
as after a password login.

The callback redirects to the return URL with `signed_in=true`,
`signed_in=mfa_required`, `linked=true`, or `error=` one of `provider_error`, `invalid_id_token`,
`requirements_not_met`, `account_not_linked` and
`account_linked_elsewhere`. Linking enforces the provider's `acr` and
`max_age` requirements too.

## Konklav as an OpenID provider

The provider role reuses sessions, refresh rotation, access tokens and step
up. Its endpoints live under `/v1/oauth2/` (versioned like every other
endpoint), with discovery at `/.well-known/openid-configuration` on the
subject surface. It is off unless `oidc_provider` is configured:

```styx
oidc_provider {
    id_token_key_file "/run/secrets/id-token.pem"
    login_url "https://login.example/"
}
```

New pieces:

- **Clients**: a control-plane resource. `PUT /v1/oidc/clients/{id}`
  registers or replaces a client (needs `konklav:clients:manage`) with its:
  - kind (`confidential` or `public`)
  - redirect URIs (exact match)
  - scopes (`openid`, `email`, `phone`, `groups`, and `tenant` to allow
    `tenant:<id>`)
  - access-token audience
  - visible groups (exact keys or `prefix*`)
  - an optional login URL
  - ID-token algorithm (`ES256`, `EdDSA` or, with an RSA key, `RS256`)
  - whether refresh is allowed

  `POST …/secret` issues a confidential client's secret once; Konklav
  keeps only its SHA-256. `DELETE` disables the client and revokes its
  sessions, keeping the registration as history.
- **Login requests** and **authorization codes** are challenges: hashed,
  single-use, ten minutes and sixty seconds.
- **Client sessions**: exchanging a code starts a new session for the
  client. It's a child of the login application's session, with the same
  subject, credential, tenant and authentication, and it ends with it. It
  records the client and the granted scopes. Its access tokens carry the
  client's audience, and its refresh tokens only work at the token endpoint
  for that client. Konklav's own API refuses its access tokens.
- **ID tokens and the ES256 key**: many OIDC libraries can't verify EdDSA,
  so ID tokens default to ES256 with a P-256 key loaded from
  `id_token_key_file` and published in JWKS next to the Ed25519 keys. The
  relying SDK ignores it. Access tokens stay EdDSA. Rotating the ES256 key
  means replacing the file; publishing the next key ahead of a rotation, as
  the Ed25519 keys allow, is not built yet.
- **RS256**: OpenID Connect requires providers to offer RS256, and some
  relying parties accept nothing else. With `rsa_key_file` (an RSA key of
  at least 2048 bits), discovery lists RS256, JWKS publishes the key with
  an RFC 7638 thumbprint as its `kid`, and clients can be registered for
  it. Signing uses aws-lc-rs, not the `rsa` crate, whose private-key
  operations aren't constant-time (RUSTSEC-2023-0071).
- **`acr`**: `urn:konklav:acr:1` for sessions with one authentication
  method and `urn:konklav:acr:2` for two or more (an identity-provider
  login counts the methods it was credited with). `acr_values` asks for
  `2`.

### Login hand-off instead of a hosted page

Konklav has no user interface, and `/v1/oauth2/authorize` doesn't add one:

1. The client redirects to `/v1/oauth2/authorize`, with:
   - the authorization code response type
   - PKCE `S256`
   - optionally `nonce`, `max_age`, `acr_values` and a `tenant:<id>` scope

   Konklav validates the client and redirect URI; until both check out,
   errors go to the browser rather than to the redirect URI. It then keeps
   the request as a challenge, sets a cookie binding it to the browser, and
   redirects to the login URL with `login_request=<id>`.
2. The login application (a relying system's frontend, or a small
   operators' login app) reads `GET /v1/oauth2/login-requests/{id}`, which
   includes the request's `prompt` and `login_hint`. It signs the subject in
   through the existing `/v1` API, including MFA, step-up and tenant
   selection. It may instead refuse the request with `POST
   /v1/oauth2/login-requests/{id}/reject` and an error such as
   `login_required`: that is how `prompt=none` is answered when nobody is
   signed in. The refusal returns a `redirect_to` too, and the error
   reaches the client the same way a code would.
3. It calls `POST /v1/oauth2/login-requests/{id}/accept` with the session's
   access token (and the usual browser `Origin` and client header).
   Konklav checks `max_age`, `acr_values`, `prompt=login` (a sign-in after
   the request started) and the requested tenant against the session, and
   returns `redirect_to`.
4. The browser follows it to `/v1/oauth2/authorize/resume`. Konklav
   checks the cookie and the one-time acceptance secret that `redirect_to`
   carries, so only a browser that both started and accepted the request
   finishes it. Someone who starts a request and sends its login link to a
   signed-in victim therefore gets nothing: the victim's browser lacks the
   cookie, and the attacker's lacks the acceptance. Konklav then redirects
   to the client with a code, the client's `state` and `iss`.
5. The client calls `POST /v1/oauth2/token` with the code, the redirect
   URI, the PKCE verifier and its credentials (HTTP basic or form; none for
   public clients). The response holds an access token, an ID token and,
   if allowed, a refresh token. With a `DPoP` header (RFC 9449), the
   session is bound to the proof's key and the tokens are
   sender-constrained (`token_type` `DPoP`). A client registered with
   `require_dpop` gets no tokens without one, and an authorization request
   can bind its code to a key with `dpop_jkt`. See
   [proof-of-possession](proof-of-possession.md#sender-constrained-tokens-dpop).

Consent screens are left to the login application. First-party clients are
registered as pre-consented.

### Client credentials, revocation and logout

- **Client credentials.** A confidential client can name a
  `service_subject`. Konklav then keeps a `client` credential (identifier:
  the client id) on that service principal, moving it if the binding
  changes and revoking it (and its sessions) if the binding is removed. The
  `client_credentials` grant starts a session for the principal that lasts
  one access token. Its access token carries the client's audience, and it
  gets no refresh or ID token.
- **`private_key_jwt`.** Any client with a registered `jwks` can
  authenticate at the token and revocation endpoints with a signed
  assertion (RFC 7523):
  - `iss` and `sub` are the client id
  - `aud` is the token endpoint or the issuer
  - the signature uses an asymmetric algorithm
  - `jti` is single-use; used ones are kept until the assertion expires
- **Revocation** (`POST /v1/oauth2/revoke`, RFC 7009) ends the session
  behind a refresh or access token the client was issued, and answers 200
  for anything else.
- **CORS.** A browser app registered as a public client calls the token,
  revocation and userinfo endpoints from its own origin, with the `DPoP`
  header allowed. They answer
  preflights and send `Access-Control-Allow-Origin` for an origin of an
  active public client's redirect URIs, never `*` and without allowing
  credentials, so registering a client needs no list of origins. Discovery
  and the key set allow any origin. Nothing else on the subject-facing
  surface sends CORS headers: a login application is served from
  Konklav's own origin.
- **RP-initiated logout** (`GET /v1/oauth2/logout`) takes an
  `id_token_hint`. Konklav checks the hint against its own keys, and
  accepts it even if it has expired. It then ends the login application's
  session that the client session came from; every client session started
  from it ends with it. Finally it redirects to a registered
  `post_logout_redirect_uri` with the client's `state`.
- **Back-channel logout.** Clients can register a `backchannel_logout_uri`.
  A trigger queues a logout token whenever one of their sessions is
  revoked, whether by logout, revocation, an operator or a disabled
  subject, in the same transaction, so none is lost. A worker in every
  instance:
  - leases due tokens
  - signs them as `logout+jwt` with the client's algorithm
  - posts them, retrying with backoff up to eight times

  Sessions that simply expire send nothing; clients know `exp`.

### Claims

Konklav holds no profile data, so it can only serve:
- the subject id
- login identifiers, with whether they were verified:
  - `email` from email-link (verified), password (not verified) and
    federated credentials (as the provider reported)
  - `phone_number` from phone-code credentials (verified)
- `groups`

`groups` lists the subject's global roles that the client's registration
lets it see, such as roles named `ops-*` for environments. ID tokens carry
`groups` but not `email` or `phone_number`: every code exchange also returns
an access token, so OpenID Connect puts a scope's claims in
`/v1/oauth2/userinfo`. A downstream Konklav reads them there before linking
by email.

A client can also ask for single claims with the `claims` request
parameter (OIDC Core 5.5), such as `name` with only the `openid` scope. A
claim is served only when a scope the client is registered for covers it,
and others are dropped, as scopes are. Claims asked for in the ID token are
honoured only for Konklav's own claims (email, phone, groups), so issuing
tokens never waits on the claims hook. `essential` is accepted, and a
missing claim isn't an error.

### Claims hook

Profile claims such as `name` come from an optional claims hook: a relying
system's endpoint, which stays the system of record. Konklav calls it only
while serving userinfo and the peer subjects endpoint, never while issuing
tokens, and only for a granted scope the hook serves:

```styx
oidc_provider {
    claims_hook {
        url https://profiles.internal/konklav/claims
        timeout_ms 1500          // the default
        on_failure omit          // or fail, which answers userinfo with 503
        cache_ttl_seconds 300    // 0, the default, caches nothing
        cache_entries 10000      // the default
        scopes {
            profile (name given_name family_name locale)
            employee (department)
        }
    }
}
```

- **Request:** `POST` with `Content-Type: application/jwt`. The body is
  signed with the ES256 ID-token key, with `typ` `konklav-claims-request+jwt`,
  so the hook verifies it against Konklav's JWKS, as it does access tokens.
  It holds:
  - `iss`, `aud` (the hook's URL), `iat`, `exp` (a minute later) and `jti`
  - `sub`, `client_id`, and `tenant` and `membership` when the session has
    them, so profiles can differ per tenant
  - `scopes` (the granted ones the hook serves) and `claims` (theirs)
- **Answer:** a JSON object. Konklav keeps only the claims configured for
  the granted scopes, and never takes its own claims (`sub`, login
  identifiers, `groups`, protocol claims) from it; configuring them is
  refused at startup. `404` means no claims.
- **Cache:** answers may be kept in memory, never in the database, by
  subject, client, tenant, membership and scopes, for at most
  `cache_ttl_seconds`. A `Cache-Control: max-age` shortens that, and
  `no-store` or `no-cache` skips caching. When the cache is full, expired
  entries go first, then the oldest.

### Passed claims

An identity provider can be configured to pass claims it reports on to
Konklav's own clients, without a claims hook, such as an upstream's `name`:

```styx
identity_providers ({
    id ops
    …
    pass_claims {
        profile (name given_name family_name locale)
    }
})
```

At a federated login, Konklav keeps the configured claims the provider
reported (from its ID token and userinfo), by scope, on the session the
login started. Client sessions started from it copy them, and userinfo
serves them for granted scopes and requested claims; a hook's value wins.
They are a copy for the session's lifetime, not profile data Konklav keeps:
each federated login brings its own, and the sweeper erases them as soon as
a session has been revoked or has expired. A chain of Konklavs passes
claims along: an upstream with a claims hook serves `name` in userinfo, a
downstream reads it at login and passes it to its own clients.

The hook keeps `r[subject.no-profile]` and
`r[platform.repo.relying-agnostic]`: Konklav names no relying system and
stores nothing it answers. The alternative, letting the login application
attach claims to the session at login, would keep profile data in Konklav's
sessions table and serve it stale until the next sign-in.

## Claim mapping

Rules live in the provider's configuration, so environments can be
reviewed and deployed like any other config:

```styx
identity_providers ({
    id operators
    issuer "https://ops.konklav.example"
    client_id prod-eu
    redirect_uri "https://prod-eu.konklav.example/v1/login/oidc/operators/callback"
    return_urls ("https://console.prod-eu.example/")
    provisioning create
    local_mfa_factors 0
    session_lifetime_seconds 3600
    require_acr "urn:konklav:acr:hwk"
    methods ({from hwk, to hwk}, {from otp, to otp})
    grants (
        {claim groups, contains sre, global_role operator}
        {claim groups, contains support, tenant "0193…", roles (agent)}
    )
})
```

The client secret goes in the secrets file, as
`identity_provider_secrets ({provider operators, client_secret …})`.

- Each rule tests one claim, with `equals` (a string) or `contains` (a
  member of a list), and grants either a global role, or a membership in a
  tenant with roles there.
- Rules are evaluated at every federated login, before the session starts,
  so the first token already reflects them.
- Global role assignments, memberships and tenant role assignments that a
  rule creates record `managed_by = provider`. When a rule stops matching,
  its managed assignments are removed and its managed memberships end
  (revoking their sessions). Grants made any other way are never touched.
  An existing membership is reused rather than taken over.
- A rule naming a role or tenant that doesn't exist is skipped with a
  warning, so a stale rule doesn't block logins.
- Mapping to capabilities goes through roles, so the catalog still says
  what each capability means. The built-in `konklav.admin` role, which
  grants `konklav:control:all`, is the usual target for an operators group.

## Deprovisioning

Plain OIDC only rechecks a subject at login, so a person removed upstream
keeps downstream sessions until they expire. In increasing strength:

1. **Short federated sessions.** A per-provider lifetime cap (one hour for
   production operators) bounds the delay without anything else.
2. **Back-channel logout.** The upstream sends a logout token to each client
   when a session ends or a subject is disabled. This works with any
   OpenID provider that supports it.
3. **Peering.** A downstream follows its upstream's peer feed: a view of
   the change feed scoped to the downstream's OIDC client.
   - The upstream emits `subject.changed` when a subject is disabled or
     re-enabled, alongside `entitlements.changed`.
   - `POST /v1/oauth2/peer/events` lists those events for subjects that
     have had a session for the calling client. An event without a subject
     means every subject may be affected, such as after a catalog change.
   - `POST /v1/oauth2/peer/subjects` returns a subject's `active` state and
     the claims the client would receive with all its scopes, including
     `groups`.
   - Both endpoints authenticate the client like the token endpoint
     (secret or `private_key_jwt`). They answer as if subjects the client
     has never seen don't exist, so a downstream learns nothing about
     anyone else and needs no service principal or capability upstream.

   A downstream with `peering` on polls the feed every ten seconds, keeping
   its place in `peer_cursor`. For each federated account an event names,
   it fetches the subject's current claims:
   - If the upstream disabled the subject or no longer knows it, the
     downstream revokes that credential's sessions and removes the
     provider's managed grants.
   - Otherwise it re-applies claim mapping to the fresh claims, as at a
     login.

   Access therefore follows upstream changes within seconds, without a new
   login. Peering only works with a Konklav upstream; other providers
   still have the first two mechanisms.

## Break-glass

Losing the upstream mustn't lock operators out of production:

- Each instance keeps a few local operator subjects with hardware-backed or
  sealed secret-key credentials, not the bootstrap token. They have the
  `operator` role locally and no federated credential.
- `PUT /v1/credentials/{id}/break-glass` marks an active password or
  secret key; federated credentials can't be marked, since they depend on
  an upstream.
- Every session started with one appends `break_glass.used` (subject,
  credential, kind, session) in the same transaction, which deployments
  alert on.
- The bootstrap token stays a first-run tool, removed once the first
  operator exists.

## Workload federation

CI and tools acting across environments get a token from the upstream and
exchange it downstream with the JWT bearer grant (`POST /v1/oauth2/token`,
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`). For example, an
upstream OIDC client bound to the job's service principal uses the client
credentials grant, with the downstream's issuer as its audience.

- The downstream accepts assertions only from identity providers with
  `workloads` on. It checks them with that provider's keys (discovered or
  pinned), and requires its own issuer or token endpoint as `aud`.
- It maps the assertion's `sub` to the local service principal that holds
  a federated credential for it. Operators create that credential on the
  control plane (`POST /v1/subjects/{id}/credentials` with
  `{"kind": "federated", "provider": …, "subject": …}`). People can't have
  workload identities; they link accounts by signing in.
- Each assertion needs a `jti` and is exchanged once. The `jti` is kept
  until the assertion expires, so a leaked token can't be exchanged again;
  a job fetches a fresh upstream token for each exchange.
- The resulting session lasts one access token, with this instance's
  audience and the `fed` method. Nothing is refreshed, and no long-lived
  secret sits in every environment.
- The grant uses the token endpoint, so the instance needs `oidc_provider`
  configured.

Token exchange (RFC 8693), for acting on behalf of a person, is deferred.

### Key pinning

`pinned_jwks_file` makes a downstream use a fixed JWKS for a provider
instead of the keys its discovery document names. The keys are never
fetched or refreshed, so a compromised discovery document or key endpoint
can't introduce a key. Rotating the upstream's keys then means updating the
file first.

## Audit and impersonation

- Federated sessions record `{provider, upstream sub}`.
- An operator impersonating a user downstream produces an actor chain whose
  actor is the operator's local subject, together with its upstream identity.
- Downstream audit trails therefore resolve to one person across every
  environment.

## What changes in existing parts

| Part | Change |
|---|---|
| Credentials | New kinds `federated` (data `{provider, sub, email?, email_verified?}`) and `client` (a client acting as a service principal) |
| Sessions | Provider and upstream subject through the federated credential; per-provider lifetime cap; the OIDC client and granted scopes for client sessions |
| Grants | `managed_by` on memberships and role assignments |
| Signing keys | An ES256 key for ID tokens, in JWKS with its `alg` |
| Control plane | OIDC clients (`konklav:clients:manage`); break-glass credentials flagged |
| Subject surface | `/v1/login/oidc/*`, linking, login-request acceptance |
| New surface paths | `/.well-known/openid-configuration`, `/v1/oauth2/authorize` (and `/resume`), `/v1/oauth2/login-requests/{id}` (and `/accept`, `/reject`), `/v1/oauth2/token`, `/v1/oauth2/userinfo`, `/v1/oauth2/revoke`, `/v1/oauth2/logout` |
| Feed | `break_glass.used`; `subject.changed`; the client-scoped peer feed |

## Decisions

Proposed defaults, to confirm before implementation:

| Decision | Proposed default | Alternatives |
|---|---|---|
| Login UI for the provider role | Hand-off to a configured login URL | A minimal hosted login page in Konklav |
| Account linking | Only while signed in; verified-email linking off unless a provider enables it with a domain allow-list | Always allow verified-email linking |
| Claim mapping location | Provider configuration (Styx), reviewed and deployed with the instance | Control-plane resources editable at runtime |
| Federated session lifetime | 1 hour for operator providers, configurable per provider | Instance-wide lifetime |
| Peering in the first release | No: short sessions and back-channel logout first, peering next | Peering from the start |
| Break-glass credential | Local secret keys with an alerting event; hardware keys once `public_key` exists | Bootstrap token |
| Second signing algorithm | ES256, and RS256 when an RSA key is configured | RS256 only (wider support, larger keys and tokens) |
| ID token claims | Subject id and groups; login identifiers from userinfo; a claims hook for the rest, in userinfo | Store profile data in Konklav; login identifiers in the ID token |
| Claims hook authentication | A request JWT signed with the ID-token key | A shared secret |
| Identity provider claims for clients | Passed claims, kept on the session until it ends | A copy on the federated credential; the upstream's refresh token kept to call its userinfo |
| SAML | Deferred; brokers translate SAML to OIDC | Native SAML |

## Phases

1. **Identity-provider client** (done): providers in configuration, PKCE,
   ID-token validation, federated credentials, linking while signed in,
   link-only provisioning, method mapping, session caps.
2. **Claim mapping and break-glass** (done): rules, managed grants,
   provisioning policy and verified-email linking, `break_glass.used`.
   Operator federation works from here.
3. **OpenID provider** (done): discovery, clients, login hand-off, codes,
   ID tokens, ES256, userinfo with groups, refresh.
4. **Provider extras** (done): client credentials with `private_key_jwt`,
   RP-initiated and back-channel logout, revocation.
5. **Peering and workloads** (done): the client-scoped peer feed, key
   pinning, the JWT bearer grant.

## Interoperability

Besides tests against Konklav's own fakes and against a second Konklav,
two suites run against independent implementations:

- **Ory Hydra as the identity provider.** Hydra is installed by mise and
  started in memory per test. The test plays its login and consent app
  through the admin API. It covers:
  - sign-in with Hydra's RS256 ID tokens and keys, over real HTTP
  - mapping its `amr` and custom claims
  - a refused login
  - Hydra's JWT client-credentials tokens accepted through the JWT bearer
    grant
- **The `openidconnect` crate as the client.** It covers:
  - discovery, including the JWKS with both Ed25519 and P-256 keys
  - the code flow with PKCE and the hand-off
  - ES256 and EdDSA ID-token verification
  - userinfo and refresh

  Its revocation helper requires HTTPS, so revocation is sent directly in
  the local test.

## Open points

- Publishing the next ES256 key ahead of a rotation, as Ed25519 keys allow.
- Token exchange (RFC 8693) for acting on behalf of a person.
- Back-channel logout for sessions that expire rather than end.
- An SSE variant of the peer feed, if polling every ten seconds proves too
  slow or too costly.
