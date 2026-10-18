# OIDC and federation

Status: accepted. Phases 1 and 2 (identity providers, claim mapping and
break-glass) are implemented; later phases are designed only. The rules are in
[`../spec/federation.md`](../spec/federation.md); this note explains them
and lists the decisions still open. It replaces the earlier "federation is
out of scope" position.

## Goals

1. **Sign in through identity providers.** Corporate IdPs, social logins,
   and national eID schemes through an OIDC broker, so that eID doesn't need
   native integrations.
2. **Be an identity provider.** Applications and tools sign in with
   standard OIDC libraries instead of Conclave's `/v1` API, and each gets
   its own audience and claims.
3. **Federate operators across instances.** One operators' instance holds
   the people who run the platform. Dev, staging and each production region
   run their own Conclave and trust it for operator sign-in and access,
   without copying end-user data between them.

## Topology for operators

```
              ┌──────────────────────────┐
              │ operators' Conclave      │  OpenID provider
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

## Conclave as a client of identity providers

1. `GET /v1/login/oidc/{provider}/start` creates a challenge holding
   `state`, `nonce` and the PKCE verifier, sets a short-lived cookie
   binding it to the browser, and redirects to the provider.
2. `GET /v1/login/oidc/{provider}/callback`:
   - checks `state` against the cookie and consumes the challenge
   - exchanges the code
   - validates the ID token
3. It then resolves the federated credential:
   - linked: use its subject
   - otherwise: link or provision per policy
   - neither allowed: fail with the same error as an unknown account
4. It maps `amr`/`acr` to Conclave methods, applies claim mapping, and
   starts an ordinary session, with the provider's session-lifetime cap.
5. It redirects to the configured return URL. The browser receives the
   refresh cookie exactly as for a password login.

Linking an extra provider to an existing subject happens while signed in:
`POST /v1/credentials/oidc/{provider}/link` (with the access token, an
allowed `Origin` and the client header) returns the provider URL and sets
the state cookie, and the callback links the account to that subject. Only
linking while signed in avoids account takeover through a provider that
reports an email it doesn't own.

The callback redirects to the return URL with `signed_in=true`,
`linked=true`, or `error=` one of `provider_error`, `invalid_id_token`,
`requirements_not_met`, `account_not_linked` and
`account_linked_elsewhere`. Linking enforces the provider's `acr` and
`max_age` requirements too.

## Conclave as an OpenID provider

The provider role reuses sessions, refresh rotation, access tokens and step
up. New pieces:

- **Clients**: a control-plane resource (`PUT /v1/oidc/clients/{id}`).
- **Login requests**: the state of an `/oauth2/authorize` call while the
  subject signs in.
- **Authorization codes**: stored hashed, single-use, about 60 seconds.
- **ID tokens and ES256 keys**: many OIDC libraries can't verify EdDSA, so
  each signing key set gains an ES256 key, published in JWKS with its `alg`.
  Access tokens stay EdDSA, because relying systems verify them through the
  SDK.

### Login hand-off instead of a hosted page

Conclave has no user interface, and `/oauth2/authorize` doesn't add one:

1. The client redirects to `/oauth2/authorize`. Conclave validates the
   client, redirect URI and PKCE, stores a login request, and redirects to
   the login URL with `login_request=<id>`.
2. The login application (a relying system's frontend, or a small
   operators' login app) signs the subject in through the existing `/v1`
   API, including MFA, step-up and tenant selection.
3. It calls `POST /v1/oauth2/login-requests/{id}/accept` with the session's
   access token. Conclave checks `max_age` and `acr_values` against the
   session, issues the code, and returns the redirect URL to the client.

Consent screens are left to the login application. First-party clients are
registered as pre-consented.

### Claims

Conclave holds no profile data, so it can only serve:
- the subject id
- login identifiers (email, phone), with whether they were verified
- groups

`groups` lists the subject's global roles that the client's registration
lets it see, such as roles named `ops:*` for environments. Richer profile
claims come from an optional claims hook: a relying-system endpoint that
Conclave calls with the subject id. That keeps
`r[platform.repo.relying-agnostic]`.

## Claim mapping

Rules live in the provider's configuration, so environments can be
reviewed and deployed like any other config:

```styx
identity_providers ({
    id operators
    issuer "https://ops.conclave.example"
    client_id prod-eu
    redirect_uri "https://prod-eu.conclave.example/v1/login/oidc/operators/callback"
    return_urls ("https://console.prod-eu.example/")
    provisioning create
    session_lifetime_seconds 3600
    require_acr "urn:conclave:acr:hwk"
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
- Mapping to capabilities goes through roles (for example `operator`
  granting `conclave:control:all`), so the catalog still says what each
  capability means.

## Deprovisioning

Plain OIDC only rechecks a subject at login, so a person removed upstream
keeps downstream sessions until they expire. In increasing strength:

1. **Short federated sessions.** A per-provider lifetime cap (one hour for
   production operators) bounds the delay without anything else.
2. **Back-channel logout.** The upstream sends a logout token to each client
   when a session ends or a subject is disabled. This works with any
   OpenID provider that supports it.
3. **Peering through the change feed.** A downstream instance follows the
   upstream's feed as a relying system, through the relying SDK it already
   ships. On `subject.changed` (disabled) it revokes the subject's federated
   sessions. That event doesn't exist yet: subject state changes only show
   today as `session.changed` for the revoked sessions, so peering adds it. On `entitlements.changed` for a federated subject, it fetches
   the entitlement set, re-evaluates mapping, and adjusts managed grants
   immediately. The delay becomes the feed's propagation delay, typically
   seconds.

Peering needs a service principal at the upstream for each downstream,
holding a read-only capability for the subjects it federates. Most of
this machinery already exists.

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

CI and tools acting across environments get a token from the upstream
(client credentials) and exchange it downstream with the JWT bearer grant
(`/oauth2/token`, `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`).
The downstream maps the upstream issuer and `sub` to a local service
principal, so no long-lived secret keys sit in every environment. Token
exchange (RFC 8693) for acting on behalf of a person is deferred.

## Audit and impersonation

- Federated sessions record `{provider, upstream sub}`.
- An operator impersonating a user downstream produces an actor chain whose
  actor is the operator's local subject, together with its upstream identity.
- Downstream audit trails therefore resolve to one person across every
  environment.

## What changes in existing parts

| Part | Change |
|---|---|
| Credentials | New kind `federated` with data `{provider, sub, email?, email_verified?}` |
| Sessions | `federation` (provider, upstream subject) recorded with the session; per-provider lifetime cap |
| Grants | `managed_by` on memberships and role assignments |
| Signing keys | A second algorithm (ES256), `alg` in JWKS |
| Control plane | OIDC clients; break-glass credentials flagged |
| Subject surface | `/v1/login/oidc/*`, linking, login-request acceptance |
| New surface paths | `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/revoke`, `/oauth2/logout` |
| Feed | `break_glass.used`, and `subject.changed` for peering |

## Decisions

Proposed defaults, to confirm before implementation:

| Decision | Proposed default | Alternatives |
|---|---|---|
| Login UI for the provider role | Hand-off to a configured login URL | A minimal hosted login page in Conclave |
| Account linking | Only while signed in; verified-email linking off unless a provider enables it with a domain allow-list | Always allow verified-email linking |
| Claim mapping location | Provider configuration (Styx), reviewed and deployed with the instance | Control-plane resources editable at runtime |
| Federated session lifetime | 1 hour for operator providers, configurable per provider | Instance-wide lifetime |
| Peering in the first release | No: short sessions and back-channel logout first, peering next | Peering from the start |
| Break-glass credential | Local secret keys with an alerting event; hardware keys once `public_key` exists | Bootstrap token |
| Second signing algorithm | ES256 | RS256 (wider support, larger keys and tokens) |
| ID token claims | Subject id, login identifiers and groups; a claims hook for the rest | Store profile data in Conclave |
| SAML | Deferred; brokers translate SAML to OIDC | Native SAML |

## Phases

1. **Identity-provider client** (done): providers in configuration, PKCE,
   ID-token validation, federated credentials, linking while signed in,
   link-only provisioning, method mapping, session caps.
2. **Claim mapping and break-glass** (done): rules, managed grants,
   provisioning policy and verified-email linking, `break_glass.used`.
   Operator federation works from here.
3. **OpenID provider**: discovery, clients, login hand-off, codes, ID tokens,
   ES256, userinfo with groups, refresh.
4. **Provider extras**: client credentials, RP-initiated and back-channel
   logout, revocation.
5. **Peering and workloads**: following the upstream feed, key pinning, the
   JWT bearer grant.
