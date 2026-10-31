# Federation

OpenID Connect in both directions: Konklav signing subjects in through
identity providers, and Konklav acting as an OpenID provider for
applications and other Konklav instances. Federation between Konklav
instances builds on both and adds a few capabilities only peers have.

Status: implemented. The rationale and the decisions behind
these rules are in
[`../architecture/oidc-and-federation.md`](../architecture/oidc-and-federation.md).

## Identity providers

r[federation.idp.config]
Each identity provider MUST be configured with an issuer, a client id,
client authentication from secret configuration (a client secret or a
private key), requested scopes, claim mapping rules and a provisioning
policy. Endpoints and keys MUST come from the issuer's discovery document
unless they are pinned in configuration.

r[federation.idp.code-flow]
Federated login MUST use the authorization code flow with PKCE (`S256`).
The `state`, `nonce` and code verifier MUST be kept as a single-use
challenge bound to the browser that started the login. Implicit and hybrid
flows MUST NOT be supported.

r[federation.idp.id-token]
An ID token MUST be rejected unless its signature verifies against the
provider's keys with an asymmetric algorithm, and its `iss`, `aud`, `azp`
(when present), `exp`, `iat` and `nonce` match. `alg: none` and symmetric
algorithms MUST be refused.

r[federation.idp.userinfo]
When the provider's discovery document names a `userinfo_endpoint` and the
token response carries an access token, the provider's UserInfo response
MUST be fetched with it and its claims added to the ID token's, for linking,
provisioning and claim mapping. The ID token's claims MUST win where both
hold one. The login MUST fail if the UserInfo request fails or its `sub`
differs from the ID token's.

r[federation.jwks-refresh]
A token naming a key the provider's cached keys lack MAY cause the keys to
be fetched again, but at most once a minute per provider, so tokens with
made-up key ids can't make Konklav fetch the provider's keys on every
request.

r[federation.local-mfa]
Each identity provider's configuration MUST state how many local MFA
factors a sign-in through it needs, with no default. When it needs any, the
federated credential MUST require them, and the browser MUST get a partial
session, with no refresh token until MFA completes, that it completes with
MFA as after a password login.

r[federation.credential]
A federated credential MUST be identified by the provider and the
provider's `sub`, never by an email address or another mutable claim.

r[federation.linking]
A federated credential MUST only be linked to an existing subject while that
subject is signed in, or when the provider's policy allows linking by an
email address that the provider reports as verified and whose domain the
policy allows. Unverified claims MUST NOT link accounts.

r[federation.provisioning]
A federated login without a linked subject MUST create one only if the
provider's provisioning policy allows it; otherwise it MUST fail without
revealing whether a matching subject exists.

r[federation.methods]
The provider's `amr` and `acr` values MUST be mapped to Konklav
authentication methods through configuration; unmapped values MUST NOT be
credited. A provider MAY be configured to require `acr_values` and a
`max_age`, and a login whose ID token doesn't satisfy them MUST fail.

r[federation.session]
A federated login MUST create an ordinary Konklav session. The provider's
tokens MUST NOT be passed to relying systems, and the provider's refresh
token MUST NOT be stored unless configuration requires it.

r[federation.session-lifetime]
Each provider MUST be able to cap the lifetime of sessions it creates,
independently of the instance-wide session lifetime.

## Claim mapping

r[federation.mapping.rules]
Claim mapping rules MUST be able to grant global roles, memberships and
tenant roles based on claim values, and MUST be re-evaluated at every
federated login.

r[federation.mapping.managed]
Grants created by claim mapping MUST record the provider that manages them.
Re-evaluation MUST remove managed grants that no longer match and MUST NOT
change grants that the provider doesn't manage.

## OpenID provider

r[oidc.provider.discovery]
When the provider role is enabled, Konklav MUST publish an OpenID Provider
discovery document listing only the endpoints, grants, algorithms and claims
it supports.

r[oidc.provider.jwks]
The key set the discovery document names MUST be served on the
subject-facing surface, where the issuer is, as well as on the relying
surface, so clients that can reach only the issuer can verify ID tokens.

r[oidc.provider.clients]
OIDC clients MUST be control-plane resources with a caller-supplied id, a
type (`confidential` or `public`), registered redirect URIs, allowed grants
and scopes, the audience of their access tokens, and the claims they may
receive. Redirect URIs MUST match exactly.

r[oidc.provider.client-audience]
A client's audience MUST NOT be Konklav's own access-token audience, so
tokens issued to a client are never accepted by Konklav's own surfaces.

r[oidc.provider.error-page]
An authorization request whose error can't be sent to the client, because
its client or redirect URI isn't known good, MUST be answered with a
human-readable page, never a redirect.

r[oidc.provider.code-flow]
The authorization endpoint MUST accept requests by `GET` and by form
`POST`. It MUST require PKCE (`S256`) from every client, unless a
confidential client is registered without it. A token request MUST present
a `code_verifier` exactly when the authorization request sent a
`code_challenge`. Authorization codes MUST be single-use, short-lived, and
bound to the client, the redirect URI, the code challenge, the nonce and
the session. A missing `response_type` MUST be refused as
`invalid_request`, and any other than `code` as
`unsupported_response_type`.

r[oidc.provider.scopes]
An authorization request MUST include the `openid` scope. Other scopes the
client may not have MUST be dropped rather than refused, and the token
response MUST say which scopes were granted.

r[oidc.provider.request-objects]
Konklav doesn't support request objects or the `claims` parameter. A request
with `request` or `request_uri` MUST be refused with `request_not_supported`
or `request_uri_not_supported`, and discovery MUST say that none of the
three is supported.

r[oidc.provider.prompt]
The login request MUST carry the request's `prompt` and `login_hint` to the
login application. With `prompt=login`, Konklav MUST accept only a session
whose sign-in happened after the request started. A `prompt` combining
`none` with another value MUST be refused as `invalid_request`.

r[oidc.provider.login-refusal]
A login application MUST be able to refuse a login request with
`login_required`, `interaction_required`, `consent_required`,
`account_selection_required` or `access_denied`, as it must for `prompt=none`
when nobody is signed in. Konklav MUST then send that error to the client's
redirect URI, through the browser that started the request, as it would a
code.

r[oidc.provider.userinfo]
The UserInfo endpoint MUST accept `GET` and `POST`, with the access token in
the `Authorization` header or, for `POST`, in the form body. A missing or
invalid access token MUST be answered with 401 and a
`WWW-Authenticate: Bearer` challenge.

r[oidc.provider.token-errors]
Token endpoint responses MUST NOT be cached. A client that failed to
authenticate with HTTP basic credentials MUST be answered with 401 and a
`WWW-Authenticate: Basic` challenge.

r[oidc.provider.code-reuse]
Presenting an authorization code that was already exchanged MUST fail and
MUST revoke the session it was exchanged for, ending every token issued
from it.

r[oidc.provider.login-handoff]
The authorization endpoint MUST NOT render user interface. It MUST redirect
to the login URL configured for the client or the instance with an opaque
login request, which a login application completes by presenting a session
that satisfies the request (including any `max_age` and `acr_values`).
Only then MUST Konklav issue the authorization code, and only to a browser
that proves it both started the request and received its acceptance, so a
request started by one person can't be completed with another's session.

r[oidc.provider.id-token]
ID tokens MUST carry `iss`, `sub` (the subject id), `aud` (the client id),
`exp`, `iat`, `auth_time`, `nonce` when one was sent, `amr`, `acr` and
`sid`, and `groups` when the client may receive it. Claims of the `email`
and `phone` scopes MUST only be served from the UserInfo endpoint, since an
access token is always issued with the ID token.

r[oidc.provider.algorithms]
Signing keys MUST support `ES256` in addition to `EdDSA`, and `RS256`, which
OpenID Connect requires providers to offer, when an RSA key of at least 2048
bits is configured. Discovery MUST list only the algorithms whose keys are
configured, and a client MUST NOT be registered for one that isn't. JWKS
MUST publish each key's `alg`, and ID tokens MUST be signed with the
algorithm the client is registered for.

r[oidc.provider.tokens]
Access tokens issued through OIDC MUST be Konklav access tokens with the
client's audience, so relying systems verify them unchanged. OIDC refresh
tokens MUST be the session's refresh tokens, with the same rotation and
reuse detection.

r[oidc.provider.tenant]
A client MUST be able to target a tenant, either with a `tenant:<id>` scope
or through tenant selection in the login application. Tokens then carry the
tenant and membership as they do for direct logins.

r[oidc.provider.claims]
`userinfo` and ID tokens MUST only contain claims Konklav holds (the
subject id, login identifiers with their verification state, and group
claims) and those of a claims hook. A scope's claims MUST come from
the credential signed in with when it holds them, and otherwise from the
subject's other active credentials, preferring a verified email address. Konklav MUST NOT store profile
data to serve claims.

r[oidc.provider.claims-hook]
A claims hook, when configured, MUST only be called while serving userinfo
and the peer subjects endpoint, never while issuing tokens, and only when
the access token's granted scopes include a scope the hook serves.

r[oidc.provider.claims-hook.request]
The hook MUST be called with a `POST` whose body is a JWT signed with the
ID-token key, with `typ` `konklav-claims-request+jwt`, the hook's URL as
`aud`, an expiry of at most a minute, and the subject, client, tenant and
membership, and the granted scopes the hook serves with their claims.

r[oidc.provider.claims-hook.scopes]
Only the claims configured for the granted scopes MUST be passed on from
the hook's answer. Claims Konklav serves itself, and the protocol claims,
MUST NOT be taken from it. A `404` MUST mean the hook has no claims for the
subject.

r[oidc.provider.claims-hook.failure]
When the hook fails, times out or answers badly, userinfo MUST either be
served without the hook's claims or refused with `503`, as configured.

r[oidc.provider.claims-hook.cache]
What the hook returns MUST NOT be stored in the database. It MAY be cached
in memory, by subject, client, tenant, membership and scopes, for at most the
configured time to live, shortened by the answer's `Cache-Control`
(`max-age`, or `no-store` to skip caching). The cache MUST hold a bounded
number of entries.

r[oidc.provider.groups]
A client MAY receive a `groups` claim listing the subject's global roles
that the client's registration allows it to see, and no others.

r[oidc.provider.client-credentials]
Service principals MUST be able to obtain access tokens with the client
credentials grant, authenticating with a client secret or `private_key_jwt`.

r[oidc.provider.revocation]
Clients MUST be able to revoke a refresh or access token they were issued
(RFC 7009), which MUST end the session behind it. Revoking an unknown token
MUST succeed without effect.

r[oidc.provider.logout]
Konklav MUST support RP-initiated logout, and MUST send back-channel logout
tokens to clients that registered a back-channel URI whenever a session
they received tokens for ends.

## Federation between instances

r[federation.peer.standard]
Federation between Konklav instances MUST work with only the rules above,
so an upstream instance can be replaced by another OpenID provider.
Peer-only capabilities MUST be optional.

r[federation.peer.feed]
An upstream Konklav MUST offer each OIDC client a view of its change feed
limited to subjects that have had a session for that client, and the
current claims and state of such a subject. Only confidential clients,
authenticated with a secret or a signed assertion, MAY read this view;
public clients MUST be refused. A downstream instance MAY
follow it. When it does, it MUST revoke the sessions of subjects the
upstream disables, and MUST re-evaluate managed grants when a subject's
claims change, within its polling interval.

r[federation.peer.pinning]
A downstream instance MUST be able to pin the upstream's signing keys
instead of discovering them.

## Break-glass

r[federation.break-glass]
An instance MUST support local operator credentials that work while every
upstream is unavailable. Each use MUST append a `break_glass.used` event.

## Workload federation

r[federation.jwt-bearer]
The token endpoint MAY accept JWT bearer assertions (RFC 7523) from a
configured upstream. An accepted assertion MUST map, by upstream issuer and
`sub`, to a local service principal, and the issued token MUST be that
principal's.

r[federation.jwt-bearer.replay]
An assertion MUST carry a `jti`, and each one MUST be exchanged at most
once per upstream issuer until it expires.

## Audit

r[federation.audit]
Sessions created from federated credentials MUST record the provider and
the provider's subject, and actor chains MUST carry them, so actions trace
back to the upstream identity.
