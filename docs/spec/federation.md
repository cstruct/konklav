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

r[oidc.provider.clients]
OIDC clients MUST be control-plane resources with a caller-supplied id, a
type (`confidential` or `public`), registered redirect URIs, allowed grants
and scopes, the audience of their access tokens, and the claims they may
receive. Redirect URIs MUST match exactly.

r[oidc.provider.code-flow]
The authorization endpoint MUST require PKCE (`S256`) for every client.
Authorization codes MUST be single-use, short-lived, and bound to the
client, the redirect URI, the code challenge, the nonce and the session.

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
`sid`, and only the further claims the client may receive.

r[oidc.provider.algorithms]
Signing keys MUST support `ES256` in addition to `EdDSA`. JWKS MUST publish
each key's `alg`, and ID tokens MUST be signed with the algorithm the client
is registered for.

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
claims) unless a claims hook is configured. Konklav MUST NOT store profile
data to serve claims.

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

## Audit

r[federation.audit]
Sessions created from federated credentials MUST record the provider and
the provider's subject, and actor chains MUST carry them, so actions trace
back to the upstream identity.
