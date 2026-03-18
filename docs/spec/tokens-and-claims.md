# Tokens And Claims

This file defines the initial JWT payload model for delegated tenant access and decentralized authorization.

## Access token envelope

r[token.access.jwt.standard-claims]
Access tokens MUST be JWTs that include standard claims for issuer, subject, audience, token identifier, issued-at time, and expiry.

r[token.access.context.target-tenant]
Access tokens MUST identify the target tenant context in a dedicated claim so resource servers can reject tokens presented against the wrong tenant boundary.

r[token.access.context.actor-chain]
When a token represents delegated or assumed access, it MUST carry the originating actor chain, including the source subject and source tenant, in a structured claim.

## Authorization snapshot

r[token.access.authz.snapshot-claim]
Access tokens MUST carry a dedicated authorization snapshot claim containing compiled entitlements rather than raw role definitions or raw policy source.

r[token.access.authz.catalog-revision]
The authorization snapshot MUST identify the action catalog revision used when compiling token entitlements.

r[token.access.authz.policy-revision]
The authorization snapshot MUST identify the policy or entitlement revision used when compiling token entitlements.

r[token.access.authz.tenant-bits]
The authorization snapshot MUST support a compact representation for tenant-wide allowed actions, such as a bitmap keyed to the action catalog revision.

r[token.access.authz.scoped-bits]
The authorization snapshot MUST support scoped entitlement entries that bind a tenant-local scope kind and scope identifier to a compact representation of allowed actions.

r[token.access.authz.portable-facts]
The authorization snapshot MUST carry only portable subject or session facts that are safe for offline evaluation by downstream services.

r[token.access.authz.no-arbitrary-dsl]
Access tokens MUST NOT embed arbitrary executable policy expressions or an unbounded policy DSL.

## Token use

r[token.access.use.offline-evaluation]
Relying systems validating an access token MUST combine token signature validation, expiry checks, tenant-context checks, and local resource-context evaluation over the compiled authorization snapshot.

r[token.access.use.staleness-bounds]
Offline authorization decisions based on token-carried entitlements MUST be bounded by token expiry and by a defined strategy for catalog or policy revision invalidation.

r[token.access.jwt.asymmetric-signing]
Access tokens intended for relying-system validation MUST support asymmetric signing so verification keys can be distributed without sharing signing secrets.

r[token.access.jwt.jwks-publication]
The platform MUST publish verification keys for relying-system token validation through a JWKS-compatible surface.

## Illustrative payload

The initial claim layout can follow a structure like this:

```json
{
  "iss": "https://conclave.example",
  "sub": "019c2950-612b-71a0-ba14-eb8ea9cd37dc",
  "aud": "clinic-api",
  "jti": "019cfbe5-efde-7923-9bdf-564233276fe9",
  "iat": 1773752676,
  "exp": 1773754476,
  "tid": "tenant-root-child-123",
  "act": {
    "sub": "019c2950-612b-71a0-ba14-eb8ea9cd37dc",
    "tid": "tenant-root"
  },
  "az": {
    "catalog_rev": 2,
    "policy_rev": 481,
    "tenant_bits": "qg",
    "scopes": [
      {
        "kind": "clinic",
        "id": "09c7578e-0a07-4257-a4af-bf5c3ca121cb",
        "bits": "8A"
      }
    ],
    "facts": {
      "authn_level": 2
    }
  }
}
```

The exact encoding of compact action sets can change, but the semantics MUST remain stable with respect to the advertised catalog and policy revisions.
