# Tenancy And Identity

Tenants, subjects, credentials, memberships and facts.

## Tenants

r[tenant.root.bootstrap]
Conclave MUST always have a root tenant, created before any other tenant.
Its identifier is the nil UUID, and APIs MUST also accept `root` for it.

r[tenant.tree.single-parent]
Every non-root tenant MUST have exactly one parent tenant.

r[tenant.tree.no-implicit-access]
A parent-child relationship MUST NOT by itself grant any subject access in
the child tenant. Access across tenants requires a membership or an explicit
assumption grant.

r[tenant.lifecycle.states]
A tenant MUST be in exactly one of the states `active`, `suspended` or
`deleted`. Only `active` tenants accept new sessions or token issuance.

r[tenant.lifecycle.suspend-revokes]
Moving a tenant out of `active` MUST revoke every session targeting that
tenant.

r[tenant.authority]
Conclave MUST be the source of truth for tenant existence, parentage and
lifecycle state. Relying systems MAY keep projections, keyed by the same
identifier, for their own data.

r[tenant.facts]
Tenants MUST be able to carry facts declared in the action catalog.

## Subjects

r[subject.identifier.stable]
Every subject MUST have a stable identifier that never changes when its
credentials, login identifiers or memberships change.

r[subject.kind]
Every subject MUST have a kind, `human` or `service`. Service subjects MUST
NOT authenticate with interactive credentials.

r[subject.state]
A subject MUST be either `active` or `disabled`. Disabling a subject MUST
revoke all of its sessions and block new ones.

r[subject.no-profile]
Conclave MUST NOT be the system of record for subject profile data such as
display names, language or country. It stores only what authentication and
authorization need.

## Credentials

r[credential.linked]
A subject MUST be able to hold several credentials. Each credential belongs
to exactly one subject.

r[credential.identifier.unique]
A login identifier MUST be unique among active credentials of the same kind.

r[credential.history]
Credential replacement and revocation MUST preserve history. A credential
MUST NOT be overwritten in place.

r[credential.password.hashing]
Password credentials MUST be stored with a memory-hard password hash
(Argon2id). Conclave MUST be able to verify hashes imported from earlier
systems that use compatible Argon2id encodings, and MUST rehash them under
current parameters on successful login.

r[credential.secret-key.dual]
Secret-key credentials MUST support two independently rotatable keys with
their own creation and expiry times, so that a service principal can rotate
without downtime.

r[credential.secret-key.hashed]
Secret-key values MUST only be shown once, when created, and MUST be stored
as hashes.

r[credential.mfa-requirement]
A credential MUST be able to declare how many MFA factors it requires
before login completes.

r[credential.revocation-ends-sessions]
Revoking or replacing a credential MUST revoke the sessions established with
it, except where the operation explicitly keeps the caller's current
session (for example, a password change).

## Memberships

r[membership.first-class]
A subject's presence in a tenant MUST be a first-class membership record
with its own identifier.

r[membership.unique]
A subject MUST have at most one active membership per tenant.

r[membership.state]
A membership MUST be `active` or `ended`. Ending a membership MUST revoke the
sessions targeting it and remove its contributions to entitlements.

r[membership.facts]
Memberships MUST be able to carry facts declared in the action catalog.
Relying systems MAY write membership facts through the control plane.

## Facts

r[fact.typed]
Facts MUST be typed (string, integer, boolean or string list) according to
their catalog declaration. Writing a fact that is undeclared or of the wrong
type MUST fail.

r[fact.unique-keys]
A fact key MUST be declared for at most one target (tenant or membership),
so that tokens can carry tenant and membership facts side by side.

r[fact.portability]
Every fact key MUST be declared portable or non-portable. Only portable
facts may appear in tokens.

r[fact.bounded]
Conclave MUST enforce a configured size limit on the portable facts that a
token can carry.
