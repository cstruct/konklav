# Tenancy And Identity

Tenants, subjects, credentials, memberships and facts.

## Tenants

r[tenant.root.bootstrap]
Konklav MUST always have a root tenant, created before any other tenant.
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
Konklav MUST be the source of truth for tenant existence, parentage and
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
A subject MUST be `active`, `disabled` or `erased`. Disabling a subject MUST
revoke all of its sessions and block new ones. An erased subject MUST stay
erased: it MUST NOT be enabled or disabled.

r[subject.no-profile]
Konklav MUST NOT be the system of record for subject profile data such as
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
MUST NOT be overwritten in place. Erasure (`subject.erasure.removes`) is the
only operation that removes credentials.

r[credential.password.hashing]
Password credentials MUST be stored with a memory-hard password hash
(Argon2id). Konklav MUST be able to verify hashes imported from earlier
systems that use compatible Argon2id encodings, and MUST rehash them under
current parameters on successful login.

r[credential.password.hash-input]
Creating a password credential through the control plane MUST accept
either a password or an Argon2id PHC hash, but not both. A hash MUST be
rejected as an invalid request unless it parses as Argon2id with valid
parameters. Konklav then stores it as given, so the password never has to
reach Konklav.

r[credential.secret-key.dual]
Secret-key credentials MUST support two independently rotatable keys with
their own creation and expiry times, so that a service principal can rotate
without downtime.

r[credential.secret-key.hashed]
Secret-key values MUST only be shown once, when created, and MUST be stored
as hashes.

r[credential.secret-key.expiry]
An operator MUST be able to set or clear the expiry of either slot of an
active secret-key credential without changing the slot's secret, so a
key's lifetime can change without handing out new secrets.

r[credential.public-key.stored]
Public-key credentials MUST store only public material: the public key and
its algorithm, the signature counter, the attestation format and a label
chosen by the subject. Their login identifier is the credential ID in
unpadded base64url, compared case-sensitively.

r[credential.public-key.no-mfa]
Public-key credentials MUST NOT require MFA factors, because user
verification already makes a passkey login multi-factor.

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
Facts MUST be typed (string, integer, boolean, string list or date range)
according to their catalog declaration. A date range is an object with
`from` and `until` dates (`YYYY-MM-DD`), `from` not after `until`. Writing a fact that is undeclared or of the wrong
type MUST fail.

r[fact.unique-keys]
A fact key MUST be declared for at most one target (tenant, membership or
share), so that tokens can carry tenant and membership facts side by side.

## Erasure

r[subject.erasure.operation]
The control plane MUST offer an operation that erases one subject. It MUST
require a capability of its own, since it can't be undone, and it is a
change of the subject's state under `authz.control-plane.escalation`. A
caller MUST NOT be able to erase its own subject.

r[subject.erasure.removes]
Erasing a subject MUST leave Konklav holding none of its personal data. It
MUST:
- revoke the subject's sessions and the sessions started from them, such
  as impersonation sessions, and erase the claims an identity provider
  passed and the key thumbprint from each
- delete its credentials, its MFA factors and the challenges made for it,
  or sent to one of its recipients without naming a subject
- delete the login attempts recorded for its login identifiers
- end its memberships and remove their facts
- delete its role assignments, global ones included
- delete the stored `delivery.requested` events made for it, or sent to
  one of its recipients without naming a subject
- delete the remembered batch answers that name it or one of its login
  identifiers

r[subject.erasure.history]
Erasure MUST also remove the facts from every row version of the subject's
memberships, at once and whatever history's retention is.

r[subject.erasure.tombstone]
An erased subject MUST keep its id, kind and state `erased`, with the time
of erasure, and nothing else. Its id MUST NOT be given to another subject,
and creating a subject with that id MUST fail with `SUBJECT_ERASED`.

r[subject.erasure.atomic]
Erasure MUST happen in one transaction, together with the events it
causes. A failed erasure MUST change nothing.

r[subject.erasure.idempotent]
Erasing an erased subject MUST succeed, change nothing and append no
events.

r[subject.erasure.blocks-writes]
Every later operation that would give an erased subject a credential, MFA
factor, membership, role assignment, challenge or session MUST fail with `SUBJECT_ERASED`, whichever way it arrives: the control
plane, a batch, an import, a bootstrap set or an identity provider's claim
mapping.

r[subject.erasure.identifier-released]
After erasure, each of the subject's login identifiers MUST be free for
another subject to take, and authenticating with one MUST fail exactly as
for a login identifier Konklav has never seen
(`platform.error.no-enumeration`).

r[subject.erasure.bound-client]
Erasing a service principal that an OIDC client authenticates as MUST fail
with a conflict until the client is disabled. Enabling such a client again
MUST fail with `SUBJECT_ERASED`.

r[subject.erasure.event]
Erasure MUST append one `subject.erased` event after the `session.changed`
and `entitlements.changed` events it causes.

r[subject.erasure.list]
The relying surface MUST let a service principal read the erased subjects'
ids with their times of erasure, ordered by that time, in pages, from a
time the caller gives. It MUST cover every erasure there has ever been, so
that a relying system can catch up however long it was away.

r[subject.erasure.entitlements]
The relying surface MUST answer for an erased subject as for any subject
that holds nothing: an empty entitlement set and denied checks.

## Personal data reports

r[subject.report.contents]
The control plane MUST offer a personal data report for one subject,
holding:
- the subject
- its credentials: kind, login identifier, times, and for a federated
  credential the provider with what it reported, for a passkey its label
- its MFA factors: kind and, for an email factor, the address
- its memberships with their facts, and its role assignments
- its sessions that have not been deleted: times, authentication methods,
  client kind, OIDC client and the claims an identity provider passed
- its challenges that have not been deleted: purpose, recipient and times

r[subject.report.no-secrets]
A personal data report MUST NOT hold password hashes, secret keys, MFA
seeds, passkey key material, refresh-token hashes or challenge material.

r[subject.report.erased]
The personal data report of an erased subject MUST hold only what
`subject.erasure.tombstone` keeps.

r[subject.report.complete]
Every place Konklav stores personal data MUST be covered by both
`subject.erasure.removes` and `subject.report.contents`. Adding such a
place without deciding both MUST fail verification.

r[fact.portability]
Every fact key MUST be declared portable or non-portable. Only portable
facts may appear in tokens, and share facts MUST NOT be portable.

r[fact.bounded]
Konklav MUST enforce a configured size limit on the portable facts that a
token can carry.
