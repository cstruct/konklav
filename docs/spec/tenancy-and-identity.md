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

r[tenant.key]
A tenant MAY have a key that matches `[a-z]+(-[a-z]+)*`, is at most 63
characters long, isn't `root`, and is unique among all tenants. It MAY be
given when the tenant is created, or set later on a tenant that has none,
and MUST NOT change or be removed once set, so no other tenant can take it.
Setting a tenant's key to the one it has MUST answer as the first time.

r[tenant.key.reference]
Wherever Konklav takes a tenant reference, a UUID or `root`, on any surface,
in a `tenant:` scope or in configuration, it MUST also take a tenant key
and treat it as the tenant that has it. A key no tenant has MUST be answered
exactly as a UUID of no tenant is. Tokens, events and stored records MUST
keep identifying tenants by UUID.

r[tenant.key.event]
`tenant.changed` MUST carry the tenant's key, and setting a key MUST emit
it.

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

r[credential.mfa-seed.bound]
A TOTP seed MUST be encrypted bound to its MFA factor and that factor's
subject, as authenticated data of the encryption, so that its ciphertext
stored on another factor, or its factor moved to another subject, does not
decrypt. The stored ciphertext MUST say that it is bound, and one that does
MUST NOT be decrypted without its binding. Seeds stored before they were
bound MUST keep decrypting, and stay unbound until the factor is enrolled or
imported again.

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

## Access requests

r[membership.access-request]
When configured, a signed-in human subject whose login is complete (not
`partial`) MUST be able to request a membership in an active tenant that
takes access requests and where it has no active membership. A subject MUST
have at most one pending request per tenant; asking again while one is
pending MUST answer that one.

r[membership.access-request.disclosure]
A request for a tenant that doesn't exist, isn't active or takes no access
requests MUST be refused with the same answer, so that requests disclose
no tenant that doesn't take them.

r[membership.access-request.retry]
After a denial, a new request from the same subject for the same tenant
MUST be refused until a configured time has passed.

r[membership.access-request.decision]
A pending request MUST be decided once: approved or denied by an operator
holding `konklav:tenants:manage`, or by a member of its tenant as
`membership.access-request.tenant` allows, or withdrawn by its subject. Approving MUST
create the membership, with the facts and role assignments the approval
names, in the same transaction; when the subject has become a member
meanwhile, approving MUST record that membership and create none. Deciding
a request again the same way MUST answer as the first time; deciding it
another way MUST fail.

r[membership.access-request.tenant]
On the subject-facing surface, a subject with a full session that isn't
impersonated and that holds `konklav:tenant:admit` tenant-wide in a tenant
(`authz.tenant-capability`) MUST be able to list, approve and deny the
access requests to that tenant, and MUST be refused for any other tenant,
and with a partial session. A request to another tenant MUST be not found.
No one MAY decide their own request. An approval MUST give only roles of the
tenant that the decider's active membership there is assigned tenant-wide,
and none whose policies, or whose template's, name a `konklav:` action, so
no one admits another into more than they hold and the capability doesn't
spread through approvals.

r[membership.access-request.decider]
A decided request MUST record who decided it: the member or operator who
approved or denied it (none for the bootstrap token), or the subject who
withdrew it (none when erasure withdrew it). Listing and getting requests
MUST show it.

r[membership.access-request.event]
Every new or decided access request MUST emit `access_request.changed`
carrying the request's id, subject, tenant, state and, once approved, the
membership.

r[membership.access-request.erasure]
Erasing a subject MUST withdraw its pending access requests.

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
  or sent to one of its own addresses (`subject.erasure.own-addresses`)
  without naming a subject
- delete the login attempts recorded for its own addresses
- end its memberships and remove their facts
- delete its role assignments, global ones included
- delete the stored `delivery.requested` events made for it, or sent to
  one of its own addresses without naming a subject
- delete the remembered batch answers that name it or one of its own
  addresses

r[subject.erasure.own-addresses]
Where erasure or the personal data report matches data that doesn't name
the subject, it MUST match by the subject's own addresses only: the login
identifiers of its credentials, the email addresses its federated
credentials carry, and the email addresses of the MFA factors it has
proven. The address of a factor that was never proven, and the recipient
of a challenge made for the subject, MUST NOT count, since anyone can name
any address there. An address that another subject holds at the time, as
the login identifier of a credential that isn't revoked or in a proven MFA
factor that isn't removed, MUST NOT count either, unless it is the login
identifier of one of the subject's own credentials that isn't revoked.

r[subject.erasure.metadata]
Erasure MUST remove the metadata of the subject, of its credentials, of
its memberships and of the invites among the challenges it deletes, which
include the invites the subject redeemed. It MUST remove that metadata
from stored `metadata.changed` and `invite.redeemed` events too, at once,
without waiting for the retention that `metadata.erasure` allows.

r[subject.erasure.history]
Erasure MUST also remove the facts and the metadata from every row version
of the subject's memberships, and the metadata from every row version of
the subject, at once and whatever history's retention is.

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
A write that is under way while the erasure commits MUST either be erased
with the rest or fail the same way.

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
- the subject, with its metadata
- its credentials: kind, login identifier, times, metadata, and for a
  federated credential the provider with what it reported, for a passkey
  its label
- its MFA factors, removed ones included: kind and, for an email factor,
  the address
- its memberships with their facts and metadata, and its role assignments
- its sessions that have not been deleted: times, authentication methods,
  client kind, OIDC client, the claims an identity provider passed and the
  key thumbprint
- the challenges that erasure would delete: purpose, recipient, times
  and, for an invite, its metadata
- the login attempts that erasure would delete: time, kind of credential,
  login identifier, outcome and address

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
