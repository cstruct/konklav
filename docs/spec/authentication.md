# Authentication

Login, MFA, step-up, sessions, session flags, challenges and delivery.

## Login

r[authn.login.methods]
Konklav MUST support login with a password credential, with a phone
one-time code, with an email magic link, with a passkey, and with a
secret-key credential for service principals.

r[authn.login.staged]
Login MUST proceed through explicit stages, each issuing a token that is
valid only for the next step:
- *partial*: the first factor succeeded but MFA is still required
- *identity*: the subject is authenticated but no tenant is selected
- *tenant*: the session targets one membership in one tenant

r[authn.login.tenant-selection]
Moving from the identity stage to the tenant stage MUST require an active
membership of the subject in an active target tenant. The session MUST
record that membership.

r[authn.login.single-tenant-context]
A session MUST target at most one tenant at a time. Switching tenant MUST
bump the session version.

r[authn.login.rate-limit]
Login attempts MUST be rate-limited per credential and per login identifier,
over several windows (for example minutes, hours and days), and per client
address across identifiers, more loosely, so one source can't try many
identifiers. An attempt MUST
count toward the limit while it is being checked, so concurrent attempts
can't exceed it, and every check of a credential's secret MUST count,
including those made for step-up and password change.

r[authn.login.hashing-bound]
Password and secret-key hashing MUST run with bounded concurrency, so a
burst of login attempts queues instead of exhausting CPU.

r[authn.login.timing]
Failed and successful first-factor attempts MUST NOT be distinguishable by
response time beyond a configured jitter.

r[authn.pacing]
Endpoints whose response time could reveal whether a login identifier,
subject or credential exists (first-factor login, MFA completion, step-up,
starting and completing passwordless login and password reset, password
change and invite redemption) MUST NOT respond before a configured floor
plus or minus a random jitter, measured from the request's arrival. The
work and the wait MUST run concurrently, so the floor adds no latency when
the work takes longer.

## MFA and step-up

r[authn.mfa.factors]
Konklav MUST support TOTP and emailed one-time codes as MFA factors.

r[authn.mfa.secrets-encrypted]
TOTP secrets MUST be stored encrypted under keys from secret configuration,
with support for several active decryption keys so they can be rotated.

r[authn.mfa.partial-factors]
A partial session MUST be able to list its subject's active MFA factors, so
the client can offer one to complete login with. It MUST NOT see inactive
factors or enroll, activate or remove any.

r[authn.mfa.attempts]
TOTP verification MUST be limited per factor over several windows, counting
every failed check, and MUST NOT accept the same time step twice, even for
concurrent requests.

r[authn.mfa.factor-codes]
An emailed MFA code MUST be checked against the newest code sent for that
factor, and sends to a factor's address MUST be limited per subject, so a
factor another subject registered for the same address can't block or use
up its codes.

r[authn.mfa.management]
Enrolling, activating or removing an MFA factor MUST require a full session
that authenticated recently, so a stolen access token can't add or strip
factors.

r[authn.mfa.factor-listing]
The control plane MUST show a subject's MFA factors with their kind,
whether they are active and, for email-code factors, their address. It
MUST NOT show a factor's seed or codes.

r[authn.mfa.amr]
Every session MUST record the authentication methods used, as `amr`
values, together with the time of the last authentication. A method MUST use
its RFC 8176 value where one fits, and otherwise a Konklav-specific value
listed in the nomenclature.

r[authn.step-up.demand]
When an operation requires authentication methods or recency that the
session lacks, the decision MUST be a step-up demand carrying the
requirement, not a plain denial.

r[authn.step-up.in-session]
Completing step-up MUST update the existing session's `amr` and
authentication time and bump its version. It MUST NOT create a new session.

## Passkeys

r[authn.passkey.registration]
A human subject MUST be able to register a passkey only from a full session
(identity or tenant stage) that authenticated recently. The
ceremony's challenge MUST be single-use, bound to that session, and expire.
Passkeys MUST NOT be created any other way.

r[authn.passkey.discoverable]
Passkey login MUST NOT require a login identifier. Konklav MUST find the
credential by the credential ID the authenticator returns, and MUST refuse
the assertion unless its user handle names the credential's subject.

r[authn.passkey.origin]
Registrations and assertions MUST be refused unless the client data's origin
is a configured passkey origin and the authenticator data's RP ID hash
matches the configured relying party ID.

r[authn.passkey.user-verification]
Registrations and assertions MUST be refused unless the authenticator
reports user verification.

r[authn.passkey.counter]
When the stored or the presented signature counter is non-zero, an assertion
whose counter does not exceed the stored one MUST be refused. A successful
assertion MUST persist the updated counter.

r[authn.passkey.amr]
A passkey login or step-up MUST record the methods `swk` and `mfa`, since
user verification adds a second factor to possession of the key.

r[authn.passkey.management]
A subject MUST be able to list and revoke its own passkeys from a full
session. Revoking MUST require a session that authenticated recently.

## Sessions

r[session.server-side]
Every issued access or refresh token MUST belong to a server-side session
record.

r[session.version]
Every change to a session's security context (refresh, tenant switch, flag
change, step-up, revocation) MUST increase its version. Access tokens carry
the version they were issued at, and relying systems MUST reject versions
lower than the session's current version.

r[session.expiry]
Sessions MUST have an absolute expiry. Refreshing MUST NOT extend a session
beyond it.

r[session.refresh.rotation]
Every refresh MUST rotate the refresh token. Presenting a refresh token that
was already rotated MUST revoke the session (reuse detection).

r[session.refresh.recompute]
Refreshing MUST re-read the session's membership, subject state, facts and
flags, so that a refreshed token reflects current state.

r[session.revocation.targets]
Sessions MUST be revocable by session, subject, credential, membership and
tenant, optionally keeping one named session.

r[session.revocation.event]
Every session change MUST emit a `session.changed` event carrying the
session id, its new version and whether it is revoked.

r[session.sign-out-others]
A subject MUST be able to end its other sessions only from a full session,
not a partial one that has proven a single factor.

r[session.history]
Session records MUST remain queryable after revocation or expiry, for audit,
for a configured retention period.

r[session.admin]
The control plane MUST allow operators to list, inspect and revoke sessions,
with filters for subject, credential, membership and tenant.

## Session flags

r[session.flags.catalog]
Session flags MUST be declared in the action catalog as either restrictive
or assertive. Konklav MUST NOT interpret flag names.

r[session.flags.origin]
Flags MUST be set only by the flow that creates or steps up a session,
according to catalog or credential configuration, or by an explicit login
request that the catalog allows. Only restrictive flags may be requestable
at login. Relying systems MUST NOT add flags to an existing session.

r[session.flags.credential]
A credential MAY carry restrictive session flags. Every session started
with it MUST carry them, together with any the login request asked for.

r[session.flags.restrictive]
A decision for a session carrying a restrictive flag MUST deny unless the
operation explicitly admits that flag.

r[session.flags.assertive]
An operation MAY require assertive flags. A decision for a session missing a
required assertive flag MUST deny.

## Browser sessions

r[session.browser.cookie]
For browser clients, the refresh token MUST be delivered only as an
`HttpOnly`, `Secure`, `SameSite=Strict` cookie, and access tokens MUST be
returned in the response body. Every cookie Konklav sets MUST carry the
`__Host-` prefix (and so `Path=/` and no `Domain`), so that no other host,
including a sibling subdomain, and no plain-HTTP response can set or
replace it. Only a deployment that turns secure cookies off for local
development MAY use unprefixed names.

r[session.browser.csrf]
Cookie-authenticated endpoints MUST check the request `Origin` against a
configured allow-list and MUST require a custom request header.

r[session.browser.mfa]
When MFA completes a browser session's login, the refresh cookie MUST be
delivered in that response, after the same `Origin` and header checks as
the login itself.

r[session.dpop.bind]
A request that starts a session (a password, secret-key, passkey, email-link
or one-time-code login, or redeeming an invite) MAY carry a DPoP proof for
its own URL, and the session MUST then be bound to the proof's key. A
federated sign-in starts with a browser navigation, which can't carry the
header, so it MAY name the key with `dpop_jkt` instead, and the session the
callback starts MUST be bound to that key. A session started from another,
by impersonation, MUST keep its parent's binding.

r[session.dpop.required]
A deployment MUST be able to require that browser sessions are bound. A
browser login, or federated sign-in, without a DPoP proof or `dpop_jkt` is
then refused.

r[session.dpop.surfaces]
The subject-facing and control-plane surfaces MUST accept Konklav's own
sender-constrained access tokens under the `DPoP` scheme with a valid proof,
and refuse them under `Bearer` (`r[token.dpop.scheme]`). A proof's `htu`
MUST be one of the configured base URLs at which clients address Konklav,
followed by the request's path, so a reverse proxy that mounts a surface
under a prefix can be described. Unless configured, the base URLs MUST be
the issuer and each allowed browser origin, with and without the
console's `/control` prefix.

r[session.client-kind]
Whether a login returns cookies or body tokens MUST be decided by the
endpoint or an explicit request parameter, never by inspecting user-agent
headers.

## Challenges and delivery

r[challenge.single-use]
Challenges (one-time codes, magic-link tokens, invite tokens, reset tokens)
MUST be single-use, short-lived, and stored only as hashes.

r[challenge.attempts]
Code challenges MUST limit verification attempts and invalidate the code
when the limit is reached.

r[challenge.send-limit]
Sending challenges MUST be limited per recipient and purpose over several
windows, including a daily one, so that the codes a recipient can be sent
in a day allow only a bounded number of guesses. Where a request names a
login identifier without authenticating, a send refused by the limit MUST
be answered like one that went out, so the limit doesn't reveal which
identifiers exist.

r[challenge.delivery.event]
Konklav MUST NOT send messages. To deliver a challenge it MUST emit a
`delivery.requested` event with the channel, recipient, purpose, challenge
material and the subject, if any.

r[challenge.delivery.no-replay]
Delivery-request events MUST be readable only by consumers authorized for
delivery, and their challenge material MUST expire with the challenge.

## Invites, reset and impersonation

r[authn.invite.redeem]
Redeeming an invite MUST link a credential to a new or existing subject and
MUST activate any membership the invite targets.

r[authn.invite.membership-id]
An invite to a tenant MAY name the id of the membership its redemption
creates. Redemption by a subject that already has a different active
membership in that tenant MUST fail with a typed conflict.

r[authn.invite.revoke]
An operator MUST be able to revoke an invite that hasn't been redeemed.
Redeeming a revoked invite MUST fail exactly as redeeming an expired one
does. Revoking an invite again MUST change nothing, and revoking a redeemed
invite MUST fail with a typed conflict.

r[authn.reset-password]
Password reset MUST go through a challenge, and completing it MUST revoke
the subject's other sessions.

r[authn.impersonation.actor-chain]
Impersonation MUST require an explicit grant (a control-plane capability or
an assumption grant). It MUST create a session for the target subject whose
tokens carry the impersonating subject in the actor chain.

r[authn.impersonation.time-bounded]
Impersonation and assumption sessions MUST be time-bounded and auditable,
and MUST be revoked when the impersonating subject's session is revoked.

r[authn.impersonation.limits]
An impersonation session MUST NOT be accepted on the control-plane surface,
MUST NOT start another impersonation, and MUST NOT enroll, activate, change
or remove the target's credentials, MFA factors or passkeys, or end the
target's other sessions. Listing the caller's own control-plane capabilities
MUST report none for it.
