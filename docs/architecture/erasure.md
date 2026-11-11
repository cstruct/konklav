# Erasure and personal data reports

Konklav is not a store for profile data (`r[subject.no-profile]`), but it
can't authenticate people without holding some personal data: login
identifiers, federated identities, the addresses challenges go to, and
whatever facts a deployment puts on memberships. This note describes how a
deployment answers a request to be forgotten, or a request for access, for
the part Konklav holds, and how relying systems find out so they can deal
with theirs.

The normative rules are `subject.erasure.*` and `subject.report.*`
([tenancy and identity](../spec/tenancy-and-identity.md)),
`feed.subject-erased` ([change feed](../spec/change-feed.md)) and
`relying.erasure.*` ([relying systems](../spec/relying-systems.md)).

## Why Konklav doesn't hold the profile

Putting names, addresses and the rest into Konklav would make one place to
erase from, which is tempting. It was rejected:

- Konklav knows nothing about any relying system's domain. A profile
  store needs schemas, field-level access rules and purposes, which are
  all domain knowledge.
- Konklav copies state outward on purpose: tokens verified offline, cached
  entitlement sets, projections. Personal data wants the fewest copies
  possible.
- Every profile read would depend on Konklav being up, and one breach
  would yield credentials and profiles together.

So each system erases what it holds. Konklav erases its own part and is
the place the others hear it from.

## What erasure does

`POST /v1/subjects/{id}/erase` on the control-plane surface, in one
transaction:

| Where | What happens |
| --- | --- |
| Sessions | Revoked with reason `subject_erased`, with the sessions started from them. Identity-provider claims and DPoP key thumbprints are cleared. The rows go when session retention allows, as for any ended session. |
| Credentials, MFA factors | Deleted. This is the only operation that deletes a credential (`r[credential.history]`). |
| Challenges | Deleted, both those made for the subject and those sent to one of its recipients without naming a subject, such as an invite. |
| Login attempts | Deleted for the subject's login identifiers. |
| Memberships | Ended, and their facts removed. |
| Role assignments | Deleted, global ones included. |
| History | Every row version of the subject's memberships loses its facts. |
| Stored events | `delivery.requested` events for the subject, or to one of its recipients without naming a subject, are deleted. Gaps in the feed's cursors are normal, so consumers notice nothing. |
| Remembered batch answers | Deleted where they name the subject or one of its recipients, or were remembered for it as the caller. |
| The subject | Becomes `erased`, with the time. |

Then it appends `subject.erased`, after the `session.changed` and
`entitlements.changed` events the steps above caused.

The operation needs the capability `konklav:subjects:erase`, separate from
`konklav:subjects:manage` because it can't be undone. Erasing an operator
needs `konklav:control:all`, like any change to an operator's state, and
nobody can erase themself. A service principal that an OIDC client
authenticates as can't be erased until the client is disabled.

### The erased subject stays

The `subject` row holds an id, a kind, a state and timestamps. None of
that is personal data once everything else is gone, so the row is kept as
the erased subject. That has three uses:

- Identifiers in sessions kept for retention, in stored events, in history
  and in relying systems' projections still refer to something.
- The id can't be reused, by accident or by an import that still has the
  old record. Every write that would attach something to an erased subject
  fails with `SUBJECT_ERASED`.
- Relying systems can ask which subjects were erased, at any later time.

The database enforces this itself, with triggers on the tables that name
a subject, so bulk SQL from an import can't get around it.

The login identifiers are free again. If the person returns, they sign up
as a new subject, and nothing connects the two.

### Why sessions keep no credential

A session refers to the credential it was established with, and ended
sessions are kept for a while (`r[retention.sessions]`), partly because a
back-channel logout may still be pending. Erasure must not wait for that.
So a session's credential reference may be empty once the session has
ended, and deleting a credential empties it.

### Why all membership facts go

Facts are catalog data, and Konklav can't tell `member_type` from
`date_of_birth`. Rather than add a "personal" marking to the catalog that
every deployment would have to get right, erasure removes every fact on
the subject's memberships. Tenant facts and share facts are left alone:
they describe a tenant or a share, not this subject.

### History

History exists to explain a decision as of a past time. Leaving an erased
person's facts readable there until history's retention runs out would
make erasure depend on a setting meant for something else. So the facts
are removed from the row versions in the same transaction. The cost is
that an explanation as of a time before the erasure sees that subject's
memberships without facts, and may explain a decision differently from how
it was made. `r[history.as-of]` says so.

The subject's own row versions, and those of its role assignments, hold
only identifiers and are kept.

## What Konklav can't reach

Erasure covers Konklav's database. It doesn't cover, and operators must
handle themselves:

- database backups, replicas that lag, and write-ahead log archives
- bootstrap sets written by `export` before the erasure
- telemetry already exported, although it never holds login identifiers
  or addresses (`r[telemetry.privacy]`)
- messages a relying system sent for a `delivery.requested` event
- what relying systems hold

Address-only login attempts (those not tied to a login identifier) stay
until the rate-limit window passes, since nothing links them to a subject.

## Relying systems

A relying system that keeps anything keyed by subject id should:

1. Consume `subject.erased`, through the relying SDK or directly. The
   event carries the subject's id and the time, nothing else, and every
   feed consumer may read it.
2. Delete or anonymize its own data for that subject. The handler must be
   idempotent, because the feed is at-least-once and catching up can
   repeat an erasure.
3. Catch up after a `reset`, or after any outage longer than feed
   retention, with `GET /v1/erased-subjects?since=` on the relying
   surface. The list covers every erasure there has ever been, in the
   order they happened, so a system that was away for a year reads a year
   of it.

The list's entries have the form of the event's payload: `subject` and
`erased_at`, in seconds. `since` is in seconds too and inclusive, so a
system can pass the time of the last event it applied and get the erasure
at that very second again rather than miss it. A full page ends with
`next`, which goes into `after` for the page behind it.

The path isn't under `/v1/subjects`, because the control-plane surface has
`/v1/subjects/{id}` and surfaces that share a listener must not overlap.

### Through the relying SDK

The relying core does the cache side itself: on `subject.erased` it drops
the subject's cached sessions and entitlement sets, and then returns an
erasure notice for the host binding to hand to the relying system.
Decisions need nothing special, because an erased subject has no sessions
and an empty entitlement set.

There are two notices:

- **Erased**, with the subject and the time. The relying system deletes
  its data about the subject.
- **Missed**: erasures may have been missed, so the relying system should
  read the list. The core gives it on a `reset`, with the time it applied
  its last event (by the host's clock), and when it starts following the
  feed with no position of its own, without a time. The second case is
  every start of the process: the bindings keep their feed position in
  memory, so they can't know what happened while they weren't running.

| Binding | Notices | Reading the list |
| --- | --- | --- |
| `konklav-relying-client` (Rust) | `RelyingClient::erasures()`, a channel of `ErasureNotice`; ask for it before `start()` | `RelyingClient::erased_subjects(since)` |
| `konklav-relying` (Python) | `RelyingClient(on_erasure=...)`, awaited with `Erased` or `ErasuresMissed`, one at a time | `RelyingClient.erased_subjects(since)` |

`konklav-axum` and `konklav-fastapi` add nothing of their own: the
application holds the client they are given.

Notices aren't durable. They are lost with the process, and the Python
client logs a handler that raises and moves on. A relying system that
must not miss an erasure therefore keeps, in its own storage, the time it
has handled erasures up to:

1. On **Missed**, read the list from the stored time, delete, and store
   the latest `erased_at` read. Only this step moves the stored time.
2. On **Erased**, delete. This is the fast path, and may fail without
   harm, since the next read of the list repeats it.

A deployment that restarts rarely can also run step 1 on a schedule. The
Python notes app ([examples/notes-app](../../examples/notes-app)) does
exactly this for its notes; the Rust one keeps notes in memory and so has
nothing to catch up on after a restart.

Usually the relying system is also where erasure starts, since it owns the
relationship with the person and knows what must be settled first. Its
flow is then: check its own obligations, call Konklav's erase operation,
and delete its own data either right away or when the event comes back.
Doing it on the event keeps one code path for erasures started elsewhere,
such as by an operator in the console.

Konklav can't make a relying system delete anything. What it guarantees
is that the signal is durable and can't be missed for good.

### Federation between Konklav instances

When one Konklav signs people in to another, the downstream instance has
its own subject with a federated credential. Erasing the upstream subject
doesn't erase the downstream one. Whoever operates the downstream instance
treats it like any relying system would: it hears `subject.erased` from
upstream if it peers through the feed, and erases its own subject through
its own control plane.

## Personal data reports

`GET /v1/subjects/{id}/personal-data` on the control-plane surface returns
what Konklav holds about one subject, as one answer read from one
snapshot. It needs `konklav:subjects:manage`.

| Part | What it shows |
| --- | --- |
| `subject` | Id, kind, state and times. |
| `credentials` | Kind, login identifier and times, revoked ones included. A federated credential shows the provider, the provider's `sub` and the email address it reported. A passkey shows its label. |
| `mfa_factors` | Kind and, for an email factor, the address. Removed factors are included, since their rows stay until erasure. |
| `memberships` | Tenant, state and facts, ended ones included. |
| `role_assignments` | Global ones and those of the subject's memberships. |
| `sessions` | Every session retention hasn't deleted: times, authentication methods, client kind, OIDC client, the claims an identity provider passed and the DPoP key thumbprint. |
| `challenges` | Purpose, recipient and times, for the challenges erasure would delete. |
| `login_attempts` | Time, kind of credential, login identifier, outcome and client address, for the attempts erasure would delete. |

It never shows hashes, seeds, key material or challenge material. For an
erased subject every list is empty.

Three things Konklav holds are left out on purpose:

- **Facts a membership had earlier**, which history keeps as row versions.
  The report shows the facts that hold now.
- **Stored `delivery.requested` events.** Each repeats the recipient of a
  challenge the report already shows, next to material that must not be
  shown.
- **Remembered batch answers**, which are short-lived copies of answers the
  caller already received.

Erasure removes all three.

It covers Konklav only. A deployment's full answer to an access request
adds what its relying systems hold.

### Keeping erasure and the report complete

Erasure and the report must cover the same places
(`r[subject.report.complete]`). A test in `items/store/tests/erasure.rs`
holds a decision for every column of the database: no personal data,
personal data that erasure removes and the report shows, or data that
erasure removes and the report leaves out, with the reason. It compares
that list with the schema, so a migration that adds a column fails the
test until someone has decided how erasure and the report treat it.

## Handling an erasure request

What an operator does when someone asks to be forgotten. The steps work
the same in the console, over the control-plane API and with the Python
control-plane client.

1. **Find the subject.** Search by login identifier in the console, or
   `GET /v1/subjects?identifier=`. Check that it is the person asking and
   not someone who shares an address.
2. **Take the personal data report if you need one.** After erasure there
   is nothing left to report. The report is also the answer to a request
   for access, for Konklav's part.
3. **Settle what the relying systems need settled.** Open orders, legal
   holds and the like are theirs to know. Konklav checks none of it.
4. **Clear what blocks the erasure.**
   - A service principal that an OIDC client authenticates as: disable the
     client first.
   - An operator: the erasure needs `konklav:control:all`, and someone
     else has to do it, since nobody can erase their own subject.
5. **Erase.** `POST /v1/subjects/{id}/erase`, or **Erase…** on the
   subject's page in the console. It needs `konklav:subjects:erase`. It
   takes effect at once and can't be undone.
6. **Check that the relying systems followed.** They hear `subject.erased`
   on the change feed. `GET /v1/erased-subjects` on the relying surface
   lists the subject from then on, so a system that was down catches up
   when it returns.

### What is left afterwards, and for how long

| What | Holds | Goes when |
| --- | --- | --- |
| The erased subject | Id, kind, state, times | Never. It keeps the id from being used again. |
| The subject's ended sessions | Ids and times | After `retention.sessions_days` (default 30). |
| Events about the subject | Ids | After `feed.retention_hours`. |
| Row versions in history | Ids | After `history.retention_days` (default 90), when history is enabled. |
| Login attempts by address alone | A client address, tied to no subject | When the rate-limit window passes. |

None of these needs anything from the operator.

### What the operator has to handle

- **Backups, replicas and write-ahead log archives** still hold the
  person until they expire under their own retention. If a backup from
  before an erasure is restored, the erasure is undone, and so is
  Konklav's record of it. Keep the ids of erased subjects somewhere
  outside that database, such as the erasure request's ticket, and erase
  them again after a restore.
- **Bootstrap sets** written by `export` before the erasure still hold
  the person. Delete them or export again. Loading an old set into the
  same database is refused for the erased subject, but loading it into an
  empty database would bring the person back.
- **Messages already sent** for the subject's delivery requests, such as
  emails with sign-in links, are with the mail provider and the recipient.
- **Telemetry already exported** holds subject ids but never login
  identifiers or addresses (`r[telemetry.privacy]`).
- **Relying systems** that don't consume the change feed have to be told
  some other way.

If the person comes back later, they sign up as a new subject. Nothing
links it to the erased one.

## Compatibility

Erasure arrived in release 1.7.0. Clients written against earlier
releases meet four things they didn't before:

- **A third subject state.** A subject's `state` may be `erased`, and
  subjects carry `erased_at`. Code that matches on the state has to
  handle the new value.
- **A new feed kind.** `subject.erased` appears on the change feed.
  Relying SDKs from before 1.7.0 ignore it. Their caches still come out
  right, because the `session.changed` and `entitlements.changed` events
  of the same erasure empty them, but the relying system isn't told to
  delete its own data. Upgrade the SDK to hear it.
- **A new capability.** `konklav:subjects:erase` is separate from
  `konklav:subjects:manage`, so operators who manage subjects can't erase
  them until a role grants it. `konklav:control:all`, and with it the
  built-in `konklav.admin` role, covers it.
- **Sessions without a credential.** An ended session of an erased subject
  has `credential_id: null`.

Two additions change nothing for existing clients: a federated credential
shows `federated` with the provider's account, and an MFA factor may carry
`removed_at`.
