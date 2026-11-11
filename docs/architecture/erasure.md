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
   retention, with `GET /v1/subjects/erased?since=` on the relying
   surface. The list covers every erasure there has ever been, in the
   order they happened, so a system that was away for a year reads a year
   of it.

The relying SDK does the cache side itself: on `subject.erased` it drops
the subject's cached sessions and entitlement sets before handing the
event to the host. Decisions need nothing special, because an erased
subject has no sessions and an empty entitlement set.

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
what Konklav holds about one subject: its credentials' kinds and login
identifiers, federated identities, passkey labels, MFA factors, memberships
with facts, role assignments, and the sessions and challenges not yet
deleted by retention. It never shows hashes, seeds, key material or
challenge material.

It covers Konklav only. A deployment's full answer to an access request
adds what its relying systems hold.

Erasure and the report must cover the same places. A test compares both
against the database schema, so adding a column that can hold personal
data fails until someone decides how erasure and the report treat it
(`r[subject.report.complete]`).
