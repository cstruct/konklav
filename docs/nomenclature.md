# Nomenclature

This document defines the preferred language for Konklav specs, code, API surfaces, and documentation.

Terms are introduced in dependency order: each definition only uses terms defined above it, or points explicitly to a later section. If a new term becomes important to the project, add it here before spreading it across specs or APIs.

## Systems and boundaries

- `Konklav`
  - The identity and access service defined by this repository.
  - Konklav decides who someone is (authentication) and what they may do (authorization), and it publishes the results to other software.

- `Konklav control plane`
  - Konklav itself and the resources it manages directly, such as tenants, roles, signing keys, and sessions.
  - Operations against the control plane are administrative: they change what Konklav knows, rather than asking it to authenticate someone.

- `relying system`
  - An external application, API, workload, or platform that trusts Konklav.
  - A relying system validates tokens issued by Konklav, consumes the authorization data Konklav publishes, and enforces its own decisions about its own resources.
  - Konklav never depends on, or names, a specific relying system.
  - Prefer this term over vague phrases like `using system`, `client app`, or `target system`.

- `surface`
  - One of Konklav's three groups of HTTP endpoints, separated so that deployments can expose them differently:
    - the `subject-facing surface`, used by people and software to log in and manage their own sessions
    - the `relying surface`, used by relying systems to fetch keys and authorization data, ask for decisions, and read events
    - the `control-plane surface`, used to administer the control plane

## Tenancy

- `tenant`
  - An explicit isolation boundary. Everything that grants access, from memberships to roles to sessions, lives inside exactly one tenant.
  - Relying systems typically map a tenant to a customer, organization, or account, and keep their own data partitioned by it.

- `root tenant`
  - The tenant that always exists. Its identifier is the nil UUID, and APIs accept `root` for it.
  - It is the top of the tenant tree and the home of `global roles` (see Authorization).

- `tenant tree`
  - Every tenant except the root has exactly one parent tenant.
  - A parent-child relationship grants nothing by itself. Access across tenants always requires an explicit membership or an `assumption grant` (see Authentication).

- `tenant state`
  - A tenant's lifecycle state: `active`, `suspended`, or `deleted`.
  - Only active tenants accept new sessions.

- `projection`
  - A relying system's local copy of Konklav-owned state, kept for its own joins and foreign keys.
  - Example: a relying system's tenant table, with the same identifiers as Konklav's tenants and extra profile columns.
  - A projection is never authoritative. Konklav is.

## Principals and people

- `subject`
  - The generic principal model inside Konklav: anything that can authenticate and be granted access.
  - A subject can be human or software, which its `subject kind` records.
  - Every subject has a stable identifier that survives changes to its email address, phone number, credentials, and memberships.
  - Konklav stores only what authentication and authorization need about a subject. Profile data such as display names or language belongs to relying systems.
  - Use this term whenever the behavior applies broadly and is not specific to a person or workload type.

- `subject kind`
  - Either `human` or `service`.
  - Service subjects can only authenticate non-interactively.

- `operator`
  - A human subject operating the Konklav control plane.
  - Examples: platform admin, support engineer, developer operating the system.

- `service principal`
  - A subject of kind `service`, representing software rather than a person.
  - Examples: API clients, automation, background jobs, a relying system reading Konklav's events.

- `membership`
  - A first-class record binding one subject to one tenant.
  - A subject has at most one active membership per tenant, and can have memberships in many tenants.
  - Access inside a tenant always goes through a membership; Konklav keeps no implicit global user state.
  - Example: the same person can be a member of tenant A and tenant B, with different roles in each.

- `tenant member`
  - A human subject acting inside a tenant through a membership.
  - Use this term when the text is specifically about the end-user experience inside a tenant.

## Catalog and facts

- `action catalog`
  - The vocabulary a deployment declares to Konklav: actions, action groups, scope kinds, fact keys, and session flags (all defined below).
  - Relying systems supply the catalog as data. Konklav hard-codes none of it, apart from its own control-plane capabilities.
  - Every catalog change produces a new `revision` (see Change feed).

- `action`
  - A named permission that can be granted, such as `workspace:read` or `report:export`.
  - Action names are colon-delimited hierarchical names.
  - The `konklav:` namespace is reserved for `control-plane capabilities` (see Authorization) and cannot be authored.
  - Konklav never interprets what an action means. It only records who holds it, and where.

- `action group`
  - A catalog name that stands for a set of actions and is expanded when authorization is compiled.
  - It is defined either by listing actions, or by a namespace selector such as "every action not in `sys:`".
  - Granting a group also grants the group's own name, so an operation can require the group itself.
  - Example: `tenant:all` expanding to every tenant-level action.

- `scope kind`
  - A catalog-declared type of resource inside a tenant, such as `workspace`, `project`, or `clinic`.

- `scope`
  - A specific resource inside a tenant, written as a `(scope kind, scope id)` pair.
  - Example: `(workspace, 0193a2f1-…)`.
  - Konklav treats scope ids as opaque. It doesn't know whether the resource exists or what it contains, so a relying system resolves its own resources into scopes before asking for a decision.

- `fact`
  - A typed key/value pair attached to a tenant, membership, or session, whose key is declared in the action catalog.
  - Example: a membership fact `member_type=professional`, or a tenant fact `tenant_type=personal`.
  - Facts describe a subject's situation. They are not permissions.

- `portable fact`
  - A fact declared safe to copy into tokens, so that relying systems can read it without asking Konklav.
  - A `non-portable fact` stays inside Konklav, or inside the relying system that owns it.

## Authentication

- `credential`
  - Something a subject uses to prove who it is. Each credential belongs to exactly one subject, and a subject can have several.
  - Credential kinds:
    - `password`: a secret the subject knows, found by a login identifier
    - `phone_otp`: a one-time code sent to a phone number
    - `email_link`: a magic link sent to an email address
    - `secret_key`: a generated key for service principals, with two independently rotatable slots
    - `public_key`: reserved for future proof-of-possession credentials
    - `federated`: an account at an `identity provider` (see Federation)
    - `client`: an `OIDC client` acting as a service principal (see Federation)
  - Replaced or revoked credentials are kept as history, never overwritten in place.

- `login identifier`
  - The value used to look up a credential: an email address, a phone number, or a key id.
  - It is stored on the credential, not as subject profile data, and is unique among active credentials of the same kind.

- `MFA factor`
  - A second factor registered for a subject, used after a credential has succeeded.
  - Kinds: `totp` (an authenticator app) and `email_code`.
  - A credential declares how many MFA factors it requires before login completes.

- `authentication method`
  - The `amr` value recording how a subject proved who it is. RFC 8176 values are used where one fits, such as `pwd`, `otp`, `sms`, or `hwk`.
  - Konklav-specific values cover methods RFC 8176 has no fitting value for: `eml` (email code or magic link), `fed` (see below) and `sk` (a service principal's secret key or OIDC client secret). `swk` is reserved for software-held proof-of-possession keys and never means a shared secret.
  - `fed` records a login through an identity provider; the methods the provider reports are credited only as its configuration maps them.
  - A session records every method used, and when the most recent authentication happened (`auth_time`).

- `challenge`
  - A short-lived, single-use secret that Konklav creates and the subject proves back to it.
  - Examples: a one-time code, a magic-link token, an invite token, a password-reset token.
  - Konklav stores only hashes of challenges.

- `delivery request`
  - A request from Konklav for a relying system to deliver a challenge to a recipient, for example by email or SMS.
  - Konklav never renders or sends messages itself. It publishes delivery requests as events (see Change feed).

- `invite`
  - A challenge that, when redeemed, links a credential to a new or existing subject, and may activate a membership.

- `session`
  - Konklav's server-side record of one authentication, from login until sign-out, expiry, or revocation.
  - It records:
    - the subject and the credential used
    - the target tenant and membership, if one has been chosen
    - authentication methods and `auth_time`
    - session flags and a session version
  - Every token belongs to a session, so revoking a session invalidates all of its tokens.

- `login stage`
  - How far a session has progressed through login:
    - `partial`: the credential succeeded, but MFA is still required
    - `identity`: the subject is authenticated, but no tenant is chosen
    - `tenant`: the session targets one membership in one tenant
  - A session targets at most one tenant at a time. Switching tenant is an explicit step.

- `session version`
  - A counter on the session that increases whenever its security context changes: refresh, tenant switch, flag change, step-up, or revocation.
  - Tokens record the version they were issued at. A token with an older version than the session's current one is rejected.

- `access token`
  - A short-lived signed JWT that a subject presents to relying systems.
  - It identifies the subject, session, session version, and target tenant. It carries portable facts and session flags, but no permissions.

- `token kind`
  - What an access token may be used for. It is either the login stage (`partial`, `identity`, `tenant`) or a single purpose (`reset_password`, `invite`).
  - A relying operation declares which token kinds it accepts.

- `refresh token`
  - An opaque, long-lived secret bound to one session, exchanged for a new access token.
  - Every use rotates it. Presenting an already-rotated refresh token revokes the session (`reuse detection`).

- `session flag`
  - A label on a session, declared in the action catalog and set only by the flow that created or stepped up the session.
  - Konklav copies flags into tokens without interpreting them.
  - There are two kinds:
    - A `restrictive flag` denies the session everywhere except operations that explicitly admit the flag. Example: a session limited to a subject's personal tenant.
    - An `assertive flag` is a positive statement that an operation can require. Example: `device_bound` after a hardware-key login.

- `step-up`
  - A requirement for stronger or more recent authentication than the session currently has, such as two authentication methods, or an `auth_time` within the last five minutes.
  - An unmet step-up requirement yields a demand to re-authenticate, not a plain denial.
  - Completing step-up updates the existing session rather than creating a new one.

- `assumption grant`
  - An explicit, Konklav-managed permission for one subject to act in another tenant, or as another subject.
  - It is time-bounded and auditable, and it is the only way to cross tenant boundaries without a membership.

- `impersonation`
  - Acting as another subject under an assumption grant or a control-plane capability, typically for support.

- `actor chain`
  - The originating subject and tenant behind a session created through impersonation or assumption.
  - It is carried in tokens as the `act` claim, so the real actor is never hidden behind the impersonated one.

- `signing key`
  - An Ed25519 key pair used to sign access tokens.
  - Its `kid` is derived from the public key.
  - The public keys still able to verify unexpired tokens are published as `JWKS` at `/.well-known/jwks.json`.

## Authorization

- `policy`
  - One rule inside a role or template. It has three parts:
    - an action or action group
    - an `effect`: `allow` or `deny`
    - whether it is `scope-bound`: a scope-bound policy applies only at its assignment's scope, while one that isn't applies tenant-wide

- `template`
  - A reusable blueprint of policies that roles can be derived from.
  - Templates cannot be assigned to anyone directly.
  - Example: a `clinician` template that every new tenant gets a role from.

- `role`
  - A named, assignable set of policies that belongs to exactly one tenant.
  - A role can be derived from a template. Its policies then override the template's, action by action.
  - Every role has an integer `priority`, used to resolve conflicts between roles.

- `role assignment`
  - The activation of a role for a membership, either tenant-wide or at one scope.
  - A membership can hold several assignments, including several at the same scope.
  - Roles are reusable definitions. Assignments are what actually grant access.

- `global role`
  - A role owned by the root tenant.

- `global assignment`
  - The assignment of a global role directly to a subject, not to a membership.
  - Its grants apply regardless of which tenant a session targets.
  - This is how operator-level actions are granted, including control-plane capabilities.

- `control-plane capability`
  - A built-in action in the `konklav:` namespace that governs Konklav's own control-plane operations.
  - Examples: creating tenants, revoking sessions, impersonating subjects.
  - Capabilities can only be granted through global assignments.

- `compilation`
  - Turning assignments, roles, templates, policies, and action groups into entitlement sets.
  - Compilation expands action groups, applies priority and effect rules, and removes denies, so that request-time checks never walk role definitions.

- `entitlement set`
  - The compiled result for one subject in one tenant, which is all a relying system needs in order to decide.
  - It contains only effective allows:
    - global actions, from global assignments
    - tenant-wide actions
    - actions per scope

- `requirements`
  - What an operation in a relying system demands:
    - actions at the global, tenant, or scope level
    - accepted token kinds
    - admitted restrictive flags and required assertive flags
    - step-up conditions

- `decision`
  - The outcome of evaluating requirements against an access token, its session, and an entitlement set: `allow`, `deny`, or a step-up demand.

## Change feed

- `event`
  - A record that something in Konklav changed, written in the same transaction as the change itself.
  - Kinds include:
    - `session.changed`
    - `entitlements.changed`
    - `tenant.changed`
    - `signing_keys.changed`
    - `delivery.requested`

- `outbox`
  - The database table where events are written and kept for a retention period.

- `cursor`
  - An event's position in the outbox, strictly increasing.
  - Each consumer keeps its own cursor and resumes from it.

- `change feed`
  - The ordered stream of events that Konklav serves to relying systems.
  - It is delivered over Server-Sent Events, resumable by cursor, with a paged JSON alternative.

- `heartbeat`
  - A message sent periodically on an idle change-feed stream, so that consumers can tell a quiet feed from a dead connection.

- `reset`
  - A special event that tells a consumer it cannot resume exactly from its cursor, for example because the cursor is older than retention. Everything it has cached may be stale.

- `revision`
  - A number identifying a state of Konklav's data: the cursor of the last event that affected it.
  - Entitlement sets carry the revision they were compiled at.

## Relying integration

- `relying SDK`
  - The library relying systems use to validate tokens and make decisions. It consists of a relying core and a host binding.

- `relying core`
  - The language-neutral part of the relying SDK. It verifies tokens, evaluates requirements, and runs the logic for the entitlement cache and change feed.
  - It is `sans-I/O`: it never makes network calls, reads clocks, or sleeps. It is given inputs and reports what work it needs done.

- `host binding`
  - A thin, language-specific layer around the relying core that performs the HTTP calls, timers, and background tasks the core asks for.
  - Examples: the Python binding, the native Rust binding.

- `entitlement cache`
  - The relying SDK's local copy of entitlement sets and session states, kept fresh from the change feed.

- `debounce window`
  - How long the relying SDK waits after an `entitlements.changed` event before re-fetching, so that bursts of events cause a single fetch.
  - It also bounds how long a removed grant can still be honored.

- `check API`
  - Konklav's central decision endpoint on the relying surface.
  - The relying SDK uses it when its entitlement cache cannot be trusted, for example because the change feed has lost its connection.
  - If neither the cache nor the check API is available, the relying SDK denies (`fails closed`).

- `read-your-writes`
  - The guarantee that a relying system, after changing something in Konklav, sees that change in its next decision.
  - The relying SDK provides it by waiting until it has applied events up to the cursor that the write returned.

## Federation

- `OpenID Connect` (OIDC)
  - The standard protocol Konklav uses for federation, in both directions.

- `identity provider`
  - An external service that Konklav trusts to authenticate subjects, such as a corporate directory, a national eID broker, or another Konklav instance.
  - Each one is configured with its own provisioning policy, authentication-method mapping and claim mapping rules.

- `federated credential`
  - A credential that proves a subject through an identity provider.
  - It is identified by the provider and the provider's subject identifier (`sub`), never by an email address.

- `claim mapping`
  - Rules that turn claims from an identity provider, such as group names, into global roles, memberships and role assignments.
  - Grants created this way are `managed` by the provider: re-evaluating the rules adds and removes only those grants.

- `OpenID provider`
  - Konklav's role when other software signs subjects in through it with OIDC.

- `OIDC client`
  - A registration at Konklav's OpenID provider, for a relying system, tool or other Konklav instance, with its own redirect URIs, audience and visible claims.
  - Prefer `relying system` when the software's role, not its registration, is what matters.

- `login hand-off`
  - How Konklav's OpenID provider gets a subject signed in without its own user interface: it redirects to a configured login application, which signs the subject in through the subject-facing surface and then completes the pending login request.

- `upstream` and `downstream` instance
  - In federation between Konklav instances, the upstream is the OpenID provider (for example, an operators' instance) and each downstream (dev, staging, a production region) trusts it as an identity provider.

- `peering`
  - Optional federation between Konklav instances beyond OIDC: a downstream follows the upstream's change feed, limited to subjects that signed in through it, so subjects disabled or regrouped upstream lose access downstream within seconds.

- `break-glass credential`
  - A local operator credential that works while every upstream is unavailable. Every use is recorded as an event.

## Software architecture and traceability

- `software item`
  - An identifiable architectural part of a larger software product or subsystem that is tracked as a meaningful design, dependency, or traceability boundary.
  - A software item can be implemented as a Rust crate today, but it can also be another kind of component such as a service, CLI, SDK, binding, worker, or integration.
  - Prefer this term over `crate` when the discussion is intended to stay valid as the repository grows beyond Rust.

- `software unit`
  - A software item that is not further subdivided for the purpose of a given design or verification discussion.
  - Use this term sparingly and only for lower-level design or verification contexts where the decomposition boundary matters.

## Writing guidance

- Prefer `subject` over `user` unless the text is specifically about a human person or tenant-member experience.
- Prefer `tenant member`, `operator`, or `service principal` when one of those is the precise actor.
- Prefer `relying system` over vague phrases like `using system` or `target system`.
- Specs and architecture notes MUST NOT name a specific relying system. Use generic scope kinds such as `workspace`, `project`, or `clinic` in examples.
- Say `access token` or `refresh token` rather than bare `token` in normative text.
- Say `role assignment` when talking about granting access, and `role` only for the definition.
- Say `entitlement set` for compiled results, and avoid `permissions` for them, since that word blurs actions, policies, and entitlements.
- Prefer `software item` over `crate` in architecture or traceability guidance that should remain valid for non-Rust components.
- Keep using `crate` when the text specifically describes a Rust workspace member, crate README, or Rust-only implementation detail.
- Avoid bare `system`, `item`, or `unit` in normative text when `relying system`, `software item`, or `software unit` would be clearer.
- If a new term becomes important to the project, add it here before spreading it across specs or APIs.
