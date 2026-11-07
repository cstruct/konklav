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

- `transport types`
  - The request and response types of Konklav's HTTP surfaces, defined once and shared by the server and Konklav's own clients.
  - They are kept separate from storage models, so the shape of an API changes only on purpose.

- `API document`
  - The OpenAPI description of a surface, generated from the server's routes and transport types and committed next to the server.
  - It describes one release: a client generated from it is supported against a server of the same version only.
  - Only the control-plane surface has one so far.

- `control-plane client`
  - A library that calls the control-plane surface on an operator's or automation's behalf, such as the Python package `konklav-control-plane`.
  - It is separate from the relying SDK: it changes what Konklav knows, while the relying SDK asks Konklav for decisions. Neither depends on the other.

- `batch`
  - One control-plane request that applies several control-plane write operations in order, all or nothing.
  - Its operations are the ordinary ones, with their usual paths, bodies and answers. Later operations name what earlier ones created by the ids the caller chose, never by reading earlier results.
  - Not to be confused with the bulk endpoints that take many records of one kind, such as imports and registered-scope changes.

- `idempotency key`
  - A value a caller chooses and sends with a batch, so that the server answers a repeat with the first answer instead of applying the batch again.
  - Kept for a limited time, per caller.

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
  - Operators usually get their control-plane capabilities from a built-in role (see Authorization).

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
  - A named permission that can be granted, such as `document:read` or `report:export`.
  - Action names are colon-delimited hierarchical names.
  - The `konklav:` namespace is reserved for `control-plane capabilities` (see Authorization) and cannot be authored.
  - Konklav never interprets what an action means. It only records who holds it, and where.

- `action group`
  - A catalog name that stands for a set of actions and is expanded when authorization is compiled.
  - It is defined either by listing actions, or by a namespace selector such as "every action not in `sys:`".
  - Granting a group also grants the group's own name, so an operation can require the group itself.
  - Example: `tenant:all` expanding to every tenant-level action.

- `scope kind`
  - A catalog-declared type of resource inside a tenant, such as `project`, `folder`, or `site`.

- `scope`
  - A specific resource inside a tenant, written as a `(scope kind, scope id)` pair.
  - Example: `(project, 0193a2f1-…)`.
  - Konklav treats scope ids as opaque. It never knows what a resource contains, and unless the scope is a registered scope (below), it doesn't know whether the resource exists either, so a relying system resolves its own resources into scopes before asking for a decision.

- `registered scope kind`
  - A scope kind the catalog declares as `registered`. Konklav decides requirements at scopes of this kind only from its own record of the scope, so a relying system can name the scope alone.
  - Example: a `document` kind whose ids are registered as they are created.

- `registered scope`
  - A scope of a registered scope kind that a relying system has recorded with Konklav, together with its owner tenant and its containing scopes.
  - Its tenant is fixed for good once recorded, even if the scope is removed and recorded again.
  - A registered scope that was never recorded, or has been removed, satisfies no requirement.
  - Roles can't be assigned at a registered scope; access to it always comes from its tenant, its containing scopes, or a share of one of them.

- `containing scope`
  - A scope of a kind that isn't registered, which a registered scope belongs to, such as the project a document sits in.
  - Actions held at any one containing scope apply to the registered scopes inside it.

- `fact`
  - A typed key/value pair attached to a tenant, membership, session, or share, whose key is declared in the action catalog.
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
    - `public_key`: a key pair held by the subject's authenticator, of which Konklav stores only the public key; today always a `passkey`
    - `federated`: an account at an `identity provider` (see Federation)
    - `client`: an `OIDC client` acting as a service principal (see Federation)
  - Replaced or revoked credentials are kept as history, never overwritten in place.

- `login identifier`
  - The value used to look up a credential: an email address, a phone number, a key id, or a WebAuthn credential ID.
  - Email addresses and phone numbers are compared case-insensitively; credential IDs are unpadded base64url and compared exactly.
  - It is stored on the credential, not as subject profile data, and is unique among active credentials of the same kind.

- `MFA factor`
  - A second factor registered for a subject, used after a credential has succeeded.
  - Kinds: `totp` (an authenticator app) and `email_code`.
  - A credential declares how many MFA factors it requires before login completes.

- `authentication method`
  - The `amr` value recording how a subject proved who it is. RFC 8176 values are used where one fits, such as `pwd`, `otp`, `sms`, or `hwk`.
  - Konklav-specific values cover methods RFC 8176 has no fitting value for: `eml` (email code or magic link), `fed` (see below) and `sk` (a service principal's secret key or OIDC client secret). `swk` means a software-held proof-of-possession key, such as a passkey, and never a shared secret.
  - `fed` records a login through an identity provider; the methods the provider reports are credited only as its configuration maps them.
  - A session records every method used, and when the most recent authentication happened (`auth_time`).

- `passkey`
  - A discoverable `public_key` credential used through WebAuthn: the browser or device keeps the private key and proves possession by signing a challenge, after verifying the user with a biometric or PIN.
  - A passkey login records `swk` and `mfa`.

- `relying party ID`
  - The domain Konklav's passkeys are scoped to (WebAuthn's RP ID), such as `example.com`. It is WebAuthn's term and has nothing to do with a `relying system`; prefer the full phrase `relying party ID`.

- `user handle`
  - The opaque identifier an authenticator stores with a passkey and returns when used. Konklav uses the subject id.

- `signature counter`
  - A counter some authenticators increase on every use, so a cloned key can be detected. Synced passkeys usually report zero.

- `attestation`
  - A statement from an authenticator about what kind of device created a key. Konklav currently requests none and records the format it got.

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

- `DPoP key`
  - A key pair a client generates and keeps, ideally non-extractable (a WebCrypto key or a platform keystore key), to prove that it is the party a session's tokens were issued to (DPoP, RFC 9449).
  - Konklav and relying systems know it only by its `key thumbprint`: the RFC 7638 SHA-256 thumbprint of its public JWK, carried as `jkt`.

- `DPoP proof`
  - A short-lived JWT signed with a DPoP key and sent in the `DPoP` request header. It names one HTTP request (method and URL), when it was made, and, when an access token comes with it, a hash of that access token.

- `bound session`
  - A session tied to one DPoP key when it was created. Its access tokens carry the key thumbprint in `cnf.jkt`, and its access and refresh tokens are accepted only together with a DPoP proof made with that key.
  - A session is bound or unbound for its whole life.

- `sender-constrained token`
  - An access or refresh token of a bound session. A stolen one is useless without the DPoP key. Prefer this term over `bound token` or `PoP token`.
  - An access token that is not sender-constrained is a `bearer token`.

- `session flag`
  - A label on a session, declared in the action catalog and set only by the flow that created or stepped up the session.
  - Konklav copies flags into tokens without interpreting them.
  - There are two kinds:
    - A `restrictive flag` denies the session everywhere except operations that explicitly admit the flag. Example: a session limited to a subject's personal tenant.
    - An `assertive flag` is a positive statement that an operation can require. Example: `device_bound` after a hardware-key login.

- `confinement`
  - A restrictive flag's limit on where a session carrying it may act, declared with the flag in the action catalog: the tenants whose portable facts match.
  - It is a conjunction of `fact predicates`, each naming a tenant fact and the values it may have. Example: `personal_only` confined to tenants whose `tenant_type` is `personal`.
  - A flag with a confinement is a `confined flag`, and a session carrying one is a `confined session`. A confined session can't enter a tenant outside the confinement, and decisions for it deny whenever its tenant is outside it.
  - Confinements are deliberately not a policy language: no operators beyond "one of these values", no disjunction across facts, no references to the operation.

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
  - Example: a `reader` template that every new tenant gets a role from.

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

- `built-in role`
  - A global role that Konklav defines and ships, granting a fixed set of control-plane capabilities.
  - Its key carries the reserved `konklav.` prefix. Built-in roles can be assigned like any global role, but they cannot be created, changed, or deleted through the API.
  - Examples: `konklav.admin`, `konklav.support`, `konklav.delivery`.

- `reserved role key`
  - A role key that starts with `konklav.`. Only built-in roles may use one, in any tenant.

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
    - `tenant fact requirements`: fact predicates, shaped like a confinement's, that the token's tenant must match. Example: `{"tenant_facts": {"tenant_type": ["client"]}}` for an operation only client tenants may use.

- `route policy`
  - A relying system's declaration of an operation's requirements with scope ids still unresolved, such as the requirements of one HTTP route, which it can merge with the route policies of the layers around the operation (routers, applications).
  - In the Python relying SDK it is `konklav_relying.Policy`, and in its FastAPI integration (`konklav-fastapi`) `RoutePolicy`. Say `route policy` in prose, so it isn't mistaken for a `policy` in a role.
  - The `operation's own route policy` is the one declared on the route itself, not on the routers or application around it. Only it can admit restrictive flags.

- `scope resolver`
  - A relying system's function that finds, for one request, the id of a scope its route policy names by kind, such as from a path parameter. It can also name the scope's kind, for a route whose resource may be of several kinds, and its owner tenant.

- `route tenant`
  - The tenant a request addresses on its own, such as from a path parameter, rather than through its token. A route tenant that isn't the token's tenant is denied before any decision, since requirements always mean the token's tenant.

- `decision`
  - The outcome of evaluating requirements against an access token, its session, and an entitlement set: `allow`, `deny`, or a step-up demand.

- `decision explanation`
  - A control-plane account of why a decision allows or denies: every check it makes, and for each required action, the policy that allows or denies it, or why nothing does.

- `share`
  - One tenant's scope made available to another tenant, with the actions the other tenant may use there.
  - The `owner tenant` holds the scope. The `recipient tenant` receives it, either tenant-wide or at one of its own scopes, such as a project.
  - A share is `offered` first, and only takes effect once it is `accepted` on the recipient's behalf. Either side can `revoke` it, and a revoked share is final.
  - A member of the recipient tenant gets only the actions the share allows that they already hold at the recipient, so the recipient's own roles decide who uses it.
  - A share can be valid for a period only, and doesn't chain: a recipient can't share it on.

- `share attribute`
  - A fact attached to a share, declared in the catalog with target `share`, such as the `date_range` of the data shared.
  - Konklav validates attributes but doesn't interpret them. It returns them with allow decisions as obligations.

- `obligation`
  - A condition an allow decision carries for the relying system to apply, such as narrowing a query to a share's date range.

## Change feed

- `event`
  - A record that something in Konklav changed, written in the same transaction as the change itself.
  - Kinds include:
    - `session.changed`
    - `entitlements.changed`
    - `tenant.changed`
    - `share.changed`
    - `scope.changed`
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

- `position`
  - A special event that begins a change-feed stream which needs no reset. Its cursor is where the stream starts, so a consumer knows its place in the feed even before any other event arrives.

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

- `rate limit`
  - A named bound on how often events may happen per key, such as login attempts per email address, enforced by the relying SDK.
  - It has one or more `rate-limit windows`, and an event is admitted only when every window admits it.

- `rate-limit window`
  - A number of events and a period: the window admits that many events at once, and after that one more each time the period divided by the number has passed.
  - Example: 3 per minute and 30 per hour, together, let a burst through but not a sustained flood.

- `rate-limit store`
  - A Redis server the relying system owns, through which every process enforces its rate limits together.
  - Every process also tracks its limits in memory, and answers from that state while the store is unavailable.

- `local divisor`
  - A number that divides each window's size in a process's in-memory state, so that several processes answering from memory together admit about the limit.

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

- `claims hook`
  - An optional endpoint of a relying system that Konklav's OpenID provider calls while serving userinfo, for profile claims such as `name` that Konklav doesn't hold.
  - The relying system stays the system of record: Konklav never stores what the hook returns, and caches it only in memory, for a bounded time.

- `passed claims`
  - Claims an identity provider reported, such as `name`, that Konklav is configured to pass on to its own OIDC clients.
  - They are a copy kept on the federated session and the client sessions started from it, and erased when those sessions end.

- `login hand-off`
  - How Konklav's OpenID provider gets a subject signed in without its own user interface: it redirects to a configured login application, which signs the subject in through the subject-facing surface and then completes the pending login request.

- `upstream` and `downstream` instance
  - In federation between Konklav instances, the upstream is the OpenID provider (for example, an operators' instance) and each downstream (dev, staging, a production region) trusts it as an identity provider.

- `peering`
  - Optional federation between Konklav instances beyond OIDC: a downstream follows the upstream's change feed, limited to subjects that signed in through it, so subjects disabled or regrouped upstream lose access downstream within seconds.

- `break-glass credential`
  - A local operator credential that works while every upstream is unavailable. Every use is recorded as an event.

## Import and bootstrap

- `import`
  - Loading another system's identity data into Konklav in bulk, keeping
    the records' identifiers so it can be repeated without duplicates.
  - Konklav offers it through the control plane and through the
    `bootstrap` command (below).

- `external id`
  - A record's identifier in the system it comes from, when that isn't a
    UUID, such as `4711` or `usr_abc`.
  - Konklav never stores it. It derives the record's own UUID from it (see
    `id namespace`).

- `id namespace`
  - A UUID that an import declares once, from which external ids are
    turned into Konklav UUIDs: UUID version 5 of the namespace and
    `<kind>:<external id>`, such as `subject:4711`.
  - The mapping is deterministic, so repeating an import finds the same
    records, and a relying system that knows the namespace can compute a
    record's Konklav id from its own.

- `natural key`
  - What identifies a record that comes with no identifier at all:
    - a tenant's key (a name chosen in the import, treated as an external id)
    - a subject's login identifier
    - a credential's kind and login identifier
    - a membership's subject and tenant
    - an MFA factor's subject and its position among that subject's factors

- `bootstrap set`
  - Everything one run of the `bootstrap` command reads from its files:
    catalog, templates, tenants, subjects, credentials, MFA factors,
    memberships, role assignments, registered scopes and sessions.
  - It can be written as flat tables (CSV, one file per kind of record,
    referring to each other by id) or as nested documents (Styx, with
    records inside the ones they belong to), or a mix of both.

- `bootstrap format version`
  - The version of the tables and documents a bootstrap set is written in,
    `major.minor`. It is not Konklav's release version: a release changes
    it only when it changes the files it reads.
  - A minor version only adds optional tables, columns or keys, so a
    server reads every older minor version of its major. Anything else is
    a new major version.
  - A set declares it with a top-level `format` key in one of its nested
    documents; a set without one is format 1.0.

- `export`
  - Writing a database's identity data as a bootstrap set, which the
    `bootstrap` command applies to an empty database unchanged.
  - It is a command with database access, not a control-plane operation,
    because the set holds hashes and MFA seeds.

## Operations

- `retention`
  - How long Konklav keeps a row it no longer needs, such as an expired challenge or an ended session, before deleting it.
  - Each kind of row has its own rule, set either by configuration or by the longest window anything still reads it over, such as a rate limit's.

- `history`
  - An optional record, off by default, of past versions of the rows that compilation and decision explanations read: subjects, tenants, memberships, the action catalog, templates, roles, their policies, role assignments, shares and registered scopes.
  - It keeps rows that were changed, deleted, or soft-deleted by a state such as an ended membership, so that a decision can be explained as of a past time.
  - Sessions are not part of it.

- `row version`
  - One state of one row in the history, with the period it was current: from when it was written until it was changed or deleted.

- `history horizon`
  - The earliest time history can answer for: when history was enabled, or its retention ago, whichever is later.

- `sweeper`
  - The background task that deletes what retention allows, in bounded batches, and erases delivery material from stored events once its challenge has expired.
  - Only one instance's sweeper runs at a time.

- `delivery material`
  - The secret part of a `delivery.requested` event: the one-time code or link token the relying system sends.

- `telemetry`
  - The traces, metrics and logs Konklav exports over OTLP for operators. It is separate from the change feed, which is for relying systems.

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
- Specs and architecture notes MUST NOT name a specific relying system. Use generic scope kinds such as `project`, `folder`, or `site`, and actions such as `document:read`, in examples. Avoid names that suggest a particular kind of relying system.
- Say `access token` or `refresh token` rather than bare `token` in normative text.
- Say `role assignment` when talking about granting access, and `role` only for the definition.
- Say `entitlement set` for compiled results, and avoid `permissions` for them, since that word blurs actions, policies, and entitlements.
- Prefer `software item` over `crate` in architecture or traceability guidance that should remain valid for non-Rust components.
- Keep using `crate` when the text specifically describes a Rust workspace member, crate README, or Rust-only implementation detail.
- Avoid bare `system`, `item`, or `unit` in normative text when `relying system`, `software item`, or `software unit` would be clearer.
- If a new term becomes important to the project, add it here before spreading it across specs or APIs.
