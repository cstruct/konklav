# Nomenclature

This document defines the preferred language for Conclave specs, code, API surfaces, and documentation.

## Principals and people

- `subject`
  - The generic principal model inside Conclave.
  - A subject can be human or machine.
  - Use this term when the behavior applies broadly and is not specific to a person or workload type.

- `tenant member`
  - A human end user acting within a tenant boundary.
  - A tenant member authenticates through Conclave and receives tenant-scoped sessions or tokens.

- `operator`
  - A human using Conclave's control plane.
  - Examples: platform admin, support engineer, reseller admin, developer operating the system.

- `service principal`
  - A non-human subject representing software.
  - Examples: API clients, automation, background jobs, control-plane integrations.

## Systems and boundaries

- `Conclave control plane`
  - Conclave itself and the APIs or resources it manages directly.
  - Control-plane capabilities are built in, system-defined, and separate from tenant-authored authorization state.

- `relying system`
  - An external application, API, workload, or platform integrated with Conclave.
  - A relying system validates tokens issued by Conclave and enforces its own resource-context authorization decisions.

- `tenant`
  - An explicit isolation boundary for memberships, roles, templates, policy assignments, sessions, and data.

## Authorization concepts

- `control-plane capability`
  - A built-in Conclave authorization concept governing operations against the Conclave control plane.
  - These are not authored through tenant-managed action catalogs.

- `action`
  - A cataloged authorization symbol used in tenant or relying-system authorization state.
  - Tenant-authored actions live in namespaces Conclave allows for managed authorization configuration.

- `template`
  - A non-assignable export surface that descendants can derive from across tenant boundaries.

- `role`
  - A tenant-local assignable authorization definition used for memberships and token compilation.

## Writing guidance

- Prefer `subject` over `user` unless the text is specifically about a human person or tenant-member experience.
- Prefer `tenant member`, `operator`, or `service principal` when one of those is the precise actor.
- Prefer `relying system` over vague phrases like `using system` or `target system`.
- If a new term becomes important to the project, add it here before spreading it across specs or APIs.
