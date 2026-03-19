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

## Software architecture and traceability

- `software item`
  - An identifiable architectural part of a larger software product or subsystem that is tracked as a meaningful design, dependency, or traceability boundary.
  - A software item can be implemented as a Rust crate today, but it can also be another kind of component such as a service, CLI, SDK, UI, worker, or integration.
  - Prefer this term over `crate` when the discussion is intended to stay valid as the repository grows beyond Rust.

- `software unit`
  - A software item that is not further subdivided for the purpose of a given design or verification discussion.
  - Use this term sparingly and only for lower-level design or verification contexts where the decomposition boundary matters.

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
- Prefer `software item` over `crate` in architecture or traceability guidance that should remain valid for non-Rust components.
- Keep using `crate` when the text specifically describes a Rust workspace member, crate README, or Rust-only implementation detail.
- Avoid bare `system`, `item`, or `unit` in normative text when `relying system`, `software item`, or `software unit` would be clearer.
- If a new term becomes important to the project, add it here before spreading it across specs or APIs.
