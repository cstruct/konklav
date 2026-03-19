# CLI

`conclave-cli` is the Conclave CLI for managed-configuration workflows against the Conclave control plane.

It loads managed configuration from the current working directory, translates that desired state into control-plane API requests, and prints the server responses needed for validate, plan, apply, and invite workflows.

## Responsibilities

- Provide the operator-facing command-line entry point for managed configuration.
- Load managed configuration from local Styx bundles in the current working directory.
- Call the server's control-plane surface for validate, plan, and apply operations.
- Call the server's invite-creation operation with operator-supplied arguments.

Out of scope:

- defining the managed-configuration data model
- authoritatively validating or applying managed configuration without the server
- serving as the control-plane runtime itself

## Public Interface

Primary entry point:

- `src/main.rs`
  - Defines the CLI arguments, subcommands, managed-config loading behavior, and outbound control-plane requests.

Command overview:

- `validate`
  - Load managed config from the current directory and call `/v1/managed/validate`.
- `plan`
  - Load managed config from the current directory and call `/v1/managed/plan`.
- `apply`
  - Load managed config from the current directory and call `/v1/managed/apply`.
- `invite-create`
  - Call `/v1/invites` for one subject and optional expiry.

See [`src/main.rs`](src/main.rs) for the command surface.

## Relationships

### Dependency Summary

| Software item | Relationship |
| --- | --- |
| `conclave-controlplane-api` | Provides the request types the CLI sends to the control-plane surface. |
| `conclave-managed-config` | Provides the local managed-config loading and parsing used before validate, plan, and apply requests are sent. |
| `conclave-server` | Acts as the control-plane runtime this CLI talks to during normal operation. |

### Dependent Summary

| Software item | Relationship |
| --- | --- |
| External operators | Use this CLI to drive managed-config workflows and invite creation against a running Conclave control plane. |

## Usage

Show the available commands with:

```sh
cargo run -p conclave-cli -- --help
```

Representative workflows:

```sh
cargo run -p conclave-cli -- validate
cargo run -p conclave-cli -- plan
cargo run -p conclave-cli -- apply
cargo run -p conclave-cli -- invite-create --subject doctor-1 --expires-in-seconds 900
```

## Running

Run the CLI with:

```sh
cargo run -p conclave-cli -- <command>
```

Common runtime inputs:

- `CONCLAVE_CONTROL_PLANE_URL`
- `CONCLAVE_BOOTSTRAP_TOKEN`

For `validate`, `plan`, and `apply`, the CLI expects managed `*.styx` files in the current working directory and loads them through `ManagedConfig::load_from_dir(".")`.

## Testing

Run this software item's crate-local tests with:

```sh
cargo test -p conclave-cli
```

Coverage shape:

- Direct coverage
  - This crate has no crate-local test cases.
  - Its own logic is intentionally thin around argument parsing, managed-config loading, and outbound request dispatch.
- Indirect coverage
  - `conclave-server` and `conclave-controlplane-api` tests exercise the server-side behavior this CLI drives.
  - Local operator workflows also exercise this CLI against real managed-config bundles and a running server.

## Behavior Notes

- `validate`, `plan`, and `apply` always load managed config from the current working directory.
- The CLI delegates authoritative validation and apply semantics to the server even though it parses managed config locally first.
- The CLI prints raw response bodies, which makes it useful for iterative operator workflows but keeps presentation concerns minimal.

## Traceability And Related Docs

- [Platform spec](../../docs/spec/platform.md)
- [Managed configuration spec](../../docs/spec/managed-configuration.md)
- [Repository traceability guidance](../../docs/traceability-guidance.md)
- [Software-item README guidance](../../docs/software-item-readmes.md)
- [Project nomenclature](../../docs/nomenclature.md)
