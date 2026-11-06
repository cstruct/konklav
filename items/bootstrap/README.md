# konklav-bootstrap

Library crate that reads bootstrap sets: the tenants, people, credentials and grants that `konklav-server bootstrap` applies to a database. A set can be written by hand or exported from another identity system, as flat CSV tables, nested Styx documents, or a mix of both.

## Responsibilities

- Reading every supported file into one `BootstrapSet`:
  - flat tables: one CSV file per kind of record
  - nested Styx documents
  - a `catalog.json` in the control plane's catalog shape
- Keeping identifiers as written. `Id::resolve` turns them into UUIDs: a UUID as given, or an external id as UUID v5 of the set's id namespace and `<kind>:<external id>`.
- Carrying the natural keys of nested records that have no ids.
- Reporting every problem in every file together, each with its file and line.
- Checking the set's format version before reading its records.

Out of scope: anything that needs the database, such as finding natural keys, comparing records with stored ones and writing them. That is `konklav-server`'s `bootstrap` module. Reading is pure, apart from reading the files it is given.

## Public interface

- `read(paths)`: reads files and directories into a `BootstrapSet`, or returns every `Problem` found.
  - A directory contributes its `.csv` tables, its `.styx` documents and `catalog.json`.
- The model: `BootstrapSet` and its records, each a `Located<T>` with the `Location` it was read from.
- `FORMAT`, the newest bootstrap format version it reads and the one `export` declares, and `FormatVersion`.
- `Id`, `Kind` and `derive`, for working out the UUID an external id becomes. A relying system can use `derive` to compute Konklav ids from its own.

## File formats

[`examples/bootstrap`](../../examples/bootstrap) has a complete example of each.

### Nested (Styx)

```styx
format 1.0                                          // the bootstrap format version; see below
id_namespace 3f1c9a52-6a1e-4d0b-9a0e-6c1d8f0b2e11   // needed for external ids and tenant keys
catalog_file "catalog.json"                         // relative to this file

templates ({key reader, metadata {label Reader}, policies ({action project:read})})
global_roles ({key support, policies ({action konklav:subject:impersonate})})

tenants ({
    key acme                        // or `id`; a top-level tenant may name a `parent`
    facts {seats 25}
    templates (reader)           // roles to derive when the tenant is created
    roles ({key editor, policies ({action document:write, scope_bound true})})
    children ({key acme-north})
    members ({
        email ada@acme.example      // with password_hash, password or email_link true
        password_hash "$argon2id$…"
        roles (reader)
        scoped_roles ({role editor, scope_kind project, scope_id p-1})
        facts {member_type professional}
    })
    registered_scopes ({kind document, id d-1, containers ({kind project, id p-1})})
})

subjects ({email ops@example.com, password_hash "$argon2id$…", global_roles (konklav.admin)})

registered_scopes ({kind patient, id p-1, tenant acme, containers ({kind workspace, id w-1})})
```

- **Members and subjects** take:
  - `id`, `kind` (`human` or `service`) and `state` (`active` or `disabled`)
  - the shorthands `email` (with `password_hash`, `password` or `email_link true`) and `phone`
  - `credentials`, `factors` and `global_roles`
- **Members also take** `membership` (its id), `facts`, `roles` and `scoped_roles`.
- **Credentials** have a `kind`: `password`, `secret_key` (slots `a` and `b`), `email_link`, `phone_otp` or `federated` (with `provider` and `provider_subject`). `session_flags` lists restrictive catalog flags every session started with the credential carries.
- **Factors** are `kind totp` with `seed_base32`, or `kind email_code` with `email`.
- **Registered scopes** take `kind`, `id` and `containers` (each a `kind` and an `id`, possibly none). Inside a tenant they belong to it; at the top level they name a `tenant` (an id, a key or `root`). Kinds and ids are opaque and used as written, never resolved.
- **Templates and roles** take `metadata`, an object stored as the control plane's `metadata`. Styx scalars are text, so its values become JSON strings, and sequences and objects become arrays and objects.
- **Unknown keys** are errors.

### Flat (CSV)

Every table has a header row. Rows name other records by id. An empty cell is an absent value, lists are separated by `|`, and facts are `fact.<key>` columns. Unknown columns are errors.

| Table | Required columns | Optional columns |
|---|---|---|
| `tenants.csv` | `id` | `parent` (an id or `root`), `templates`, `fact.*` |
| `subjects.csv` | `id` | `kind`, `state` |
| `credentials.csv` | `id`, `subject`, `kind` | `identifier`, `password_hash`, `password`, `mfa_factors_required`, `session_flags`, `provider`, `provider_subject`, `a_hash`, `a_created_at`, `a_expires_at`, `b_hash`, `b_created_at`, `b_expires_at` |
| `mfa_factors.csv` | `id`, `subject`, `kind` | `seed_base32`, `email`, `active` |
| `memberships.csv` | `id`, `subject`, `tenant` | `fact.*` |
| `assignments.csv` | `role` | `membership` or `subject` (a global role), `scope_kind`, `scope_id` |
| `registered_scopes.csv` | `kind`, `id`, `tenant` | `containers` |
| `sessions.csv` | `id`, `subject`, `credential`, `stage`, `auth_time`, `version`, `refresh_hash`, `expires_at` | `tenant`, `membership`, `client_kind`, `amr`, `flags`, `impersonator`, `revoked_at` |

Registered scopes (`registered_scopes.csv` and the Styx `registered_scopes` keys) are new in format 1.1. In `registered_scopes.csv`, `kind` and `id` are the scope's own, used as written, and `containers` lists its containing scopes as `<kind>:<id>`, split at the first `:`, for example `workspace:w-1|workspace:w-2`. A container whose kind holds `:` or `|`, or whose id holds `|`, and any kind or id with surrounding spaces, can only be written in a Styx document.

CSV can't declare an id namespace, templates or roles. Put those in a `.styx` file next to the tables, as `examples/bootstrap/flat/set.styx` does.

### Format versions

The tables, columns and keys above are bootstrap format 1.0. The format has its own `major.minor` version, apart from Konklav's release version:

- **A minor version** only adds: a new optional table, column or key. Every set of an older minor version is still a valid set of the newer one.
- **A major version** is anything else: removing or renaming a table, column or key, making one required, or changing what a value means.

A set declares its version with a top-level `format` key in any of its `.styx` documents (`format 1.0`, or quoted, `format "1.0"`). CSV can't declare one, like the id namespace. Declarations that differ are a problem, and a set that declares none is format 1.0. `export` declares the current version in `set.styx`.

Before reading any records, `read` checks the version: it reads its own major at any minor up to `FORMAT`, and refuses anything else with one problem at the declaration, such as `this set needs format 1.2; this server reads format 1.0 up to 1.1`, rather than one for every key it doesn't know. A future major can upgrade sets of an older one in memory after reading them, so the server applies one shape; there are none yet.

`catalog.json` is the control plane's catalog document and changes with the control plane, not with this version.

#### Changing the format

`src/format.snapshot` records every table, column and key the readers accept, generated from `table::columns` and by reflecting on the Styx document types. Each line is `<path>: <required|optional> <kind>`, such as `csv/subjects.csv/state: optional column` or `styx/tenants/members/roles: optional list of text`; a record's keys sit under its key's path. A test (`src/format/check.rs`) regenerates it and compares it with the snapshot of the latest released format in `examples/bootstrap/formats/<version>/format.snapshot`:

- **Minor:** an added optional entry, an added entry inside one that is itself added (such as a new table's required columns), or a required entry made optional.
- **Major:** a removed (or renamed) entry, an added required entry in something that exists, an entry made required, or a changed kind.
- **None:** no difference.

`FORMAT` must be the released version bumped by the biggest of these, so changes before a release share one bump. Then the committed snapshot must match; rewrite it with:

```sh
UPDATE_FORMAT_SNAPSHOT=1 cargo test -p konklav-bootstrap format
```

The snapshot can't see what values mean, such as a new credential kind or a changed default; decide those bumps by hand. The frozen sets catch what a change breaks.

#### Releasing a format

A release that ships a new format version freezes it: add `examples/bootstrap/formats/<version>/` with a copy of `src/format.snapshot` as `format.snapshot` and at least one set in a directory of its own that uses what the version added, with any `catalog.json` it names. Frozen sets are never changed. The tests read every one of them, and the server's tests apply them to a database.

### Identifiers and natural keys

- **An id that parses as a UUID** is used as given.
- **Any other id** is an external id. It becomes UUID v5 of the id namespace and `<kind>:<id>`, where the kind is `tenant`, `subject`, `credential`, `mfa_factor`, `membership` or `session`.
- **Nested records without an id** are found by their natural key:
  - a tenant by its `key`, used as an external id
  - a subject by an active credential for its login identifier
  - a credential by its kind and identifier
  - a membership by its subject and tenant
  - an MFA factor by its subject and its position among that subject's factors

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-server` | Its `bootstrap` subcommand reads sets with this crate and applies them; its `export` subcommand writes them |

## Running

This is a library. Run it through `konklav-server bootstrap` (see [the server's README](../server/README.md)).

## Testing

```sh
cargo test -p konklav-bootstrap
```

- **Direct coverage:** both examples, every frozen set, format declarations and refusals, the format bump check, external-id derivation, and located problems for broken tables and documents.
- **Indirect coverage:** `items/server/tests/bootstrap.rs` applies the examples and every frozen set to a database.

## Traceability and related docs

- `bootstrap.*` in [the platform spec](../../docs/spec/platform.md)
- The terms `bootstrap set`, `bootstrap format version`, `external id`, `id namespace` and `natural key` in the [nomenclature](../../docs/nomenclature.md)
