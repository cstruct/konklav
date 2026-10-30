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

Out of scope: anything that needs the database, such as finding natural keys, comparing records with stored ones and writing them. That is `konklav-server`'s `bootstrap` module. Reading is pure, apart from reading the files it is given.

## Public interface

- `read(paths)`: reads files and directories into a `BootstrapSet`, or returns every `Problem` found.
  - A directory contributes its `.csv` tables, its `.styx` documents and `catalog.json`.
- The model: `BootstrapSet` and its records, each a `Located<T>` with the `Location` it was read from.
- `Id`, `Kind` and `derive`, for working out the UUID an external id becomes. A relying system can use `derive` to compute Konklav ids from its own.

## File formats

[`examples/bootstrap`](../../examples/bootstrap) has a complete example of each.

### Nested (Styx)

```styx
id_namespace 3f1c9a52-6a1e-4d0b-9a0e-6c1d8f0b2e11   // needed for external ids and tenant keys
catalog_file "catalog.json"                         // relative to this file

templates ({key clinician, policies ({action workspace:read})})
global_roles ({key support, policies ({action konklav:subject:impersonate})})

tenants ({
    key acme                        // or `id`; a top-level tenant may name a `parent`
    facts {seats 25}
    templates (clinician)           // roles to derive when the tenant is created
    roles ({key editor, policies ({action workspace:write, scope_bound true})})
    children ({key acme-north})
    members ({
        email ada@acme.example      // with password_hash, password or email_link true
        password_hash "$argon2id$…"
        roles (clinician)
        scoped_roles ({role editor, scope_kind workspace, scope_id w-1})
        facts {member_type professional}
    })
})

subjects ({email ops@example.com, password_hash "$argon2id$…", global_roles (konklav.admin)})
```

- **Members and subjects** take:
  - `id`, `kind` (`human` or `service`) and `state` (`active` or `disabled`)
  - the shorthands `email` (with `password_hash`, `password` or `email_link true`) and `phone`
  - `credentials`, `factors` and `global_roles`
- **Members also take** `membership` (its id), `facts`, `roles` and `scoped_roles`.
- **Credentials** have a `kind`: `password`, `secret_key` (slots `a` and `b`), `email_link`, `phone_otp` or `federated` (with `provider` and `provider_subject`).
- **Factors** are `kind totp` with `seed_base32`, or `kind email_code` with `email`.
- **Unknown keys** are errors.

### Flat (CSV)

Every table has a header row. Rows name other records by id. An empty cell is an absent value, lists are separated by `|`, and facts are `fact.<key>` columns. Unknown columns are errors.

| Table | Required columns | Optional columns |
|---|---|---|
| `tenants.csv` | `id` | `parent` (an id or `root`), `templates`, `fact.*` |
| `subjects.csv` | `id` | `kind`, `state` |
| `credentials.csv` | `id`, `subject`, `kind` | `identifier`, `password_hash`, `password`, `mfa_factors_required`, `provider`, `provider_subject`, `a_hash`, `a_created_at`, `a_expires_at`, `b_hash`, `b_created_at`, `b_expires_at` |
| `mfa_factors.csv` | `id`, `subject`, `kind` | `seed_base32`, `email`, `active` |
| `memberships.csv` | `id`, `subject`, `tenant` | `fact.*` |
| `assignments.csv` | `role` | `membership` or `subject` (a global role), `scope_kind`, `scope_id` |
| `sessions.csv` | `id`, `subject`, `credential`, `stage`, `auth_time`, `version`, `refresh_hash`, `expires_at` | `tenant`, `membership`, `client_kind`, `amr`, `flags`, `impersonator`, `revoked_at` |

CSV can't declare an id namespace, templates or roles. Put those in a `.styx` file next to the tables, as `examples/bootstrap/flat/set.styx` does.

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
| `konklav-server` | Its `bootstrap` subcommand reads sets with this crate and applies them |

## Running

This is a library. Run it through `konklav-server bootstrap` (see [the server's README](../server/README.md)).

## Testing

```sh
cargo test -p konklav-bootstrap
```

- **Direct coverage:** both examples, external-id derivation, and located problems for broken tables and documents.
- **Indirect coverage:** `items/server/tests/bootstrap.rs` applies the examples to a database.

## Traceability and related docs

- `bootstrap.*` in [the platform spec](../../docs/spec/platform.md)
- The terms `bootstrap set`, `external id`, `id namespace` and `natural key` in the [nomenclature](../../docs/nomenclature.md)
