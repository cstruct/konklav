# konklav-authn

Library crate with Conclave's authentication primitives. Everything here is computation only; persistence and request handling live in `konklav-store` and `konklav-server`.

## Responsibilities

- `PasswordHasher`: Argon2id hashing and verification of passwords and secret keys.
  - The default policy (t=3, m=64 MiB, p=4, 32-byte output) matches hashes produced by argon2-cffi, so imported hashes verify without being rehashed.
  - It reports when a stored hash should be rehashed.
  - It can run a dummy verification so that failures for unknown identifiers take as long as failures for wrong secrets.
- `generate_secret`: 32 random bytes, base64url.
- `RefreshToken`: opaque `<session id>.<secret>` tokens, stored only as SHA-256.

## Relationships

| Software item | Relationship |
|---|---|
| `konklav-core` | `SessionId` inside refresh tokens |
| `konklav-server` | Hashes and verifies credentials, and issues refresh tokens |

## Running

This is a library and can't run on its own.

## Testing

```sh
cargo test -p konklav-authn
```

- Direct coverage:
  - hash round-trips, salting, rehash detection and garbage input
  - a real argon2-cffi fixture
  - secret and refresh-token formats
- Indirect coverage: the server's login, refresh and secret-key tests.

## Traceability and related docs

- [Tenancy and identity spec](../../docs/spec/tenancy-and-identity.md) (credentials)
- [Authentication spec](../../docs/spec/authentication.md)
- [Nomenclature](../../docs/nomenclature.md)
