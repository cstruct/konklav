# Server Config And Secrets

This note defines how `conclave-server` handles startup config and secret-bearing config.

## Files

The server loads two explicit Styx files at startup:

- `config/server.conf.styx`
  - ordinary runtime config
  - intended for normal operator review and change management
- `config/server.secrets.styx`
  - secret-bearing config
  - intended for values that should be handled differently from ordinary runtime settings

The default paths are part of the startup contract, and operators may relocate them with:

- `--config` or `CONCLAVE_CONFIG`
- `--secrets` or `CONCLAVE_SECRETS`

The secrets path is explicit rather than derived from the public config path. That keeps secret placement intentional and allows operators to mount or store the secrets file independently from the ordinary config file.

## Boundary

The split is intentionally strict:

- secret-bearing fields are rejected in `server.conf.styx`
- non-secret fields are rejected in `server.secrets.styx`
- startup fails if either file is missing or invalid

This keeps the boundary meaningful instead of treating the secrets file as a loose overlay or a convenience include.

## Override policy

Conclave accepts CLI and environment-variable overrides for locating the config files, but not for supplying secret values directly. Secret-bearing values must come from `server.secrets.styx`.

The reason for this policy is operator safety. CLI-provided secrets are easy to leak through shell history and process inspection, and environment-provided secrets are easy to over-trust even though they may be visible through host tooling, service-manager introspection, or crash diagnostics.

Conclave still allows CLI and environment-variable overrides for locating the config files themselves and for non-secret runtime settings such as bind addresses.
