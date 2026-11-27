# Operator CLI Software Item

Stable implementation contracts owned by `konklav-cli`, the operator CLI,
whose binary is `konklav`.

## Packaging

r[item.cli.independent]
`konklav-cli` MUST NOT depend on `konklav-server`, `konklav-store` or the
relying SDK. It reaches Konklav only through the subject-facing and
control-plane surfaces, with the transport types of `konklav-api`.

r[item.cli.same-version]
The CLI MUST carry the version of the Konklav release it was built with,
and say so in `konklav --version`. It is supported only against a server of
that version.

## Sessions

r[item.cli.dpop-every-request]
Every session the CLI starts MUST be bound to a DPoP key it made, and every
request it sends with that session's access or refresh token MUST carry a
DPoP proof for the exact method and URL it sends to.

r[item.cli.secrets-in-keyring]
The CLI MUST keep a profile's DPoP private key and refresh token in the
operating system's credential store, never in its configuration file. It
MAY keep them in a file readable only by the user when the user asks for
that explicitly, and MUST then say so when it writes them.

r[item.cli.no-token-output]
The CLI MUST NOT print or log access tokens, refresh tokens, DPoP keys or
secret keys. Output of `konklav api` MUST be the response only.

r[item.cli.logout]
`konklav logout` MUST revoke the session at Konklav, then delete the
profile's local key and refresh token even when revocation failed, and say
when it did.

## Browser login

r[item.cli.loopback]
Browser login MUST listen only on `127.0.0.1`, on a port the operating
system picks, MUST accept a single callback whose `state` matches the
request, and MUST stop listening once it has one or after its timeout.

## Output

r[item.cli.exit-codes]
The CLI MUST exit with 0 on success, 1 on an error Konklav answered (with
its problem printed to standard error), 2 on a usage error, 3 when it is
not signed in or its session has ended, and 4 when it couldn't reach
Konklav.

r[item.cli.json]
Every command that prints a result MUST offer `--json`, which prints the
result as JSON on standard output and nothing else there.
