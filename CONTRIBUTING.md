# Contributing

## Local Server Signing Key

`conclave-server` expects a local Ed25519 signing key at `config/server.signing-private-key.pem` during development.

Generate it with:

```sh
openssl genpkey -algorithm Ed25519 -out config/server.signing-private-key.pem
```

The server expects that file to contain an unencrypted PKCS#8 PEM private key.
