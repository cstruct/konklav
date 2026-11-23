# Security Policy

Konklav is an identity and access service, so a flaw in it can expose the
systems that rely on it. Reports of vulnerabilities are welcome.

## Reporting a vulnerability

Report a vulnerability privately through GitHub:
[open a draft security advisory](https://github.com/cstruct/konklav/security/advisories/new).
Only the maintainers can see it.

Do not open a public issue, pull request or discussion for a vulnerability,
and do not include details of one in a commit message.

A useful report says:

- which part is affected: the server, the console, a relying SDK
  (`konklav-relying`, `konklav-relying-client`, `konklav-axum`,
  `konklav-fastapi`), the control-plane client, the Docker image or the
  release process
- the version or commit you tested
- the configuration needed to reproduce it, where it differs from
  `config/dev.styx`
- the steps to reproduce it, or a proof of concept
- what an attacker gains and what they need to start with (no account, a
  signed-in subject, an operator with a particular capability, a relying
  system's credentials)

If you are unsure whether something is a vulnerability, report it privately
anyway.

## What to expect

- An acknowledgement within 10 working days.
- An assessment within 28 days: whether we accept the report, how severe we
  think it is, and what we plan to do.
- A fix in a new release. We publish a GitHub security advisory with the
  release and credit you in it unless you ask us not to.

Please give us 90 days from your report before you publish details, or
until a fixed release is out if that is sooner. If a fix needs longer we
will say so and agree a date with you.

## Supported versions

Only the latest release gets security fixes. Every release has one version
shared by the server, the console, the Docker image, the Python packages
and the Rust crates, and Konklav's clients are supported only against a
server of the same version, so upgrade them together.

A fix ships as the next release. We do not backport fixes to earlier
releases.

## Scope

In scope:

- everything in this repository that is released: the server, the console,
  the relying SDKs, the control-plane client and the Docker image
- the build, release and CI configuration under `.github/`
- the specifications under `docs/spec/`, where following one as written
  leads to a vulnerability

Out of scope:

- the applications under `examples/`, which show how to use Konklav and are
  not meant to be deployed as they are
- the development configuration and its secrets (`config/dev.styx`,
  `config/dev.secrets.styx`, the values in `mise.toml`, the Compose
  files). These are published on purpose, and the server refuses them
  outside development
- a deployment that runs with settings the documentation marks as unsafe
  outside development
- vulnerabilities in a dependency that do not affect Konklav. Report those
  to the dependency's maintainers
- denial of service that needs an operator's credentials, or more traffic
  than a rate limit in front of the server would let through

## Safe harbour

We will not take legal action against you, or ask anyone else to, for
research that follows this policy: you test only against your own
deployment, you do not access or change other people's data, and you report
what you find privately.
