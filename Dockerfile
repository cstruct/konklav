# syntax=docker/dockerfile:1

# Keep the Rust version in sync with mise.toml.
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS chef
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /src

# The dependencies, from the manifests alone, so they're only rebuilt when those change.
FROM chef AS plan
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=plan /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --bin konklav-server --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin konklav-server

# glibc, libgcc, OpenSSL (which passkeys link) and CA certificates, as the build's
# Debian has them, and no shell. Runs as the nonroot user (65532).
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/konklav-server /usr/local/bin/konklav-server
# Mount config.styx, secrets.styx and the key files they name here. Paths in
# the config are relative to this directory.
WORKDIR /etc/konklav
ENV KONKLAV_CONFIG=/etc/konklav/config.styx \
    KONKLAV_SECRETS=/etc/konklav/secrets.styx
ENTRYPOINT ["/usr/local/bin/konklav-server"]
CMD ["serve"]
