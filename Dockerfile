# syntax=docker/dockerfile:1

# Keep the Rust version in sync with mise.toml.
FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS chef
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /src

# The dependencies, from the manifests alone, so they're only rebuilt when those change.
FROM chef AS plan
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# The login page the server embeds (items/login). Keep the Node version in sync with mise.toml.
FROM node:26.13.0-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68 AS login
WORKDIR /src/items/login
COPY items/login/package.json items/login/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY items/login ./
RUN npm run build

FROM chef AS build
COPY --from=plan /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --bin konklav-server --recipe-path recipe.json
COPY . .
COPY --from=login /src/items/login/dist items/login/dist
# Fail rather than ship the placeholder page.
RUN KONKLAV_REQUIRE_LOGIN_PAGE=1 cargo build --release --locked --bin konklav-server

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
