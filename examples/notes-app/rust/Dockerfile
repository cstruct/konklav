# syntax=docker/dockerfile:1

# One image for every Rust service of the example, built from the repository
# root so the relying client comes from this checkout and matches the
# Konklav server built next to it. The browser files are compiled in.

# Keep the Rust version in sync with mise.toml.
FROM rust:1.99.1-bookworm AS chef
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /src

FROM chef AS plan
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=plan /src/recipe.json recipe.json
RUN cargo chef cook --release --locked -p konklav-sso-example --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p konklav-sso-example --bins \
 && mkdir /out /empty \
 && cp target/release/sso-* /out/

# glibc and libgcc, and no shell. Runs as the nonroot user (65532), which is
# also the user Konklav's own image runs as, so it can read the keys.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
# Empty named volumes take these owners.
COPY --from=build --chown=65532:65532 /empty /keys
COPY --from=build --chown=65532:65532 /empty /shared
# Each service names its binary in compose.yaml.
