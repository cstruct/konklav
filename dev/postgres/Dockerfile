# Postgres with the extensions Konklav's schema requires.

# pg_jsonschema validates credential data (jsonb) against JSON Schemas in
# check constraints. Supabase publishes .deb builds per Postgres major and
# architecture. Each is pinned by its SHA-256, since it is installed as
# root: when changing the version, take the new digests from the release's
# assets and update the image tags in the compose files.
ARG PG_JSONSCHEMA_URL=https://github.com/supabase/pg_jsonschema/releases/download/v0.3.4/pg_jsonschema-v0.3.4-pg18

FROM scratch AS pg-jsonschema-amd64
ARG PG_JSONSCHEMA_URL
ADD --checksum=sha256:5c7fe6c810835e4242fb0365b57581c0009b0155200dd4f1266cee434295732f \
    ${PG_JSONSCHEMA_URL}-amd64-linux-gnu.deb /pg_jsonschema.deb

FROM scratch AS pg-jsonschema-arm64
ARG PG_JSONSCHEMA_URL
ADD --checksum=sha256:49355efc355cb8815ae482551b64598b0752f3b8cbc7a9d201bc66a91714e254 \
    ${PG_JSONSCHEMA_URL}-arm64-linux-gnu.deb /pg_jsonschema.deb

# Only the target architecture's stage is built.
FROM pg-jsonschema-${TARGETARCH} AS pg-jsonschema

FROM postgres:18.6-trixie
RUN --mount=type=bind,from=pg-jsonschema,source=/pg_jsonschema.deb,target=/tmp/pg_jsonschema.deb \
    dpkg -i /tmp/pg_jsonschema.deb
