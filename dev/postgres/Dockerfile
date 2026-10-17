# Postgres with the extensions Conclave's schema requires.
FROM postgres:18.6-trixie

ARG TARGETARCH
ARG PG_JSONSCHEMA_VERSION=0.3.4

# pg_jsonschema validates credential data (jsonb) against JSON Schemas in
# check constraints. Supabase publishes .deb builds per Postgres major and
# architecture.
ADD https://github.com/supabase/pg_jsonschema/releases/download/v${PG_JSONSCHEMA_VERSION}/pg_jsonschema-v${PG_JSONSCHEMA_VERSION}-pg18-${TARGETARCH}-linux-gnu.deb /tmp/pg_jsonschema.deb
RUN dpkg -i /tmp/pg_jsonschema.deb && rm /tmp/pg_jsonschema.deb
