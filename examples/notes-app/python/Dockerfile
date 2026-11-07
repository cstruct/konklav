# syntax=docker/dockerfile:1

# One image for every Python service of the example. Built from the
# repository root, so the Python packages come from this checkout and match
# the Konklav server built next to them.

# Keep the Rust version in sync with mise.toml.
FROM rust:1.99.1-bookworm AS wheels
COPY --from=ghcr.io/astral-sh/uv:0.8.24 /uv /usr/local/bin/uv
WORKDIR /src
COPY . .
# konklav-relying wraps the Rust relying core, so maturin compiles it here.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/items/py/target \
    uv build --wheel --python 3.12 --out-dir /wheels items/py \
 && uv build --wheel --python 3.12 --out-dir /wheels items/py-control-plane \
 && uv build --wheel --python 3.12 --out-dir /wheels items/py-fastapi

FROM python:3.12-slim-bookworm
COPY --from=wheels /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl \
        fastapi==0.162.0 uvicorn==0.34.3 httpx==0.28.1 cryptography==45.0.4 \
        redis==8.1.0 asyncpg==0.30.0
COPY examples/notes-app/python/services /app
COPY examples/notes-app/web /app/web
# Empty named volumes take these owners: Konklav's distroless image runs as
# 65532 and reads its keys, the services run as nobody.
RUN mkdir /keys /shared && chown 65532:65532 /keys && chown nobody /shared
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app/shared
# Each service names its own command in compose.yaml.
USER nobody
