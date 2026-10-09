# syntax=docker/dockerfile:1
#
# Golem — three-stage build.
#   Stage 1: build the C ARP-spoofing backend (arpoison.bin), statically linked.
#   Stage 2: resolve the Python virtualenv via uv (pyproject.toml/uv.lock).
#   Stage 3: runtime image for the FastAPI service, with the binary and venv
#            baked in.
#
# The API (api/) spawns the C binary as a subprocess and needs root + raw
# sockets at runtime; the runtime container is therefore run privileged with
# host networking (see docker-compose.yml).

# ============================================================================
# Stage 1 — build the C backend
# ============================================================================
FROM debian:trixie AS builder

# clang + make for the build, plus the C runtime dev headers needed to
# produce a *statically* linked binary (the Makefile passes --static on Linux).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        make \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY backend/ ./backend/

# The Makefile assumes build/ and bin/ already exist (it does not mkdir them).
RUN mkdir -p backend/build backend/bin \
    && make -C backend \
    && test -x backend/bin/arpoison.bin

# ============================================================================
# Stage 2 — resolve the Python virtualenv via uv
# ============================================================================
FROM ghcr.io/astral-sh/uv:0.12.24-python3.11-trixie-slim AS python-deps

WORKDIR /app

# uv sync is driven by the project's pyproject.toml/uv.lock
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ============================================================================
# Stage 3 — runtime image (FastAPI service)
# ============================================================================
FROM ghcr.io/astral-sh/uv:0.12.24-python3.11-trixie-slim AS runtime

# curl is only needed for the container healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Bring in the pre-resolved venv (built by uv in the python-deps stage) and
# the application code plus the pre-built backend binary.
COPY --from=python-deps /app/.venv ./.venv
COPY api/ ./api/
COPY --from=builder /build/backend/bin/arpoison.bin ./backend/bin/arpoison.bin

# Make the uv-managed venv the default Python for CMD below.
ENV PATH="/app/.venv/bin:${PATH}"

# Defaults used by the API (all overridable via ARPOISON_* env vars).
ENV ARPOISON_BINARY_PATH=/app/backend/bin/arpoison.bin \
    ARPOISON_HOST=0.0.0.0 \
    ARPOISON_PORT=8080

EXPOSE 8080

# FastAPI service entrypoint. Uses a shell form so the ARPOISON_HOST /
# ARPOISON_PORT env vars (set above, overridable at runtime) are honoured.
CMD ["sh", "-c", "python -m uvicorn api.main:app --host \"$ARPOISON_HOST\" --port \"$ARPOISON_PORT\""]
