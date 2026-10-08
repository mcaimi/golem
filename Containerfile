# syntax=docker/dockerfile:1
#
# Golem — two-stage build.
#   Stage 1: build the C ARP-spoofing backend (arpoison.bin), statically linked.
#   Stage 2: runtime image for the FastAPI service, with the binary baked in.
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
# Stage 2 — runtime image (FastAPI service)
# ============================================================================
FROM python:3.11-slim AS runtime

# curl is only needed for the container healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the Python runtime dependencies first (better layer caching).
# Extract the runtime deps from pyproject.toml into requirements.txt, then
# install from that — keeps the build declarative without a build tool.
COPY pyproject.toml ./
RUN python - <<'PY'
import tomllib
with open("pyproject.toml", "rb") as f:
    data = tomllib.load(f)
with open("requirements.txt", "w") as out:
    for dep in data["project"]["dependencies"]:
        out.write(dep + "\n")
PY
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and the pre-built backend binary.
COPY api/ ./api/
COPY --from=builder /build/backend/bin/arpoison.bin ./backend/bin/arpoison.bin

# Defaults used by the API (all overridable via ARPOISON_* env vars).
ENV ARPOISON_BINARY_PATH=/app/backend/bin/arpoison.bin \
    ARPOISON_HOST=0.0.0.0 \
    ARPOISON_PORT=8080

EXPOSE 8080

# FastAPI service entrypoint. Uses a shell form so the ARPOISON_HOST /
# ARPOISON_PORT env vars (set above, overridable at runtime) are honoured.
CMD ["sh", "-c", "python -m uvicorn api.main:app --host \"$ARPOISON_HOST\" --port \"$ARPOISON_PORT\""]
