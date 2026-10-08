# Golem

A two-layer toolkit for ARP manipulation on wired Ethernet LANs: a low-level C binary that forges and injects raw ARP frames, and a FastAPI service that wraps it with process lifecycle management and a REST interface.

> **Responsible use** -- ARP spoofing intercepts and redirects traffic between hosts. Use this tool **only on networks you own or for which you have explicit, written permission** (lab, CTF, authorized penetration test). Unauthorized use is illegal in most jurisdictions.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    api/ (Python)                     │
│  FastAPI REST service · process lifecycle manager    │
│  Launches, monitors, and stops arpoison.bin instances│
└──────────────────────┬──────────────────────────────┘
                       │ subprocess (stdin/stdout)
┌──────────────────────▼──────────────────────────────┐
│                 backend/ (C)                         │
│  arpoison.bin · raw ARP frame forgery & injection   │
│  Linux (AF_PACKET) and macOS (BPF) support          │
└─────────────────────────────────────────────────────┘
```

## Modules

### `backend/` -- ARP Spoofing Engine (C)

A cross-platform (Linux / macOS) C binary that operates in two modes:

- **Mode 0 -- ARP Poison (MITM)**: continuously sends forged ARP replies to two victim hosts, redirecting all traffic between them through the attacker machine (with kernel IP forwarding enabled).
- **Mode 1 -- Gratuitous ARP**: sends 3 unsolicited ARP replies to a router, announcing a forged IP-to-MAC binding.

The code is organized in four layers:

| File | Role |
|---|---|
| `src/arpoison.c` | Entry point, CLI parsing, attack mode dispatch, flood loop, signal handlers |
| `src/packet_forge.c/h` | NIC discovery, ARP cache warm-up, Ethernet/ARP header construction |
| `src/platform.c/h` | OS abstraction -- raw sockets, MAC/IP retrieval, ARP-cache lookup, IP-forwarding control |
| `src/utils.c/h` | Fatal error handler, string helpers, timestamps |
| `src/arp.h`, `src/ether-def.h` | Wire-format struct definitions and protocol constants |
| `src/color_codes.h` | ANSI terminal color macros |

Built with `clang -O3 -Wall`; statically linked on Linux, dynamically linked on macOS.

### `api/` -- REST API (Python / FastAPI)

A FastAPI service that manages `arpoison.bin` as supervised subprocesses, exposing a REST interface to start, stop, and monitor spoofing sessions.

| File | Role |
|---|---|
| `main.py` | Application entry point, FastAPI lifespan (startup checks, graceful shutdown) |
| `routes.py` | API endpoint definitions under `/api/v1` |
| `models.py` | Pydantic request/response schemas and validation (IPv4, MAC, interface names) |
| `process_manager.py` | Subprocess lifecycle: launch, stdout parsing, status tracking, SIGTERM/SIGKILL teardown |
| `config.py` | `pydantic-settings` configuration with `ARPOISON_` env-var prefix |

**Endpoints** (all under `/api/v1`):

| Method | Path | Description |
|---|---|---|
| `POST` | `/spoofer` | Start an ARP Poison (MITM) session |
| `POST` | `/spoofer/gratuitous` | Start a Gratuitous ARP session |
| `GET` | `/spoofer` | List all tracked instances |
| `GET` | `/spoofer/{id}` | Get instance details |
| `DELETE` | `/spoofer/{id}` | Stop an instance (SIGTERM, then SIGKILL after timeout) |
| `GET` | `/health` | Health check (root status, binary availability, running count) |

**Instance lifecycle**: `STARTING` -> `RUNNING` -> `STOPPING` -> `STOPPED` (or `FAILED` on unexpected exit).

## Requirements

- **Backend**: `clang` (or any C11 compiler), Linux or macOS
- **API**: Python 3.11+, [uv](https://docs.astral.sh/uv/) package manager
- **Containerized (optional)**: [Podman](https://podman.io/) (or Docker) with compose support
- **Runtime**: root privileges (raw sockets and kernel IP-forwarding control)

## Quick Start (native)

```bash
# Build the C binary
cd backend
mkdir -p build bin
make
cd ..

# Install Python dependencies
uv sync

# Run the API server (requires root)
sudo uv run python -m uvicorn api.main:app --host 0.0.0.0 --port 8080
```

API docs are available at `/docs` (Swagger UI) and `/redoc`.

## Quick Start (containerized)

The repo ships a two-stage `Containerfile` (stage 1 statically builds the C backend with `clang`/`make`, stage 2 installs the Python dependencies and bakes the binary into a `python:3.11-slim` runtime image) plus a `podman-compose.yml` deployment file.

```bash
# Build the image and start the service
podman compose up -d --build

# Follow logs / stop the service
podman compose logs -f
podman compose down
```

> **Security note**: the service MUST run with host networking and `privileged: true` so the backend can open raw `AF_PACKET` sockets and toggle `/proc/sys/net/ipv4/ip_forward`. With `network_mode: host`, the API binds `ARPOISON_PORT` (default `8080`) directly on the host — no port mapping is performed.

Configuration via environment variables: copy `.env.example` to `.env` and edit to taste; every `ARPOISON_*` variable is also overridable inline in the `environment:` block of `podman-compose.yml` (inline values win over `.env`).

### Example: Start a MITM session

```bash
curl -X POST http://localhost:8080/api/v1/spoofer \
  -H 'Content-Type: application/json' \
  -d '{
    "interface": "eth0",
    "victim1_ip": "192.168.1.10",
    "victim2_ip": "192.168.1.1",
    "timing_ms": 2000
  }'
```

### Example: Send a Gratuitous ARP

```bash
curl -X POST http://localhost:8080/api/v1/spoofer/gratuitous \
  -H 'Content-Type: application/json' \
  -d '{
    "interface": "eth0",
    "router_ip": "192.168.1.1",
    "new_ip": "192.168.1.99",
    "new_mac": "aa:bb:cc:dd:ee:ff"
  }'
```

## Configuration

The API server is configured via environment variables with the `ARPOISON_` prefix:

| Variable | Default | Description |
|---|---|---|
| `ARPOISON_BINARY_PATH` | `backend/bin/arpoison.bin` (native) / `/app/backend/bin/arpoison.bin` (container) | Path to the compiled binary |
| `ARPOISON_DEFAULT_TIMING_MS` | `2000` | Default flood timing (ms) |
| `ARPOISON_PROCESS_STOP_TIMEOUT` | `5.0` | Seconds before SIGKILL fallback |
| `ARPOISON_STARTUP_PARSE_TIMEOUT` | `15.0` | Seconds to wait for binary init output |
| `ARPOISON_HOST` | `0.0.0.0` | Server bind address |
| `ARPOISON_PORT` | `8080` | Server port |

## Project Layout

```
golem/
├── Containerfile               # Two-stage build (C backend + Python runtime)
├── podman-compose.yml          # Podman Compose deployment (host network, privileged)
├── .containerignore            # Container build-context exclusions
├── .env.example                # Config template (ARPOISON_* variables)
├── api/                        # FastAPI REST service
│   ├── main.py                 # App entry point and lifespan
│   ├── routes.py               # Endpoint definitions
│   ├── models.py               # Request/response schemas
│   ├── process_manager.py      # Subprocess lifecycle management
│   └── config.py               # Settings (env-var driven)
├── backend/                    # C ARP spoofing engine
│   ├── Makefile                # Build system
│   └── src/
│       ├── arpoison.c          # Main program
│       ├── packet_forge.c/h    # Frame construction
│       ├── platform.c/h        # OS abstraction layer
│       ├── utils.c/h           # Helpers
│       ├── arp.h               # ARP wire format
│       ├── ether-def.h         # Ethernet wire format
│       └── color_codes.h       # Terminal colors
├── pyproject.toml              # Python project metadata (uv)
└── LICENSE                     # GPLv3
```

## License

GNU General Public License v3. See [LICENSE](LICENSE).
