# GOLEM: ARP Poison API

REST API for managing ARP spoofing MITM instances, built with FastAPI.

Wraps the `arpoison.bin` C binary with process lifecycle management, providing endpoints to start, stop, and monitor spoofing sessions.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager
- Root privileges (the underlying binary requires raw socket access)
- `arpoison.bin` compiled in `../backend/bin/`

## Setup

All commands must be run from the project root (`golem/`), not from within `api/`.

```bash
# Install dependencies
uv sync

# Build the backend binary (if not already built)
cd backend && make && cd -
```

## Running

```bash
sudo uv run python -m uvicorn api.main:app --host 0.0.0.0 --port 8080
```

The server must run as root because `arpoison.bin` opens raw sockets and toggles kernel IP forwarding.

API docs are available at `http://localhost:8080/docs` (Swagger UI) and `http://localhost:8080/redoc`.

## Endpoints

All endpoints are prefixed with `/api/v1`.

### Start ARP Poison (MITM)

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

Launches a MITM session between two victims. The binary continuously sends spoofed ARP replies to both hosts, redirecting their traffic through the attacker.

### Start Gratuitous ARP

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

Sends 3 gratuitous ARP replies to associate a new IP/MAC pair on the target router. The process exits automatically after sending.

### List Instances

```bash
curl http://localhost:8080/api/v1/spoofer
```

Returns all tracked instances with their status, PIDs, resolved MAC addresses, and spoofed IPs.

### Get Instance Details

```bash
curl http://localhost:8080/api/v1/spoofer/{instance_id}
```

### Stop Instance

```bash
curl -X DELETE http://localhost:8080/api/v1/spoofer/{instance_id}
```

Sends SIGTERM to the process, allowing it to close the raw socket and disable kernel IP forwarding. Falls back to SIGKILL after a 5-second timeout.

### Health Check

```bash
curl http://localhost:8080/api/v1/health
```

Reports running instance count, root privilege status, and binary availability.

## Configuration

Settings can be overridden via environment variables with the `ARPOISON_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `ARPOISON_BINARY_PATH` | `../backend/bin/arpoison.bin` | Path to the compiled binary |
| `ARPOISON_DEFAULT_TIMING_MS` | `2000` | Default flood timing in milliseconds |
| `ARPOISON_PROCESS_STOP_TIMEOUT` | `5.0` | Seconds to wait for SIGTERM before SIGKILL |
| `ARPOISON_STARTUP_PARSE_TIMEOUT` | `15.0` | Seconds to wait for binary init output |
| `ARPOISON_HOST` | `0.0.0.0` | Server bind address |
| `ARPOISON_PORT` | `8080` | Server port |

## Instance Lifecycle

```
STARTING ──▶ RUNNING ──▶ STOPPING ──▶ STOPPED
    │                                     ▲
    └──────────▶ FAILED ──────────────────┘
```

- **STARTING**: Process launched, parsing stdout for MAC/IP resolution
- **RUNNING**: Init complete, actively sending spoofed ARP packets
- **STOPPING**: SIGTERM sent, waiting for graceful shutdown
- **STOPPED**: Process exited cleanly
- **FAILED**: Process exited unexpectedly (bad interface, ARP resolution failure, not root)
