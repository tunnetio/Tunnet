# Environment Variables

Complete reference for environment variables used by TunTun components.

## Service URL bindings

These three URLs are the only service bindings you need to configure. Set them in the repository root `.env` for local development.

| Variable | Description | Example |
|----------|-------------|---------|
| `DASHBOARD_URL` | Dashboard origin (CORS, OAuth redirects, SSH browser auth) | `http://localhost:5173` |
| `MANAGEMENT_URL` | Management API public URL (auth, REST API, CLI login) | `http://localhost:3000` |
| `CONTROL_PLANE_URL` | Control plane URL (agent enroll, relay register) | `http://localhost:8080` |

The management server derives the control plane admin API URL from `CONTROL_PLANE_URL` (same host, port `9091`).

## Secrets

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/tuntun` |
| `BETTER_AUTH_SECRET` | Auth signing secret (32+ chars) | `a-long-random-string-at-least-32-characters` |
| `TUNTUN_SERVICE_SECRET` | Internal API shared secret (management ↔ control) | `a-long-random-string-at-least-32-characters` |

## Agent (`tuntun`)

| Variable | Description | Example |
|----------|-------------|---------|
| `TUNTUN_STATE_DIR` | Agent state directory | `~/.local/state/tuntun` |
| `CONTROL_PLANE_URL` | Control plane URL (`--control-url`) | `http://127.0.0.1:8080` |
| `MANAGEMENT_URL` | Management API URL (`tuntun login`) | `http://localhost:3000` |
| `TUNTUN_ENROLL_TOKEN` | Enrollment token | `eyJ...` |
| `TUNTUN_ORG_SLUG` | Organization slug (quick enroll) | `my-company` |
| `TUNTUN_HOSTNAME` | Machine hostname | `api-prod` |
| `TUNTUN_IFNAME` | TUN interface name | `tuntun0` |
| `TUNTUN_POLL_SECS` | Snapshot poll interval | `30` |
| `TUNTUN_METRICS_BIND` | Prometheus metrics bind | `127.0.0.1:9100` |
| `TUNTUN_DISABLE_GOSSIP` | Disable gossip | `true` |
| `TUNTUN_RECORDER` | Enable SSH recording | `true` |
| `TUNTUN_JSON_LOGS` | JSON log format | `true` |

## Control plane internals

| Variable | Description | Default |
|----------|-------------|---------|
| `TUNTUN_BIND` | Public API bind address | `0.0.0.0:8080` |
| `TUNTUN_ADMIN_BIND` | Internal admin API bind | `127.0.0.1:9091` |
| `TUNTUN_INTERNAL_BIND` | Metrics/ready bind | `127.0.0.1:9090` |
