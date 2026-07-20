# Environment Variables

Complete reference for environment variables used by Tunnet components.

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
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/tunnet` |
| `BETTER_AUTH_SECRET` | Auth signing secret (32+ chars) | `a-long-random-string-at-least-32-characters` |
| `TUNNET_SERVICE_SECRET` | Internal API shared secret (management ↔ control) | `a-long-random-string-at-least-32-characters` |
| `TUNNET_AUDIT_HMAC_KEY` | Audit integrity key (32+ chars) | `another-long-random-string-at-least-32-chars` |
| `TUNNET_LICENSE` | Optional commercial license certificate | `/etc/tunnet/license.json` |

## Agent (`tunnet`)

| Variable | Description | Example |
|----------|-------------|---------|
| `TUNNET_STATE_DIR` | Agent state directory | `~/.local/state/tunnet` |
| `CONTROL_PLANE_URL` | Control plane URL (`--control-url`) | `http://127.0.0.1:8080` |
| `MANAGEMENT_URL` | Management API URL (`tunnet login`) | `http://localhost:3000` |
| `TUNNET_ENROLL_TOKEN` | Enrollment token | `eyJ...` |
| `TUNNET_ORG_SLUG` | Organization slug (quick enroll) | `my-company` |
| `TUNNET_HOSTNAME` | Machine hostname | `api-prod` |
| `TUNNET_IFNAME` | TUN interface name | `tunnet0` |
| `TUNNET_POLL_SECS` | Snapshot poll interval | `30` |
| `TUNNET_METRICS_BIND` | Prometheus metrics bind | `127.0.0.1:9100` |
| `TUNNET_DISABLE_GOSSIP` | Disable gossip | `true` |
| `TUNNET_RECORDER` | Enable SSH recording | `true` |
| `TUNNET_JSON_LOGS` | JSON log format | `true` |

## Control plane

| Variable | Description | Default |
|----------|-------------|---------|
| `TUNNET_BIND` | Public API bind address | `0.0.0.0:8080` |
| `TUNNET_ADMIN_BIND` | Internal admin API bind | `127.0.0.1:9091` |
| `TUNNET_INTERNAL_BIND` | Metrics/ready bind | `127.0.0.1:9090` |
| `TUNNET_LICENSE` | Commercial license certificate (inline JSON, file path, or HTTPS URL). Unlocks Cloud/Enterprise features when valid. | - (Community) |
| `TUNNET_AUDIT_HMAC_KEY` | Secret used to protect the audit integrity chain (32+ characters, required for Managed) | - |
| `TUNNET_AUDIT_STREAM_WEBHOOK_URL` | Optional HTTP endpoint that receives batched audit events as JSON | - |
| `TUNNET_AUDIT_STREAM_WEBHOOK_HEADERS` | Optional comma-separated `Header:Value` pairs for the webhook | - |
| `TUNNET_AUDIT_BUFFER_SIZE` | In-memory audit buffer capacity before drop | `8192` |
| `TUNNET_AUDIT_BATCH_SIZE` | Max events flushed together | `500` |
| `TUNNET_AUDIT_FLUSH_INTERVAL_MS` | Max flush interval in milliseconds | `1000` |

See [Audit Logs](/guide/concepts/audit-logs) for how the trail works in the dashboard and how to verify integrity.
