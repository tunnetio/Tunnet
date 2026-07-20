# Control Plane

The control plane (`tunnet-control`) is the Rust server that coordinates managed networks.

## What it does

The control plane handles machine enrollment and IP allocation, network snapshot building and distribution, peer discovery (exchanging iroh endpoint IDs), WebSocket connections from agents, policy distribution, device posture reports and evaluation, tunnel routing (assigning tunnels to relays), relay registration, SSH session tracking, [audit logging](/guide/concepts/audit-logs), and the admin API used by the management server.

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | WebSocket | Agent connections |
| 9090 | HTTP | Internal metrics |
| 9091 | HTTP | Admin API (used by management server) |

## Running with Docker

```bash
docker compose up -d control
```

The control plane image is built from `deploy/Dockerfile.control` using a multi-stage Rust build with cargo-chef for layer caching. The final image is based on `debian:bookworm-slim` and contains only the binary plus `ca-certificates`.

## Running manually

```bash
./target/release/tunnet-control
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string (required) |
| `TUNNET_BIND` | `0.0.0.0:8080` | Agent WebSocket bind address |
| `TUNNET_INTERNAL_BIND` | `0.0.0.0:9090` | Internal metrics bind |
| `TUNNET_ADMIN_BIND` | `0.0.0.0:9091` | Admin API bind |
| `TUNNET_SERVICE_SECRET` | - | Shared secret for internal API auth (required, must match management) |
| `TUNNET_AUDIT_HMAC_KEY` | - | Audit integrity key (required, 32+ characters) |
| `TUNNET_LICENSE` | - | Optional commercial license (Cloud / Enterprise entitlements) |
| `TUNNET_AUDIT_STREAM_WEBHOOK_URL` | - | Optional SIEM / collector webhook for audit events |
| `TUNNET_JSON_LOGS` | `false` | Enable structured JSON logs |

## Audit verification

Verify the integrity chain for an organization:

```bash
tunnet-control audit verify --org <organization_id>
```

See [Audit Logs](/guide/concepts/audit-logs) for dashboard usage, webhook export, and commercial options.
