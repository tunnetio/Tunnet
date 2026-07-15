# Management Server

The management server (`apps/management`) is the Bun/Elysia HTTP API that powers the dashboard and public API.

## What it does

The management server handles user authentication (Better Auth with email/password, SSO, OAuth), organization and network CRUD, API key management, the REST API consumed by the dashboard, OAuth 2.0 device authorization for CLI login, SSH auth browser flows, and communication with the control plane via its internal admin API.

## Running with Docker

```bash
docker compose up -d management
```

The management image is built from `deploy/Dockerfile.management`. It uses `oven/bun:1` for building and `oven/bun:1-slim` at runtime. The workspace's full `package.json` graph is copied for correct lockfile resolution.

## Running manually

```bash
bun run management:start
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string (required) |
| `BETTER_AUTH_SECRET` | - | Auth signing secret, 32+ chars (required) |
| `DASHBOARD_URL` | `http://localhost:5173` | Dashboard origin for CORS and OAuth |
| `MANAGEMENT_URL` | `http://localhost:3000` | Public management API URL (listen port derived from this) |
| `CONTROL_PLANE_URL` | `http://localhost:8080` | Control plane URL (admin API derived on port 9091) |
| `TUNTUN_SERVICE_SECRET` | - | Internal API shared secret (must match control plane) |
