# Dashboard

The dashboard (`apps/dashboard`) is a React SPA built with Vite, TanStack Query, and shadcn/ui.

## Running with Docker

```bash
docker compose up -d dashboard
```

The dashboard image is built from `deploy/Dockerfile.dashboard`. At build time, Vite compiles the React app with `MANAGEMENT_URL`, `CONTROL_PLANE_URL`, and optional `DASHBOARD_URL` from the root `.env` or Docker build args.

When `MANAGEMENT_URL` points at a different host than the dashboard, the Nitro server proxies `/api`, `/auth`, and `/.well-known` to the management service.

## Running manually

```bash
bun run dash:build
bun run dash:preview
```

## Configuration

| Variable | Description |
|----------|-------------|
| `DASHBOARD_URL` | Dashboard public URL (enrollment commands, OAuth) |
| `MANAGEMENT_URL` | Management API URL (browser client + Nitro proxy target) |
| `CONTROL_PLANE_URL` | Control plane URL (shown in enroll/relay commands) |

## Pages

The dashboard covers **Overview** (organization summary), **Machines** (list, detail, tags, serves, tunnels), **Relays** (registration, status), **Tunnels** (create, manage, redirects, port mappings), **Serves** (create, manage, ACLs), **Transfers** (file transfer monitoring), **SSH** (sessions, recordings), **Networks** (mesh map, access policies, routes, enrollment), **Users** (organization members), **Access** (org-wide policies), **Logs** (audit trail), and **Settings** (organization, internal CA, tunnel defaults, SSO, API keys, account).
