# Docker Compose Deployment

TunTun ships a production-ready `docker-compose.yml` at the repository root and four Dockerfiles in the `deploy/` directory. This is the fastest way to get the entire managed stack running.

## Quick start

```bash
# Clone the repository
git clone https://github.com/orielhaim/TunTun.git
cd TunTun

# Set secrets (or use the defaults for local development)
export TUNTUN_SERVICE_SECRET="$(openssl rand -base64 32)"
export BETTER_AUTH_SECRET="$(openssl rand -base64 32)"

# Start everything
docker compose up -d
```

Five containers come up in order: `postgres` starts first and runs its health check, `migrate` runs Drizzle migrations then exits, `control` and `management` start once the database is healthy and migrations are complete, and `dashboard` starts once management is healthy.

## Services

### postgres

Standard PostgreSQL 18 Alpine image. Data is persisted in the `pgdata` named volume. Exposed on port 5432 for local access (you can remove this in production).

### migrate

A one-shot container that uses the management image to run `bunx drizzle-kit migrate`. It exits after migrations complete. On subsequent `docker compose up` runs it checks if migrations are needed and exits quickly if the schema is current.

### control

The Rust control plane binary. Agents connect on **port 8080** (WebSocket). The internal admin API listens on **port 9091** - used by the management server and not exposed publicly in production. Port 9090 exposes internal metrics.

### management

The Bun/Elysia management API on **port 3000**. Handles user auth, organization management, REST API, OAuth device authorization, and SSH auth flows. Communicates with the control plane via `http://control:9091`.

### dashboard

The React SPA built with Vite and served via a Nitro server on **port 3000** inside the container, mapped to **port 5173** on the host. The dashboard proxies API requests to the management service at `http://management:3000`.

## Environment variables

The `docker-compose.yml` sets sensible defaults for local development. For production, you **must** change the following:

| Variable | Where | What to do |
|----------|-------|------------|
| `TUNTUN_SERVICE_SECRET` | control, management | Set to a random string of at least 32 characters. Must match on both services. |
| `BETTER_AUTH_SECRET` | management | Set to a random string of at least 32 characters. |
| `POSTGRES_PASSWORD` | postgres | Change from the default `tuntun`. |
| `DASHBOARD_URL` | management, dashboard, control | Public dashboard URL (CORS, OAuth, SSH browser auth). |
| `MANAGEMENT_URL` | management, dashboard | Public management API URL. |
| `CONTROL_PLANE_URL` | management, dashboard, control | Control plane URL for agents. |

You can set these in a `.env` file next to `docker-compose.yml`:

```env
TUNTUN_SERVICE_SECRET=your-random-secret-here-at-least-32-chars
BETTER_AUTH_SECRET=another-random-secret-here-at-least-32-chars
```

## Enrolling an agent

Once the stack is running, open the dashboard at `http://localhost:5173`, create an account and organization, then generate an enrollment token. On the machine you want to add:

```bash
sudo tuntun enroll \
  --control-url http://your-docker-host:8080 \
  --token YOUR_TOKEN

sudo tuntun run
```

## Production considerations

**TLS termination** - put a reverse proxy (Caddy, nginx, Traefik) in front of the management and dashboard services for HTTPS. The control plane WebSocket (port 8080) should also be behind TLS in production.

**Database backups** - the `pgdata` volume contains all state. Back it up regularly.

**Secret rotation** - if `TUNTUN_SERVICE_SECRET` or `BETTER_AUTH_SECRET` change, all containers that reference them must be restarted.

**Remove exposed ports** - in production, remove the `ports` mapping for `postgres` (5432) and `control` admin (9091). Only expose 8080 (agent WebSocket), 3000 (management API), and 5173 (dashboard).

## Dockerfiles reference

All Dockerfiles live in `deploy/` and use multi-stage builds:

### Dockerfile.control

Uses `rust:1.96-bookworm` with cargo-chef for layer caching. Builds the `tuntun-control` binary, strips symbols, and copies it into `debian:bookworm-slim` with just `ca-certificates`. Exposes ports 8080, 9090, and 9091.

### Dockerfile.management

Uses `oven/bun:1` for building - copies all workspace `package.json` files for lockfile resolution, runs `bun install --linker=hoisted`, then copies source. The runtime stage uses `oven/bun:1-slim` and runs the Elysia server directly. Exposes port 3000.

### Dockerfile.dashboard

Uses `oven/bun:1` for building - installs dependencies with the full workspace graph, then runs `bunx --bun vite build` in `apps/dashboard`. The build accepts `MANAGEMENT_URL`, `CONTROL_PLANE_URL`, and `DASHBOARD_URL` as build args. The runtime stage uses `oven/bun:1-slim` and serves the Nitro output. Exposes port 3000 (mapped to 5173 in compose).

### Dockerfile.relay

Uses `rust:1.96-bookworm` for building. Simpler than the control plane Dockerfile (no cargo-chef). Builds and strips `tuntun-relay`, copies into `debian:bookworm-slim`. Exposes ports 80 and 443. Entry point is `tuntun-relay run`.

## Adding the relay

The relay is not included in the default `docker-compose.yml` because it requires public DNS and TLS configuration. To add it:

```yaml
# Add to docker-compose.yml services:
relay:
  build:
    context: .
    dockerfile: deploy/Dockerfile.relay
  restart: unless-stopped
  depends_on:
    control:
      condition: service_started
  ports:
    - "443:443"
    - "80:80"
  environment:
    TUNTUN_RELAY_CONTROL_URL: "http://control:8080"
  volumes:
    - relay-certs:/etc/tuntun/certs
```

Then register and run the relay. See the [Relay self-hosted setup](/products/relay/self-hosted) for DNS and certificate configuration.

## Rebuilding

After code changes:

```bash
docker compose build
docker compose up -d
```

To rebuild a single service:

```bash
docker compose build control
docker compose up -d control
```
