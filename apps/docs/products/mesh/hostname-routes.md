# Hostname Routes

Hostname routes map DNS names to services accessible through a gateway machine. Unlike subnet routes (which operate on IP ranges), hostname routes let you expose specific services by name.

## How they work

When you create a hostname route for `internal-app`, PeerDNS resolves `internal-app.tunnet` to a synthetic IP in the private peer range (the gateway peer address). Traffic to that IP is routed through the designated gateway machine, which forwards it to the actual service.

## Wildcard routes

Hostname routes support wildcards. A route for `*.internal` matches `api.internal.tunnet`, `web.internal.tunnet`, and any other subdomain. This is useful for routing all services behind a reverse proxy through a single gateway.

## Configuration

Hostname routes are managed in the dashboard under **Networks → Routes** or through the management API.
