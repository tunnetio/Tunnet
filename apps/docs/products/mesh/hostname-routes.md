# Hostname Routes

Hostname routes map DNS names to services accessible through a gateway machine. Unlike subnet routes (which operate on IP ranges), hostname routes let you expose specific services by name.

## How they work

Hostname routes are used by Tunnet's stream APIs. The client sends the requested hostname in the authenticated stream header, so the gateway can distinguish exact and wildcard targets and connect to the intended service.

PeerDNS does not publish A records for hostname routes. A normal TCP connection to an IP address does not retain the hostname, so mapping the name to the gateway's peer address would silently connect to the gateway itself. Use a Tunnet stream client for hostname routes; use a subnet route when an unmodified IP application must reach the destination.

## Wildcard routes

Hostname routes support wildcards. A route for `*.internal` matches `api.internal.tunnet`, `web.internal.tunnet`, and any other subdomain. This is useful for routing all services behind a reverse proxy through a single gateway.

## Configuration

Hostname routes are managed in the dashboard under **Networks → Routes** or through the management API.
