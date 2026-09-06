# Routing

Tunnet supports three types of routes: subnet routes, hostname routes, and exit routes. All routes are advertised through gateway machines and distributed via the network snapshot.

## Subnet routes

A subnet route tells the mesh "to reach this CIDR, send traffic through this gateway machine." This is how you make devices that do not have the Tunnet agent installed reachable from the mesh - printers, NAS boxes, legacy servers, IoT devices.

```bash
tunnet route add 192.168.1.0/24
```

This advertises the local LAN subnet through the current machine. Other peers can now reach 192.168.1.x addresses via the mesh.

## Hostname routes

Hostname routes map a DNS name to a mesh IP through a gateway. When a peer queries `internal-app.tunnet`, PeerDNS resolves it to a synthetic IP in the private peer range (the gateway peer address), and the routing table forwards traffic for that IP to the gateway machine.

Hostname routes support wildcards (`*.internal.tunnet`) for scenarios where you want to route all subdomains of a domain through a single gateway.

## Exit nodes

An exit node is a machine that routes traffic for the wider internet. When you configure a peer to use an exit node, all non-mesh traffic from that peer flows through the exit node. This is useful when you need a fixed egress IP or want to route internet traffic through a specific geographic location.

## Split tunnels

Split tunnel preferences control what traffic stays on the mesh versus goes through the local network. In **include** mode, only specified CIDRs use the mesh. In **exclude** mode (default), specified CIDRs bypass the mesh.
