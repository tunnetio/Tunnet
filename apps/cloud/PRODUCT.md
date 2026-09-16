# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary homepage visitor: an engineer or founder who already runs machines (laptops, servers, CI, Kubernetes) and is deciding whether to put them on a private network. They compare Tunnet to Tailscale and Cloudflare.

The same visitor may be a solo operator or a platform/infra buyer. Direct mode (zero-server P2P) is a real on-ramp. The homepage's job is still to move them into **managed cloud**.

## Product Purpose

Tunnet is private mesh networking. Enroll a machine, get an overlay IP and a hostname, then SSH, serve internal HTTPS, publish public tunnels, and transfer files under one identity and one policy engine.

Success for this site: a visitor creates a managed org at `https://app.tunnet.io` (or books a demo at `https://cal.com/tunnet/demo`). Installing the open-source agent is useful and true, not the primary conversion.

## Positioning

One identity and one ACL system for mesh, serve, tunnel, send, SSH, and self-hostable edges. The control plane, dashboard, API, and relays ship in the same repository. Neighbors sell a closed coordination server or make you stitch a VPN, a tunnel tool, a bastion, and a file hop.

Direct mode exists (passphrase mesh, no control plane, free). Managed is the product: SSO, audit, API, Policy as Code, SSH recording, cloud or self-host.

## Operating Context

Visitors arrive from docs, GitHub, Discord, or a comparison against Tailscale / Cloudflare / ngrok. They live in terminals, cloud consoles, and Kubernetes. Install is `curl -fsSL https://get.tunnet.io | sh` (Linux/macOS) or `irm https://get.tunnet.io | iex` (Windows, Administrator). Agent needs root/Administrator for TUN. Docs live at `https://docs.tunnet.io`.

## Capabilities and Constraints

Confirmed: Mesh, Serve, Tunnel, SSH, Send, self-hostable Edge, Kubernetes operator, Policy as Code, device posture, audit logs, Node/Rust embed SDKs, Go management SDK. Platforms: macOS, Linux, Windows. Relays when NAT blocks. Upgrade path: `tunnet upgrade-to-managed`.

Licensing: MPL-2.0 (runtime/agent/SDKs), AGPL-3.0-only (control plane/dashboard/relays), Apache-2.0 (protocol/common). Commercial License is an alternative for AGPL components.

Managed plans exist (Free, Personal, Team, Business, Enterprise) with real prices in `packages/api/src/billing/plans.ts`. Do not invent other prices.

Undecided: no confirmed customer names, logos, or scale numbers for marketing.

## Brand Commitments

- Name: Tunnet. Logo at `/logo.png`.
- Keep the existing CTA button construction (pill, tight type, arrow). Drop the copper/orange palette. Use high-quality matte dark or light tones.
- Homepage must not be a standard stacked-hero layout. Structure should be distinctive.
- Mobile nav must open as a proper overlay, not a list that dumps onto the hero.
- Use the components added under `packages/ui` (resizable navbar, scroll laptop/container, path-draw effect, pointer highlight, wobble cards, feature bento, theme toggle, action swap, hover feature cards, marquee).
- Copy is user-focused and specific. No fluff, no fake metrics, no vanity counters.
- Testimonials section is required (existing UI component). Treat current named quotes as placeholder unless replaced with confirmed quotes.
- Product screenshots may be placeholders with comments naming the real asset to drop in.
- Visual bar named by the user: Tailscale, Cloudflare, Raycast. This is a craft bar, not a license to clone their pages.
- Tear down the incumbent Layer-1 copper/obsidian marketing look. Product facts stay; the old visual world does not.

## Evidence on Hand

- Real: install commands, docs, Discord (`https://discord.gg/y5bNc3MYKz`), GitHub (`https://github.com/tunnetio/Tunnet`), status (`https://status.tunnet.io`), demo booking, plan catalog, CLI examples in the current site.
- Status: in development. Do not claim battle-tested enterprise scale.
- Absent: verified customer logos, independent benchmarks, usage counters. Do not invent them. Do not display vanity stats.
- Synthetic product demos are allowed and should be labeled where a visitor could mistake them for live telemetry.
- Placeholder images are allowed with an HTML comment naming the intended screenshot.

## Product Principles

1. Convert to managed cloud first. Open source is proof of openness, not the headline offer.
2. Show the mechanism: one agent, one identity, the jobs it replaces (VPN + tunnel + bastion + file hop).
3. Never fake proof. Placeholders and labeled demos beat invented numbers.
4. Same agent for a laptop mesh and a 5,000-person org. Direct is the on-ramp; Managed is the destination.
5. Every claim a visitor can act on: a command, a URL, a plan fact, or a documented capability.
