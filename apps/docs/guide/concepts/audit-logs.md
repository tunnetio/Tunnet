# Audit Logs

Managed Tunnet keeps an organization-wide audit trail of administrative and security-relevant activity. Use it for investigations, compliance reviews, and day-to-day accountability.

Audit logging is available in Managed mode for every deployment, including Community self-hosts.

## Where to view logs

Open the dashboard and go to **Logs**. Entries are listed newest first and include:

- When the event occurred
- A short human-readable summary
- Who performed the action
- What resource was affected

You can load additional pages with **Load more**. Filtering by time range, actor, and resource type is available through the management API.

## What gets recorded

Typical events include:

- Network create, update, and delete
- Machine enrollment, approval, label/tag changes, and cleanup
- Access policy and posture changes
- Tunnel, Serve, and relay changes
- SSH-related administrative actions
- Member, invitation, SSO, and API key changes
- Certificate and CA operations

Routine mesh traffic between peers is **not** written to the audit log. Audit covers control-plane and administrative actions, not every packet on the network.

## Integrity

Each organization’s audit trail is append-only and cryptographically linked: every entry depends on the previous one. That makes silent edits or deletions detectable.

Self-hosters can verify the chain for an organization:

```bash
tunnet-control audit verify --org <organization_id>
```

A successful run reports how many events were checked and the sequence range. A failure points at the first broken entry so you can investigate.

Set `TUNNET_AUDIT_HMAC_KEY` on the control plane before relying on verification. Use a long random secret (32+ characters) and treat it like any other signing key: rotate only with a deliberate plan, and keep it out of application logs.

## Export to your SIEM

You can stream audit events to a webhook endpoint you control (any HTTP collector that accepts JSON batches):

```bash
TUNNET_AUDIT_STREAM_WEBHOOK_URL=https://siem.example.com/hooks/tunnet
# Optional: comma-separated Header:Value pairs
TUNNET_AUDIT_STREAM_WEBHOOK_HEADERS=Authorization:Bearer your-token
```

Delivery is best-effort with retries. PostgreSQL remains the system of record for the dashboard and for chain verification.

## Commercial features

Community deployments already get the dashboard trail, integrity verification, and webhook export.

**Cloud** and **Enterprise** licenses unlock additional audit options for larger estates — high-volume analytics storage and native connectors for common SIEM / object-storage targets. Install a license with `TUNNET_LICENSE` (inline JSON, file path, or HTTPS URL). See [Environment Variables](/self-hosting/env) and [COMMERCIAL-LICENSE.md](https://github.com/tunnetio/Tunnet/blob/main/COMMERCIAL-LICENSE.md).

## Upgrading from older releases

Releases that introduce the current audit schema replace the previous audit table. Historical rows are **not** migrated automatically. If you need the old history, export it with `pg_dump` before upgrading.
