# Managed Mode

Managed mode is Tunnet's full-featured deployment. It includes a control plane, management API, web dashboard, SSO integration, access policies, audit logs, and centralized configuration.

## When to use Managed mode

Use managed mode when you need multi-user organizations with role-based access, SSO/OIDC integration (Okta, Google Workspace, etc.), centralized access policies and ACLs, [Policy as Code](/guide/policy-as-code) (HCL/JSON/YAML, Terraform, GitOps, drift detection, rollback), device posture compliance, a web dashboard for administration, tunnel and relay infrastructure, SSH session recording, [audit logs](/guide/concepts/audit-logs), or API key / OIDC CI access for automation.

## Components

Managed mode requires three server-side components. The **control plane** (`tunnet-control`) runs on port 8080 and handles agent WebSocket connections, enrollment, IP allocation, snapshot distribution, and relay coordination. The **management API** (`apps/management`) runs on port 3000 and handles user authentication, organization management, and the REST API. The **dashboard** (`apps/dashboard`) runs on port 5173 and provides the web UI.

All three components share a PostgreSQL database.

## Configuration

See the [Self-Hosting guide](/self-hosting/) for detailed setup instructions.
