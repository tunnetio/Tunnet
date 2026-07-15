import { createHash, createHmac, randomBytes } from "node:crypto";

import {
  type InternalHealthResponse,
  type InternalReadyResponse,
  internalHealthResponse,
  internalReadyResponse,
  type RegisterDeviceBody,
  type RegisterDeviceResponse,
  registerDeviceResponse,
  type ValidateNetworkResponse,
  validateNetworkResponse,
} from "@tuntun/api/internal";
import { getControlPlaneAdminUrl } from "@tuntun/env";
import ky, { isHTTPError, type KyInstance } from "ky";

const HDR_TIMESTAMP = "x-tuntun-timestamp";
const HDR_NONCE = "x-tuntun-nonce";
const HDR_SIGNATURE = "x-tuntun-signature";

function getAdminUrl(): string {
  return getControlPlaneAdminUrl();
}

function getServiceSecret(): string {
  const secret = process.env.TUNTUN_SERVICE_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("TUNTUN_SERVICE_SECRET must be at least 32 characters");
  }
  return secret;
}

function signRequest(
  method: string,
  path: string,
  body: string,
): Record<string, string> {
  const secret = getServiceSecret();
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`;
  const signature = createHmac("sha256", secret)
    .update(canonical)
    .digest("hex");

  return {
    [HDR_TIMESTAMP]: timestamp,
    [HDR_NONCE]: nonce,
    [HDR_SIGNATURE]: signature,
  };
}

function formatErrorBody(data: unknown): string {
  if (typeof data === "string") {
    return data;
  }
  if (data === undefined || data === null) {
    return "";
  }
  return JSON.stringify(data);
}

function createSignedClient(): KyInstance {
  return ky.create({
    baseUrl: getAdminUrl(),
    retry: 0,
    hooks: {
      beforeRequest: [
        async ({ request }) => {
          const url = new URL(request.url);
          const path = url.pathname;
          const method = request.method.toUpperCase();
          const body =
            request.method === "GET" || request.method === "HEAD"
              ? ""
              : await request.clone().text();
          const authHeaders = signRequest(method, path, body);
          for (const [key, value] of Object.entries(authHeaders)) {
            request.headers.set(key, value);
          }
        },
      ],
      beforeError: [
        ({ error }) => {
          if (isHTTPError(error)) {
            const path = new URL(error.request.url).pathname;
            const detail = formatErrorBody(error.data);
            return new Error(
              `Control plane ${error.request.method} ${path} failed: ${error.response.status}${detail ? ` ${detail}` : ""}`,
            );
          }
          return error;
        },
      ],
    },
  });
}

let client: KyInstance | undefined;

function getClient(): KyInstance {
  client ??= createSignedClient();
  return client;
}

export async function getControlPlaneHealth(): Promise<InternalHealthResponse> {
  const data = await getClient().get("/internal/v1/health").json();
  return internalHealthResponse.parse(data);
}

export async function getControlPlaneReady(): Promise<InternalReadyResponse> {
  const data = await getClient().get("/internal/v1/ready").json();
  return internalReadyResponse.parse(data);
}

export async function validateNetwork(
  networkId: string,
): Promise<ValidateNetworkResponse> {
  const data = await getClient()
    .post(`/internal/v1/networks/${networkId}/validate`, { body: "" })
    .json();
  return validateNetworkResponse.parse(data);
}

function toSnakeRegisterBody(
  body: RegisterDeviceBody,
): Record<string, unknown> {
  return {
    endpoint_id: body.endpointId,
    organization_id: body.organizationId,
    network_id: body.networkId,
    hostname: body.hostname,
    os: body.os ?? "",
    agent_version: body.agentVersion ?? "",
    device_type: body.deviceType,
    metadata: body.metadata,
  };
}

function parseRegisterDeviceResponse(data: unknown): RegisterDeviceResponse {
  if (!data || typeof data !== "object") {
    throw new Error("Invalid register device response");
  }
  const raw = data as Record<string, unknown>;
  return registerDeviceResponse.parse({
    organizationId: raw.organization_id ?? raw.organizationId,
    networkId: raw.network_id ?? raw.networkId,
    networkName: raw.network_name ?? raw.networkName,
    snapshot: raw.snapshot,
  });
}

export async function registerDevice(
  body: RegisterDeviceBody,
): Promise<RegisterDeviceResponse> {
  const data = await getClient()
    .post("/internal/v1/devices/register", {
      json: toSnakeRegisterBody(body),
    })
    .json();
  return parseRegisterDeviceResponse(data);
}

export async function pushOpenTunnel(body: {
  endpointId: string;
  tunnelId: string;
  relayAddr: string;
  subdomain: string;
  publicHostname: string;
  localPort: number;
  protocol: string;
  authToken: string;
  redirectRules?: Array<{
    pathPattern: string;
    targetPort: number;
    targetIp?: string;
  }>;
}): Promise<void> {
  await getClient()
    .post("/internal/v1/tunnels/open", {
      json: {
        endpoint_id: body.endpointId,
        tunnel_id: body.tunnelId,
        relay_addr: body.relayAddr,
        subdomain: body.subdomain,
        public_hostname: body.publicHostname,
        local_port: body.localPort,
        protocol: body.protocol,
        auth_token: body.authToken,
        redirect_rules: (body.redirectRules ?? []).map((r) => ({
          pathPattern: r.pathPattern,
          targetPort: r.targetPort,
          ...(r.targetIp ? { targetIpv4: r.targetIp } : {}),
        })),
      },
    })
    .json();
}

export async function pushStopTunnel(body: {
  endpointId: string;
  tunnelId: string;
}): Promise<void> {
  await getClient()
    .post("/internal/v1/tunnels/stop", {
      json: {
        endpoint_id: body.endpointId,
        tunnel_id: body.tunnelId,
      },
    })
    .json();
}

export async function pushStartServe(body: {
  endpointId: string;
  serveId: string;
  port: number;
  protocol: string;
  internalHostname: string;
  certificatePem?: string;
  privateKeyPem?: string;
  accessMode?: string;
  allowedTags?: string[];
  allowedEndpointIds?: string[];
}): Promise<void> {
  await getClient()
    .post("/internal/v1/serves/start", {
      json: {
        endpoint_id: body.endpointId,
        serve_id: body.serveId,
        port: body.port,
        protocol: body.protocol,
        internal_hostname: body.internalHostname,
        certificate_pem: body.certificatePem,
        private_key_pem: body.privateKeyPem,
        access_mode: body.accessMode ?? "all_peers",
        allowed_tags: body.allowedTags ?? [],
        allowed_endpoint_ids: body.allowedEndpointIds ?? [],
      },
    })
    .json();
}

export async function pushStopServe(body: {
  endpointId: string;
  serveId: string;
}): Promise<void> {
  await getClient()
    .post("/internal/v1/serves/stop", {
      json: {
        endpoint_id: body.endpointId,
        serve_id: body.serveId,
      },
    })
    .json();
}

export async function pushKillSshSession(body: {
  endpointId: string;
  sessionId: string;
}): Promise<void> {
  await getClient()
    .post("/internal/v1/ssh/kill-session", {
      json: {
        endpoint_id: body.endpointId,
        session_id: body.sessionId,
      },
    })
    .json();
}

export async function pushSendFile(body: {
  endpointId: string;
  transferId: string;
  path: string;
  target: string;
  message?: string;
}): Promise<void> {
  await getClient()
    .post("/internal/v1/transfers/send", {
      json: {
        endpoint_id: body.endpointId,
        transfer_id: body.transferId,
        path: body.path,
        target: body.target,
        message: body.message,
      },
    })
    .json();
}

export async function pushAcceptTransfer(body: {
  endpointId: string;
  transferId: string;
}): Promise<void> {
  await getClient()
    .post("/internal/v1/transfers/accept", {
      json: {
        endpoint_id: body.endpointId,
        transfer_id: body.transferId,
      },
    })
    .json();
}

export async function pushRejectTransfer(body: {
  endpointId: string;
  transferId: string;
  reason?: string;
}): Promise<void> {
  await getClient()
    .post("/internal/v1/transfers/reject", {
      json: {
        endpoint_id: body.endpointId,
        transfer_id: body.transferId,
        reason: body.reason,
      },
    })
    .json();
}

export async function pushSetSendConsent(body: {
  endpointId: string;
  mode: string;
  inboxPath?: string;
  pinBlobs: boolean;
}): Promise<void> {
  await getClient()
    .post("/internal/v1/transfers/set-consent", {
      json: {
        endpoint_id: body.endpointId,
        mode: body.mode,
        inbox_path: body.inboxPath,
        pin_blobs: body.pinBlobs,
      },
    })
    .json();
}
