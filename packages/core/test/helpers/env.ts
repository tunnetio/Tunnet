import { createDb, schema } from "@tuntun/db";
import * as argon2 from "argon2";
import { eq } from "drizzle-orm";

export type TestEnv = {
  managementUrl: string;
  controlUrl: string;
  databaseUrl: string;
  apiKey: string;
  orgId: string;
  networkId: string;
  networkName: string;
  networkCidr: string;
};

function parseApiKeyPrefix(secret: string): string | null {
  const match = /^tt_([^_]+)_/.exec(secret);
  return match?.[1] ?? null;
}

export async function resolveTestEnv(): Promise<TestEnv | null> {
  const databaseUrl = process.env.DATABASE_URL;
  const apiKey = process.env.TUNTUN_TEST_SDK_API_KEY;
  if (!databaseUrl || !apiKey) {
    return null;
  }

  const managementUrl =
    process.env.TUNTUN_TEST_MANAGEMENT_URL ??
    process.env.MANAGEMENT_URL ??
    "http://127.0.0.1:3000";
  const controlUrl =
    process.env.TUNTUN_TEST_CONTROL_URL ??
    process.env.CONTROL_PLANE_URL ??
    "http://127.0.0.1:8080";

  const orgOverride = process.env.TUNTUN_TEST_ORG_ID;
  const networkOverride = process.env.TUNTUN_TEST_NETWORK_ID;

  const db = createDb(databaseUrl);
  const prefix = parseApiKeyPrefix(apiKey);
  if (!prefix) {
    return null;
  }

  const candidates = await db
    .select()
    .from(schema.apiKeys)
    .where(eq(schema.apiKeys.secretPrefix, prefix));

  let verified: (typeof candidates)[number] | null = null;
  for (const row of candidates) {
    if (await argon2.verify(row.hashedSecret, apiKey)) {
      verified = row;
      break;
    }
  }
  if (!verified) {
    return null;
  }

  const orgId = orgOverride ?? verified.organizationId;
  const networks = await db
    .select()
    .from(schema.networks)
    .where(eq(schema.networks.organizationId, orgId));

  if (networks.length === 0) {
    return null;
  }

  let network = networks.find((n) => n.id === networkOverride);
  if (!network && verified.networkIds?.length) {
    network = networks.find((n) => verified.networkIds?.includes(n.id));
  }
  network ??= networks[0]!;

  return {
    managementUrl,
    controlUrl,
    databaseUrl,
    apiKey,
    orgId,
    networkId: network.id,
    networkName: network.name,
    networkCidr: network.cidr,
  };
}

export async function waitForServices(env: TestEnv): Promise<boolean> {
  try {
    const [mgmt, control] = await Promise.all([
      fetch(`${env.managementUrl}/health`),
      fetch(`${env.controlUrl}/health`),
    ]);
    return mgmt.ok && control.ok;
  } catch {
    return false;
  }
}

export function assignedIpPrefix(cidr: string): string {
  const [base] = cidr.split("/");
  const octets = base.split(".");
  return `${octets[0]}.${octets[1]}.`;
}
