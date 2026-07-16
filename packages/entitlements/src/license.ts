import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

import { isPaidTier, type PaidTier } from "./index";

const ALG = "Ed25519" as const;
const VERSION = 1 as const;

/** Issuer public key (SPKI DER, base64). */
export const TUNTUN_LICENSE_PUBLIC_KEY_B64 =
  "MCowBQYDK2VwAyEAVFRLxiUbgHbnzc7/a3QdJYs3pqkwIKA6JR/iCbMl670=";

export type LicensePayload = {
  v: typeof VERSION;
  tier: PaidTier;
  /** Unix seconds — not valid after. */
  exp: number;
  /** Unix seconds — issued at. */
  iat: number;
  /** Optional customer id. */
  sub?: string;
};

export type LicenseCertificate = {
  alg: typeof ALG;
  payload: LicensePayload;
  /** Base64url Ed25519 signature over the canonical payload. */
  signature: string;
};

export type VerifiedLicense = {
  payload: LicensePayload;
  expired: boolean;
};

function canonicalBytes(payload: LicensePayload): Buffer {
  const body: Record<string, string | number> = {
    v: payload.v,
    tier: payload.tier,
    exp: payload.exp,
    iat: payload.iat,
  };
  if (payload.sub !== undefined) body.sub = payload.sub;
  return Buffer.from(JSON.stringify(body), "utf8");
}

function toBase64Url(data: Buffer): string {
  return data
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value: string): Buffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad =
    padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return Buffer.from(padded + pad, "base64");
}

function parsePayload(value: unknown): LicensePayload | null {
  if (value === null || typeof value !== "object") return null;
  const obj = value as Record<string, unknown>;
  if (obj.v !== VERSION || !isPaidTier(obj.tier)) return null;
  if (typeof obj.exp !== "number" || !Number.isFinite(obj.exp)) return null;
  if (typeof obj.iat !== "number" || !Number.isFinite(obj.iat)) return null;
  if (obj.sub !== undefined && typeof obj.sub !== "string") return null;
  return {
    v: VERSION,
    tier: obj.tier,
    exp: obj.exp,
    iat: obj.iat,
    ...(obj.sub !== undefined ? { sub: obj.sub } : {}),
  };
}

function parseCertificate(value: unknown): LicenseCertificate | null {
  if (value === null || typeof value !== "object") return null;
  const obj = value as Record<string, unknown>;
  if (obj.alg !== ALG || typeof obj.signature !== "string" || !obj.signature) {
    return null;
  }
  const payload = parsePayload(obj.payload);
  if (!payload) return null;
  return { alg: ALG, payload, signature: obj.signature };
}

/** Verify a certificate object or JSON string. Invalid → null. */
export function verifyLicense(
  input: unknown,
  nowSec: number = Math.floor(Date.now() / 1000),
): VerifiedLicense | null {
  let value = input;
  if (typeof input === "string") {
    try {
      value = JSON.parse(input) as unknown;
    } catch {
      return null;
    }
  }

  const cert = parseCertificate(value);
  if (!cert) return null;

  let signature: Buffer;
  try {
    signature = fromBase64Url(cert.signature);
  } catch {
    return null;
  }

  const publicKey = createPublicKey({
    key: Buffer.from(TUNTUN_LICENSE_PUBLIC_KEY_B64, "base64"),
    format: "der",
    type: "spki",
  });

  if (!verify(null, canonicalBytes(cert.payload), publicKey, signature)) {
    return null;
  }

  return {
    payload: cert.payload,
    expired: cert.payload.exp <= nowSec,
  };
}

/** Create and sign a license certificate. */
export function issueLicense(input: {
  tier: PaidTier;
  privateKeyPkcs8DerBase64: string;
  /** Absolute expiry (unix seconds). Overrides `expiresInDays`. */
  exp?: number;
  expiresInDays?: number;
  iat?: number;
  sub?: string;
}): LicenseCertificate {
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const exp =
    input.exp ?? iat + Math.floor((input.expiresInDays ?? 365) * 24 * 60 * 60);
  if (exp <= iat) throw new Error("License exp must be after iat");

  const payload: LicensePayload = {
    v: VERSION,
    tier: input.tier,
    exp,
    iat,
    ...(input.sub !== undefined ? { sub: input.sub } : {}),
  };

  const privateKey = createPrivateKey({
    key: Buffer.from(input.privateKeyPkcs8DerBase64.trim(), "base64"),
    format: "der",
    type: "pkcs8",
  });

  return {
    alg: ALG,
    payload,
    signature: toBase64Url(sign(null, canonicalBytes(payload), privateKey)),
  };
}
