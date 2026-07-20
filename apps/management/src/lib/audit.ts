import {
  type AuditIngestEvent,
  ingestAuditEvents,
} from "./control-plane-client";

const CLASS = {
  ACCOUNT_CHANGE: 7001,
  AUTH_AUDIT: 7002,
  ENTITY_MGMT: 7003,
  NETWORK_ACTIVITY: 7101,
  DEVICE_ACTIVITY: 7102,
  POLICY_ACTIVITY: 7103,
  TUNNEL_ACTIVITY: 7104,
  SSH_SESSION: 7105,
  RELAY_ACTIVITY: 7106,
  POSTURE_ACTIVITY: 7107,
  CERTIFICATE_ACTIVITY: 7108,
  FILE_TRANSFER: 7109,
  SERVE_ACTIVITY: 7110,
  API_KEY_ACTIVITY: 7111,
} as const;

const ACTIVITY = {
  CREATE: 1,
  READ: 2,
  UPDATE: 3,
  DELETE: 4,
  OTHER: 99,
} as const;

function mapAction(action: string): {
  classUid: number;
  activityId: number;
  targetType: string;
} {
  const prefix = action.split(".")[0] ?? "entity";
  let classUid: number = CLASS.ENTITY_MGMT;
  let targetType = "entity";

  switch (prefix) {
    case "network":
      classUid = CLASS.NETWORK_ACTIVITY;
      targetType = "network";
      break;
    case "device":
    case "sdk":
      classUid = CLASS.DEVICE_ACTIVITY;
      targetType = "device";
      break;
    case "policy":
    case "acl":
      classUid = CLASS.POLICY_ACTIVITY;
      targetType = "policy";
      break;
    case "tunnel":
      classUid = CLASS.TUNNEL_ACTIVITY;
      targetType = "tunnel";
      break;
    case "ssh":
      classUid = CLASS.SSH_SESSION;
      targetType = "ssh";
      break;
    case "relay":
      classUid = CLASS.RELAY_ACTIVITY;
      targetType = "relay";
      break;
    case "posture":
      classUid = CLASS.POSTURE_ACTIVITY;
      targetType = "posture";
      break;
    case "certificate":
    case "ca":
      classUid = CLASS.CERTIFICATE_ACTIVITY;
      targetType = "certificate";
      break;
    case "serve":
      classUid = CLASS.SERVE_ACTIVITY;
      targetType = "serve";
      break;
    case "api_key":
    case "apikey":
      classUid = CLASS.API_KEY_ACTIVITY;
      targetType = "api_key";
      break;
    case "member":
    case "user":
    case "invitation":
      classUid = CLASS.ACCOUNT_CHANGE;
      targetType = "user";
      break;
    case "auth":
    case "sso":
      classUid = CLASS.AUTH_AUDIT;
      targetType = "auth";
      break;
    default:
      break;
  }

  let activityId: number = ACTIVITY.OTHER;
  if (
    action.includes("created") ||
    action.includes("added") ||
    action.includes("registered") ||
    action.includes("enrolled") ||
    action.includes("issued")
  ) {
    activityId = ACTIVITY.CREATE;
  } else if (
    action.includes("deleted") ||
    action.includes("removed") ||
    action.includes("revoked") ||
    action.includes("purged")
  ) {
    activityId = ACTIVITY.DELETE;
  } else if (
    action.includes("updated") ||
    action.includes("changed") ||
    action.includes("patched") ||
    action.includes("set")
  ) {
    activityId = ACTIVITY.UPDATE;
  }

  return { classUid, activityId, targetType };
}

function toIngestEvent(input: {
  organizationId: string;
  actor: string;
  action: string;
  target?: string;
  metadata?: Record<string, unknown>;
  traceId?: string;
}): AuditIngestEvent {
  const { classUid, activityId, targetType } = mapAction(input.action);
  const targetId = input.target ?? "";
  return {
    organization_id: input.organizationId,
    class_uid: classUid,
    activity_id: activityId,
    message: `${input.action}${targetId ? ` on ${targetId}` : ""} by ${input.actor}`,
    actor: {
      actor_type: "user",
      actor_id: input.actor,
    },
    target: {
      target_type: targetType,
      target_id: targetId,
    },
    metadata: {
      action: input.action,
      ...(input.metadata ?? {}),
    },
    trace_id: input.traceId,
  };
}

/**
 * Emit an audit event via the control plane (fire-and-forget).
 * The first argument is unused (kept for call-site compatibility with former tx inserts).
 */
export async function writeAudit(
  _tx: unknown,
  input: {
    organizationId: string;
    actor: string;
    action: string;
    target?: string;
    metadata?: Record<string, unknown>;
    traceId?: string;
  },
): Promise<void> {
  const event = toIngestEvent(input);
  void ingestAuditEvents([event]).catch(() => {
    console.info(
      JSON.stringify({
        target: "audit",
        level: "info",
        organization_id: input.organizationId,
        actor_id: input.actor,
        action: input.action,
        target_id: input.target ?? null,
        message: event.message,
        note: "control plane unreachable; audit event logged to stdout only",
      }),
    );
  });
}
