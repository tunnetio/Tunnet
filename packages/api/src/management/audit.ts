import { z } from "zod";

export const auditActorSchema = z.object({
  actorType: z.string(),
  actorId: z.string(),
  displayName: z.string().nullable(),
  email: z.string().nullable(),
  ipAddress: z.string().nullable(),
});

export const auditTargetSchema = z.object({
  targetType: z.string(),
  targetId: z.string(),
  displayName: z.string().nullable(),
});

export const auditEventSchema = z.object({
  organizationId: z.string(),
  sequenceNumber: z.number().int(),
  categoryUid: z.number().int(),
  classUid: z.number().int(),
  activityId: z.number().int(),
  typeUid: z.number().int(),
  severityId: z.number().int(),
  statusId: z.number().int(),
  time: z.string(),
  message: z.string(),
  actor: auditActorSchema,
  target: auditTargetSchema,
  networkId: z.string().uuid().nullable(),
  groupId: z.string().nullable(),
  diff: z
    .object({
      before: z.record(z.string(), z.unknown()),
      after: z.record(z.string(), z.unknown()),
    })
    .nullable(),
  metadata: z.record(z.string(), z.unknown()),
  traceId: z.string().nullable(),
  entryHash: z.string(),
});

export const auditListResponse = z.object({
  entries: z.array(auditEventSchema),
  nextCursor: z.number().int().nullable(),
});

export const auditQuerySchema = z.object({
  from: z.string().optional(),
  to: z.string().optional(),
  classUid: z.coerce.number().int().optional(),
  actorId: z.string().optional(),
  targetType: z.string().optional(),
  targetId: z.string().optional(),
  severityId: z.coerce.number().int().optional(),
  search: z.string().optional(),
  cursor: z.coerce.number().int().optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(50),
});

export type AuditEvent = z.infer<typeof auditEventSchema>;
export type AuditEntry = AuditEvent;
