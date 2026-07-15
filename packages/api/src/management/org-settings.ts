import { z } from "zod";

import { parseHumanDuration } from "./duration";

export const autoCleanupModeSchema = z.enum(["hard", "soft", "soft_then_hard"]);

const durationStringSchema = z
  .string()
  .trim()
  .min(1)
  .max(100)
  .superRefine((value, ctx) => {
    if (parseHumanDuration(value) === null) {
      ctx.addIssue({
        code: "custom",
        message: "Invalid duration (use e.g. 50s, 30m, 12h, 3d, 1w)",
      });
    }
  });

const autoCleanupFieldsSchema = z.object({
  enabled: z.boolean(),
  inactivityAfter: durationStringSchema.nullable(),
  mode: autoCleanupModeSchema,
  hardDeleteAfter: durationStringSchema.nullable(),
});

export const autoCleanupSettingsSchema = autoCleanupFieldsSchema.superRefine(
  (value, ctx) => {
    if (value.enabled && !value.inactivityAfter) {
      ctx.addIssue({
        code: "custom",
        message: "inactivityAfter is required when auto-cleanup is enabled",
        path: ["inactivityAfter"],
      });
    }
    if (
      value.mode === "soft_then_hard" &&
      value.enabled &&
      !value.hardDeleteAfter
    ) {
      ctx.addIssue({
        code: "custom",
        message: "hardDeleteAfter is required for soft_then_hard mode",
        path: ["hardDeleteAfter"],
      });
    }
  },
);

export const organizationMachinesSettingsSchema = z.object({
  autoCleanup: autoCleanupSettingsSchema,
});

export const organizationSettingsSchema = z.object({
  machines: organizationMachinesSettingsSchema,
});

export const organizationSettingsResponse = z.object({
  organizationId: z.string(),
  settings: organizationSettingsSchema,
});

/** Patch body: fields optional; full validation runs after merge on the server. */
export const patchOrganizationSettingsBody = z
  .object({
    machines: z
      .object({
        autoCleanup: autoCleanupFieldsSchema.partial().optional(),
      })
      .optional(),
  })
  .refine((body) => body.machines?.autoCleanup !== undefined, {
    message: "At least one settings field must be provided",
  });

export const DEFAULT_ORGANIZATION_SETTINGS: OrganizationSettings = {
  machines: {
    autoCleanup: {
      enabled: false,
      inactivityAfter: null,
      mode: "soft",
      hardDeleteAfter: null,
    },
  },
};

export function normalizeOrganizationSettings(
  raw: unknown,
): OrganizationSettings {
  const parsed = organizationSettingsSchema.safeParse(raw);
  if (parsed.success) return parsed.data;

  const partial =
    raw && typeof raw === "object" && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  const machines =
    partial.machines &&
    typeof partial.machines === "object" &&
    !Array.isArray(partial.machines)
      ? (partial.machines as Record<string, unknown>)
      : {};
  const autoCleanup =
    machines.autoCleanup &&
    typeof machines.autoCleanup === "object" &&
    !Array.isArray(machines.autoCleanup)
      ? (machines.autoCleanup as Record<string, unknown>)
      : {};

  const merged = {
    machines: {
      autoCleanup: {
        ...DEFAULT_ORGANIZATION_SETTINGS.machines.autoCleanup,
        ...autoCleanup,
      },
    },
  };

  const result = organizationSettingsSchema.safeParse(merged);
  return result.success ? result.data : DEFAULT_ORGANIZATION_SETTINGS;
}

export type AutoCleanupMode = z.infer<typeof autoCleanupModeSchema>;
export type AutoCleanupSettings = z.infer<typeof autoCleanupSettingsSchema>;
export type OrganizationMachinesSettings = z.infer<
  typeof organizationMachinesSettingsSchema
>;
export type OrganizationSettings = z.infer<typeof organizationSettingsSchema>;
export type OrganizationSettingsResponse = z.infer<
  typeof organizationSettingsResponse
>;
export type PatchOrganizationSettingsBody = z.infer<
  typeof patchOrganizationSettingsBody
>;
