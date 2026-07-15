import { deviceLabelsSchema } from "@tuntun/api/management";

export function normalizeDeviceLabels(value: unknown): Record<string, string> {
  const parsed = deviceLabelsSchema.safeParse(value);
  return parsed.success ? parsed.data : {};
}

export function mergeDeviceLabels(
  existing: Record<string, string>,
  patch: Record<string, string | null>,
): Record<string, string> {
  const next = { ...existing };
  for (const [key, value] of Object.entries(patch)) {
    if (value === null || value === "") {
      delete next[key];
    } else {
      next[key] = value;
    }
  }
  return next;
}
