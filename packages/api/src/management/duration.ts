import parse from "parse-duration";
import { z } from "zod";

/** Parse a human duration string (e.g. `3d`, `12h`, `30m`, `50s`) to seconds. */
export function parseHumanDuration(raw: string): number | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const secs = parse(trimmed, "s");
  if (secs === null || !Number.isFinite(secs) || secs <= 0) return null;
  return Math.floor(secs);
}

/** Convert seconds to a PostgreSQL interval literal input. */
export function secondsToPgInterval(seconds: number): string {
  return `${Math.floor(seconds)} seconds`;
}

/**
 * Parse PostgreSQL `interval` text to seconds.
 * Handles verbose forms (`50 seconds`, `7 days`) and time forms (`00:00:50`, `3 04:05:06`).
 */
export function pgIntervalToSeconds(value: string): number | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  const fromTime = parsePostgresIntervalTime(trimmed);
  if (fromTime !== null) return fromTime;

  const secs = parse(trimmed, "s");
  if (secs !== null && Number.isFinite(secs) && secs > 0) {
    const whole = Math.floor(secs);
    if (whole > 0) return whole;
  }

  const fromCompact = parseCompactDuration(trimmed);
  if (fromCompact !== null) return fromCompact;

  return null;
}

/** Compact duration label (e.g. `50s`, `1m30s`, `7d`, `1w2d`). */
export function formatDurationCompact(seconds: number): string {
  const secs = Math.floor(seconds);
  if (secs <= 0) return "0s";

  const parts: string[] = [];
  let rem = secs;

  const weeks = Math.floor(rem / 604_800);
  if (weeks > 0) {
    parts.push(`${weeks}w`);
    rem %= 604_800;
  }
  const days = Math.floor(rem / 86_400);
  if (days > 0) {
    parts.push(`${days}d`);
    rem %= 86_400;
  }
  const hours = Math.floor(rem / 3600);
  if (hours > 0) {
    parts.push(`${hours}h`);
    rem %= 3600;
  }
  const minutes = Math.floor(rem / 60);
  if (minutes > 0) {
    parts.push(`${minutes}m`);
    rem %= 60;
  }
  if (rem > 0) parts.push(`${rem}s`);

  return parts.join("");
}

/** Longer human label (e.g. `50 seconds`, `1 minute, 30 seconds`). */
export function formatDurationLong(seconds: number): string {
  const secs = Math.floor(seconds);
  if (secs <= 0) return "0 seconds";

  const parts: string[] = [];
  let rem = secs;

  const weeks = Math.floor(rem / 604_800);
  if (weeks > 0) {
    parts.push(`${weeks} week${weeks === 1 ? "" : "s"}`);
    rem %= 604_800;
  }
  const days = Math.floor(rem / 86_400);
  if (days > 0) {
    parts.push(`${days} day${days === 1 ? "" : "s"}`);
    rem %= 86_400;
  }
  const hours = Math.floor(rem / 3600);
  if (hours > 0) {
    parts.push(`${hours} hour${hours === 1 ? "" : "s"}`);
    rem %= 3600;
  }
  const minutes = Math.floor(rem / 60);
  if (minutes > 0) {
    parts.push(`${minutes} minute${minutes === 1 ? "" : "s"}`);
    rem %= 60;
  }
  if (rem > 0) {
    parts.push(`${rem} second${rem === 1 ? "" : "s"}`);
  }

  return parts.join(", ");
}

export function expiresAtFromDuration(
  duration: string,
  from: Date = new Date(),
): Date {
  const secs = parseHumanDuration(duration);
  if (secs === null) {
    throw new Error("Invalid duration");
  }
  return new Date(from.getTime() + secs * 1000);
}

export const expiresInInputSchema = z
  .union([z.string().trim().min(1).max(100), z.null()])
  .superRefine((value, ctx) => {
    if (value === null) return;
    if (value.toLowerCase() === "never") return;
    if (parseHumanDuration(value) === null) {
      ctx.addIssue({
        code: "custom",
        message: "Invalid duration (use e.g. 50s, 30m, 12h, 3d, 1w, or never)",
      });
    }
  });

function parsePostgresIntervalTime(value: string): number | null {
  const dayTime = value.match(
    /^(?:(\d+)\s+)?(\d+):(\d{1,2}):(\d{1,2})(?:\.\d+)?$/,
  );
  if (dayTime) {
    const days = dayTime[1] ? Number(dayTime[1]) : 0;
    const hours = Number(dayTime[2]);
    const minutes = Number(dayTime[3]);
    const seconds = Number(dayTime[4]);
    if (
      [days, hours, minutes, seconds].some((n) => !Number.isFinite(n) || n < 0)
    ) {
      return null;
    }
    const total = days * 86_400 + hours * 3600 + minutes * 60 + seconds;
    return total > 0 ? total : null;
  }

  const secondsOnly = value.match(/^(\d+)\s+seconds?$/i);
  if (secondsOnly) {
    const n = Number(secondsOnly[1]);
    return n > 0 ? n : null;
  }

  return null;
}

function parseCompactDuration(value: string): number | null {
  const re = /(\d+)(w|d|h|m|s)/gi;
  let total = 0;
  let matched = false;

  for (const match of value.matchAll(re)) {
    matched = true;
    const amount = Number(match[1]);
    const unit = match[2]?.toLowerCase();
    const multiplier =
      unit === "w"
        ? 604_800
        : unit === "d"
          ? 86_400
          : unit === "h"
            ? 3600
            : unit === "m"
              ? 60
              : unit === "s"
                ? 1
                : 0;
    if (multiplier === 0 || amount <= 0) return null;
    total += amount * multiplier;
  }

  return matched && total > 0 ? total : null;
}
