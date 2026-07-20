import { type Database, schema } from "@tunnet/db";
import { and, eq, inArray } from "drizzle-orm";

import { db } from "./db";

type DbConn = Database | Parameters<Parameters<Database["transaction"]>[0]>[0];

export type TagActor = {
  userId: string | null;
  email: string | null;
  /** Org owner or admin - always allowed to assign any tag. */
  isOrgAdmin: boolean;
  /** Device endpoint requesting self-tag (CLI / config). */
  endpointId: string | null;
};

export function normalizeTagName(name: string): string {
  return name.trim().toLowerCase().replace(/^tag:/, "");
}

export function defaultOwnerForUser(userId: string): string {
  return `user:${userId}`;
}

/**
 * Resolve whether `actor` may assign/remove `tagName` for the org.
 * Org admins/owners always may. Otherwise owners entries are checked:
 * - `user:<id>` or `user:<email>`
 * - `tag:<name>` - actor's device must hold that tag (or user has assign permission and owns via hierarchy)
 * - `autogroup:admin` - org admin (already covered by isOrgAdmin)
 */
export async function canAssignTag(
  organizationId: string,
  tagName: string,
  actor: TagActor,
  conn: DbConn = db,
): Promise<boolean> {
  if (actor.isOrgAdmin) return true;

  const name = normalizeTagName(tagName);
  const def = await conn.query.tagDefinitions.findFirst({
    where: and(
      eq(schema.tagDefinitions.organizationId, organizationId),
      eq(schema.tagDefinitions.name, name),
    ),
  });
  if (!def) return false;

  return actorMatchesOwners(def.owners, actor, organizationId, conn, new Set());
}

async function actorMatchesOwners(
  owners: string[],
  actor: TagActor,
  organizationId: string,
  conn: DbConn,
  visited: Set<string>,
): Promise<boolean> {
  for (const owner of owners) {
    if (owner === "autogroup:admin") {
      if (actor.isOrgAdmin) return true;
      continue;
    }
    if (owner.startsWith("user:")) {
      const identity = owner.slice(5);
      if (actor.userId && identity === actor.userId) return true;
      if (actor.email && identity.toLowerCase() === actor.email.toLowerCase()) {
        return true;
      }
      continue;
    }
    if (owner.startsWith("tag:")) {
      const parentTag = normalizeTagName(owner.slice(4));
      if (visited.has(parentTag)) continue;
      visited.add(parentTag);

      if (actor.endpointId) {
        const held = await conn.query.deviceTags.findFirst({
          where: and(
            eq(schema.deviceTags.endpointId, actor.endpointId),
            eq(schema.deviceTags.tag, parentTag),
          ),
        });
        if (held) return true;
      }

      // Hierarchical: if the actor can assign the parent tag, they can assign
      // tags owned by that parent (Tailscale-style tagOwners).
      const parentDef = await conn.query.tagDefinitions.findFirst({
        where: and(
          eq(schema.tagDefinitions.organizationId, organizationId),
          eq(schema.tagDefinitions.name, parentTag),
        ),
      });
      if (
        parentDef &&
        (await actorMatchesOwners(
          parentDef.owners,
          actor,
          organizationId,
          conn,
          visited,
        ))
      ) {
        return true;
      }
    }
  }
  return false;
}

export async function assertCanAssignTags(
  organizationId: string,
  tagNames: string[],
  actor: TagActor,
  conn: DbConn = db,
): Promise<{ ok: true } | { ok: false; tag: string }> {
  const unique = [...new Set(tagNames.map(normalizeTagName).filter(Boolean))];
  for (const tag of unique) {
    const allowed = await canAssignTag(organizationId, tag, actor, conn);
    if (!allowed) return { ok: false, tag };
  }
  return { ok: true };
}

export async function ensureTagDefinitionsExist(
  organizationId: string,
  tagNames: string[],
  conn: DbConn = db,
): Promise<string[]> {
  const unique = [...new Set(tagNames.map(normalizeTagName).filter(Boolean))];
  if (unique.length === 0) return [];

  const existing = await conn.query.tagDefinitions.findMany({
    where: and(
      eq(schema.tagDefinitions.organizationId, organizationId),
      inArray(schema.tagDefinitions.name, unique),
    ),
  });
  const found = new Set(existing.map((t) => t.name));
  return unique.filter((name) => !found.has(name));
}

export async function listDeviceTags(
  endpointId: string,
  conn: DbConn = db,
): Promise<string[]> {
  const rows = await conn.query.deviceTags.findMany({
    where: eq(schema.deviceTags.endpointId, endpointId),
  });
  return rows.map((r) => r.tag).sort();
}

export async function listDeviceTagsForEndpoints(
  endpointIds: string[],
  conn: DbConn = db,
): Promise<Map<string, string[]>> {
  const map = new Map<string, string[]>();
  if (endpointIds.length === 0) return map;
  const rows = await conn.query.deviceTags.findMany({
    where: inArray(schema.deviceTags.endpointId, endpointIds),
  });
  for (const row of rows) {
    const list = map.get(row.endpointId) ?? [];
    list.push(row.tag);
    map.set(row.endpointId, list);
  }
  for (const [id, tags] of map) {
    map.set(id, tags.sort());
  }
  return map;
}

export async function applyDeviceTagChanges(
  endpointId: string,
  add: string[],
  remove: string[],
  conn: DbConn = db,
): Promise<string[]> {
  const toAdd = [...new Set(add.map(normalizeTagName).filter(Boolean))];
  const toRemove = [...new Set(remove.map(normalizeTagName).filter(Boolean))];

  for (const tag of toRemove) {
    await conn
      .delete(schema.deviceTags)
      .where(
        and(
          eq(schema.deviceTags.endpointId, endpointId),
          eq(schema.deviceTags.tag, tag),
        ),
      );
  }
  for (const tag of toAdd) {
    await conn
      .insert(schema.deviceTags)
      .values({ endpointId, tag })
      .onConflictDoNothing();
  }
  return listDeviceTags(endpointId, conn);
}

export async function replaceDeviceTags(
  endpointId: string,
  tags: string[],
  conn: DbConn = db,
): Promise<string[]> {
  const next = [...new Set(tags.map(normalizeTagName).filter(Boolean))];
  await conn
    .delete(schema.deviceTags)
    .where(eq(schema.deviceTags.endpointId, endpointId));
  for (const tag of next) {
    await conn.insert(schema.deviceTags).values({ endpointId, tag });
  }
  return next.sort();
}
