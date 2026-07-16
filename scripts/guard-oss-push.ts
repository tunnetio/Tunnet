import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

function normalizeUrl(url: string): string {
  return url.replace(/\.git$/i, "").toLowerCase();
}

function isPrivateRemote(remoteName: string, remoteUrl: string): boolean {
  if (remoteName === "private") return true;
  const normalized = normalizeUrl(remoteUrl);
  return normalized.includes("tunnet-cloud");
}

function isOssRemote(remoteName: string, remoteUrl: string): boolean {
  if (isPrivateRemote(remoteName, remoteUrl)) return false;
  const normalized = normalizeUrl(remoteUrl);
  return (
    remoteName === "origin" ||
    remoteName === "public" ||
    normalized.endsWith("/tunnet") ||
    normalized.includes("github.com/tunnetio/tunnet")
  );
}

type RefUpdate = {
  localRef: string;
  localSha: string;
  remoteRef: string;
  remoteSha: string;
};

const ZERO = "0000000000000000000000000000000000000000";

function parseRefUpdates(stdin: string): RefUpdate[] {
  return stdin
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [localRef, localSha, remoteRef, remoteSha] = line.split(/\s+/);
      return {
        localRef: localRef ?? "",
        localSha: localSha ?? "",
        remoteRef: remoteRef ?? "",
        remoteSha: remoteSha ?? "",
      };
    })
    .filter((u) => u.localRef && u.remoteRef);
}

async function git(
  args: string[],
  opts: { cwd?: string; env?: Record<string, string> } = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["git", ...args], {
    cwd: opts.cwd,
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, ...opts.env },
  });
  const stdout = await new Response(proc.stdout).text();
  const stderr = await new Response(proc.stderr).text();
  const code = await proc.exited;
  return { code, stdout: stdout.trim(), stderr: stderr.trim() };
}

async function getRemoteUrl(name: string): Promise<string> {
  const { stdout, code } = await git(["remote", "get-url", name]);
  if (code !== 0) throw new Error(`remote ${name} not found`);
  return stdout;
}

async function headHasCloud(): Promise<boolean> {
  const { stdout } = await git(["ls-tree", "-r", "--name-only", "HEAD"]);
  return stdout
    .split("\n")
    .some((line) => line === "cloud" || line.startsWith("cloud/"));
}

async function publishFiltered(remoteName: string): Promise<void> {
  console.log(
    `OSS remote detected (${remoteName}). Publishing filtered tree (excluding cloud/)…`,
  );
  const push = Bun.spawn(
    ["bun", "run", "scripts/push-oss.ts", `--remote=${remoteName}`, "--force"],
    { stdout: "inherit", stderr: "inherit" },
  );
  const code = await push.exited;
  if (code !== 0) process.exit(code);
}

/** Push tags at the filtered OSS tip via a shallow clone (object exists there). */
async function pushTagsOnOssTip(
  remoteName: string,
  tags: RefUpdate[],
): Promise<void> {
  const remoteUrl = await getRemoteUrl(remoteName);
  const internal = { TUNNET_OSS_INTERNAL_PUSH: "1" };
  const parent = await mkdtemp(join(tmpdir(), "tunnet-oss-tag-"));
  const tmp = join(parent, "repo");

  try {
    const clone = await git([
      "clone",
      "--depth",
      "1",
      "--branch",
      "main",
      remoteUrl,
      tmp,
    ]);
    if (clone.code !== 0) {
      console.error(clone.stderr || "Failed to clone OSS remote for tagging");
      process.exit(clone.code || 1);
    }

    const { stdout: clonedSha, code: tipCode } = await git(
      ["rev-parse", "HEAD"],
      { cwd: tmp },
    );
    if (tipCode !== 0 || !clonedSha) {
      console.error("Failed to resolve OSS clone HEAD");
      process.exit(1);
    }

    for (const tag of tags) {
      const name = tag.remoteRef.replace(/^refs\/tags\//, "");

      if (tag.localSha === ZERO) {
        const del = await git(["push", "origin", `:${tag.remoteRef}`], {
          cwd: tmp,
          env: internal,
        });
        if (del.code !== 0) {
          console.error(del.stderr || `Failed to delete ${tag.remoteRef}`);
          process.exit(del.code);
        }
        console.log(`Deleted ${tag.remoteRef} on ${remoteName}`);
        continue;
      }

      const tagged = await git(["tag", "-f", name], { cwd: tmp });
      if (tagged.code !== 0) {
        console.error(tagged.stderr || `Failed to create tag ${name}`);
        process.exit(tagged.code);
      }

      const pushed = await git(["push", "-f", "origin", `refs/tags/${name}`], {
        cwd: tmp,
        env: internal,
      });
      if (pushed.code !== 0) {
        console.error(pushed.stderr || `Failed to push tag ${name}`);
        process.exit(pushed.code);
      }
      console.log(
        `Pushed tag ${name} → ${clonedSha.slice(0, 7)} (OSS tip, cloud/ excluded)`,
      );
    }
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
}

const remoteName = process.argv[2] ?? "";
const stdin = await Bun.stdin.text();
const updates = parseRefUpdates(stdin);

// Internal remapped pushes (tags / filtered tip) must not re-enter this guard.
if (process.env.TUNNET_OSS_INTERNAL_PUSH === "1") {
  process.exit(0);
}

if (!remoteName) {
  process.exit(0);
}

const url = await getRemoteUrl(remoteName).catch(() => "");

// Full-tree private remote: allow native push (Sync / sync:private).
if (isPrivateRemote(remoteName, url)) {
  process.exit(0);
}

if (!isOssRemote(remoteName, url)) {
  process.exit(0);
}

if (!(await headHasCloud())) {
  process.exit(0);
}

const tagUpdates = updates.filter((u) => u.remoteRef.startsWith("refs/tags/"));
const branchUpdates = updates.filter(
  (u) =>
    u.remoteRef.startsWith("refs/heads/") ||
    u.remoteRef.startsWith("refs/for/"),
);

// Tag-only push: point tags at current OSS main tip (do not re-publish main).
if (tagUpdates.length > 0 && branchUpdates.length === 0) {
  await pushTagsOnOssTip(remoteName, tagUpdates);
  console.error(
    [
      "",
      "Published tag(s) on the filtered OSS tip (cloud/ excluded).",
      "Native tag push was stopped so the full-tree commit is not uploaded.",
      "",
    ].join("\n"),
  );
  process.exit(1);
}

// Branch push (optionally with tags): publish filtered tree, remap any tags.
await publishFiltered(remoteName);
if (tagUpdates.length > 0) {
  await pushTagsOnOssTip(remoteName, tagUpdates);
}

console.error(
  [
    "",
    "Published filtered tree to OSS (cloud/ excluded).",
    tagUpdates.length > 0
      ? "Tag(s) were pointed at the filtered OSS tip."
      : null,
    "Native git push was stopped on purpose so cloud/ is not uploaded.",
    "To update the private full tree:  bun run sync:private",
    "",
  ]
    .filter(Boolean)
    .join("\n"),
);
process.exit(1);
