/**
 * Refuse pushes to the public remote when commits include `cloud/` paths.
 *
 * Invoked by lefthook pre-push with: bun run scripts/guard-public-push.ts {remote}
 * Git pre-push protocol on stdin: <local_ref> <local_sha> <remote_ref> <remote_sha>
 */

function isPublicRemote(remoteName: string, remoteUrl: string): boolean {
  if (remoteName === "public") return true;
  if (remoteName === "private" || remoteName === "origin") return false;
  const normalized = remoteUrl.replace(/\.git$/i, "").toLowerCase();
  if (normalized.includes("tuntun-cloud")) return false;
  return (
    normalized.endsWith("orielhaim/tuntun") ||
    normalized.includes("github.com/orielhaim/tuntun")
  );
}

async function getRemoteUrl(name: string): Promise<string> {
  const proc = Bun.spawn(["git", "remote", "get-url", name], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const out = (await new Response(proc.stdout).text()).trim();
  await proc.exited;
  return out;
}

async function rangeHasCloud(
  localSha: string,
  remoteSha: string,
): Promise<boolean> {
  const zero = "0".repeat(40);
  if (localSha === zero) return false;

  const args =
    remoteSha === zero
      ? ["diff-tree", "--no-commit-id", "--name-only", "-r", localSha]
      : ["diff", "--name-only", `${remoteSha}..${localSha}`];

  const proc = Bun.spawn(["git", ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const out = await new Response(proc.stdout).text();
  await proc.exited;
  return out
    .split("\n")
    .some((line) => line === "cloud" || line.startsWith("cloud/"));
}

const remoteName = process.argv[2] ?? "";
const stdin = await Bun.stdin.text();
const lines = stdin
  .trim()
  .split("\n")
  .map((l) => l.trim())
  .filter(Boolean);

if (!remoteName) {
  process.exit(0);
}

const url = await getRemoteUrl(remoteName).catch(() => "");
if (!isPublicRemote(remoteName, url)) {
  process.exit(0);
}

for (const line of lines) {
  const parts = line.split(/\s+/);
  if (parts.length < 4) continue;
  const localSha = parts[1];
  const remoteSha = parts[3];
  if (!localSha || !remoteSha) continue;
  if (await rangeHasCloud(localSha, remoteSha)) {
    console.error(
      [
        "",
        "Refusing push to public remote: commits include cloud/ paths.",
        "SaaS-only code under cloud/ must only go to the private remote.",
        "Use:  git push private",
        "Or:   bun run sync:public",
        "",
      ].join("\n"),
    );
    process.exit(1);
  }
}

process.exit(0);
