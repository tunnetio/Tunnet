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

async function getRemoteUrl(name: string): Promise<string> {
  const proc = Bun.spawn(["git", "remote", "get-url", name], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const out = (await new Response(proc.stdout).text()).trim();
  await proc.exited;
  return out;
}

async function headHasCloud(): Promise<boolean> {
  const proc = Bun.spawn(["git", "ls-tree", "-r", "--name-only", "HEAD"], {
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
await Bun.stdin.text();

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

console.log(
  `OSS remote detected (${remoteName}). Publishing filtered tree (excluding cloud/)…`,
);

const push = Bun.spawn(
  ["bun", "run", "scripts/push-oss.ts", `--remote=${remoteName}`, "--force"],
  { stdout: "inherit", stderr: "inherit" },
);
const code = await push.exited;
if (code !== 0) {
  process.exit(code);
}

console.error(
  [
    "",
    "Published filtered tree to OSS (cloud/ excluded).",
    "Native git push was stopped on purpose so cloud/ is not uploaded.",
    "To update the private full tree:  bun run sync:private",
    "",
  ].join("\n"),
);
process.exit(1);
