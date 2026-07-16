/**
 * Publish a filtered mirror of HEAD to the OSS remote (no cloud/).
 * Prefer `git push origin` which runs this via the pre-push hook.
 *
 * Usage:
 *   bun run scripts/push-oss.ts
 *   bun run scripts/push-oss.ts --force
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const force = process.argv.includes("--force");
const remoteArg = process.argv.find((a) => a.startsWith("--remote="));
const remote = remoteArg?.slice("--remote=".length) || "origin";
const branch = "main";

async function git(
  args: string[],
  opts: { cwd?: string; allowFail?: boolean } = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["git", ...args], {
    cwd: opts.cwd,
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await new Response(proc.stdout).text();
  const stderr = await new Response(proc.stderr).text();
  const code = await proc.exited;
  if (code !== 0 && !opts.allowFail) {
    throw new Error(
      `git ${args.join(" ")} failed (${code}): ${stderr || stdout}`,
    );
  }
  return { code, stdout: stdout.trim(), stderr: stderr.trim() };
}

async function remoteTipHasCloud(cwd: string): Promise<boolean> {
  const { code, stdout } = await git(["ls-tree", "-r", "--name-only", "HEAD"], {
    cwd,
    allowFail: true,
  });
  if (code !== 0) return false;
  return stdout
    .split("\n")
    .some((line) => line === "cloud" || line.startsWith("cloud/"));
}

async function main() {
  const { stdout: remoteUrl } = await git(["remote", "get-url", remote]);
  const { stdout: headFull } = await git(["rev-parse", "HEAD"]);
  const { stdout: subject } = await git(["log", "-1", "--format=%s", "HEAD"]);
  const { stdout: body } = await git(["log", "-1", "--format=%b", "HEAD"]);
  const { stdout: repoRoot } = await git(["rev-parse", "--show-toplevel"]);

  const message = body ? `${subject}\n\n${body}`.trim() : subject;

  const tmp = await mkdtemp(join(tmpdir(), "tunnet-push-oss-"));
  console.log(`Publishing filtered tree to ${remote} (${remoteUrl})`);
  console.log(`Source: ${headFull}`);

  try {
    const clone = await git(
      ["clone", "--depth", "50", "--branch", branch, remoteUrl, tmp],
      { allowFail: true },
    );

    let mustForce = force;
    if (clone.code !== 0) {
      console.log("OSS branch missing or empty; initializing fresh clone...");
      await git(["init", "-b", branch], { cwd: tmp });
      await git(["remote", "add", "origin", remoteUrl], { cwd: tmp });
      mustForce = true;
    } else if (await remoteTipHasCloud(tmp)) {
      console.log(
        "Remote tip contains cloud/ — force-publishing a clean filtered tip.",
      );
      mustForce = true;
    }

    await git(["rm", "-rf", "--ignore-unmatch", "."], {
      cwd: tmp,
      allowFail: true,
    });

    const archive = Bun.spawn(
      ["git", "-C", repoRoot, "archive", "--format=tar", "HEAD"],
      { stdout: "pipe", stderr: "pipe" },
    );
    const extract = Bun.spawn(["tar", "-xf", "-", "-C", tmp], {
      stdin: archive.stdout,
      stdout: "pipe",
      stderr: "pipe",
    });
    const archiveCode = await archive.exited;
    const extractCode = await extract.exited;
    if (archiveCode !== 0 || extractCode !== 0) {
      const err = await new Response(extract.stderr).text();
      const aerr = await new Response(archive.stderr).text();
      throw new Error(
        `Failed to export archive: ${aerr || err || `codes ${archiveCode}/${extractCode}`}`,
      );
    }

    await rm(join(tmp, "cloud"), { recursive: true, force: true });

    await git(["add", "-A"], { cwd: tmp });
    const { stdout: porcelain } = await git(["status", "--porcelain"], {
      cwd: tmp,
    });
    if (!porcelain) {
      console.log("OSS remote already matches filtered tree; nothing to do.");
      return;
    }

    await git(["commit", "-m", message], { cwd: tmp });

    const pushArgs = ["push", "origin", `HEAD:${branch}`];
    if (mustForce) pushArgs.push("--force");
    await git(pushArgs, { cwd: tmp });
    console.log(`Pushed filtered tree to ${remote}/${branch}`);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

await main();
