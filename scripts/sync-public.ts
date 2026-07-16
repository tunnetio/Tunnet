/**
 * Publish a filtered mirror of the current HEAD to the `public` remote,
 * excluding the `cloud/` directory.
 *
 * Usage:
 *   bun run scripts/sync-public.ts
 *   bun run scripts/sync-public.ts --force   # only when public history must be rewritten
 */

import { cp, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const force = process.argv.includes("--force");
const remote = "public";
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

async function main() {
  const { stdout: remoteUrl } = await git(["remote", "get-url", remote]);
  const { stdout: headSha } = await git(["rev-parse", "--short", "HEAD"]);
  const { stdout: headFull } = await git(["rev-parse", "HEAD"]);
  const { stdout: repoRoot } = await git(["rev-parse", "--show-toplevel"]);

  const tmp = await mkdtemp(join(tmpdir(), "tuntun-sync-public-"));
  console.log(`Syncing filtered tree to ${remote} (${remoteUrl})`);
  console.log(`Source: ${headFull}`);

  try {
    const clone = await git(
      ["clone", "--depth", "1", "--branch", branch, remoteUrl, tmp],
      { allowFail: true },
    );

    if (clone.code !== 0) {
      console.log(
        "Public branch missing or empty; initializing fresh clone...",
      );
      await git(["init", "-b", branch], { cwd: tmp });
      await git(["remote", "add", "origin", remoteUrl], { cwd: tmp });
    }

    // Clear tracked files in the public clone
    await git(["rm", "-rf", "--ignore-unmatch", "."], {
      cwd: tmp,
      allowFail: true,
    });

    // Export HEAD into a staging dir, then copy everything except cloud/
    const exportDir = await mkdtemp(join(tmpdir(), "tuntun-export-"));
    try {
      await git(
        ["--work-tree", exportDir, "checkout", "-f", "HEAD", "--", "."],
        { cwd: repoRoot },
      );

      const entries = await readdir(exportDir);
      for (const name of entries) {
        if (name === "cloud") continue;
        await cp(join(exportDir, name), join(tmp, name), {
          recursive: true,
          force: true,
        });
      }
    } finally {
      await rm(exportDir, { recursive: true, force: true });
    }

    await rm(join(tmp, "cloud"), { recursive: true, force: true });

    await git(["add", "-A"], { cwd: tmp });
    const { stdout: porcelain } = await git(["status", "--porcelain"], {
      cwd: tmp,
    });
    if (!porcelain) {
      console.log(
        "Public remote already matches filtered tree; nothing to do.",
      );
      return;
    }

    await git(
      ["commit", "-m", `sync: mirror from private@${headSha} (without cloud/)`],
      { cwd: tmp },
    );

    const pushArgs = ["push", "origin", `HEAD:${branch}`];
    if (force) pushArgs.push("--force");
    await git(pushArgs, { cwd: tmp });
    console.log(`Pushed filtered mirror to ${remote}/${branch}`);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

await main();
