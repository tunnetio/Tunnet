import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  oauthClientAssertion,
  oauthClientResource,
  oauthResource,
} from "@tunnet/db/schema";
import { getTableColumns, getTableName } from "drizzle-orm";

for (const table of [
  oauthResource,
  oauthClientResource,
  oauthClientAssertion,
]) {
  test(`${getTableName(table)} has a required string primary key without a default`, () => {
    expect(getTableColumns(table).id).toMatchObject({
      name: "id",
      dataType: "string",
      primary: true,
      notNull: true,
      hasDefault: false,
    });
  });
}

test("production auth initializes and handles unauthenticated requests", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "tunnet-auth-test-"));
  try {
    const child = Bun.spawn(
      [
        process.execPath,
        "--eval",
        `
          const management = await import("./auth.ts");
          const license = await management.initAuth();
          try {
            const session = await management.auth.handler(new Request("http://localhost:3000/api/auth/get-session"));
            const organizations = await management.auth.handler(new Request("http://localhost:3000/api/auth/organization/list"));
            console.log(JSON.stringify({
              session: { status: session.status, body: await session.json() },
              organizations: { status: organizations.status, body: await organizations.json() },
            }));
          } finally {
            license.stop();
          }
        `,
      ],
      {
        cwd: import.meta.dir,
        env: {
          NODE_ENV: "production",
          DATABASE_URL: "postgres://test:test@127.0.0.1:1/tunnet_auth_test",
          BETTER_AUTH_SECRET: "tunnet-auth-regression-test-secret-32-chars",
          MANAGEMENT_URL: "http://localhost:3000",
          DASHBOARD_URL: "http://localhost:5173",
          TUNNET_STATE_DIR: stateDir,
        },
        stdout: "pipe",
        stderr: "pipe",
        timeout: 10_000,
      },
    );
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect({ exitCode, stderr }).toMatchObject({ exitCode: 0 });
    expect(JSON.parse(stdout.trim().split("\n").at(-1) ?? "")).toMatchObject({
      session: { status: 200, body: null },
      organizations: { status: 401, body: { code: "UNAUTHORIZED" } },
    });
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
}, 15_000);
