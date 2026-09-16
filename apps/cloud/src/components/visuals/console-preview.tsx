import { cn } from "@tunnet/ui/lib/utils";
import type { ReactNode } from "react";

export type ConsoleKind = "mesh" | "serve" | "tunnel" | "ssh" | "policy";

const MACHINES = [
  { name: "ori-mbp", role: "laptop", path: "direct" },
  { name: "api-west", role: "server", path: "direct" },
  { name: "db-prod", role: "postgres", path: "relay" },
  { name: "ci-runner", role: "github", path: "direct" },
  { name: "edge-sfo", role: "edge", path: "direct" },
] as const;

export function ConsolePreview({ kind }: { kind: ConsoleKind }): ReactNode {
  return (
    <div className="flex h-full min-h-[22rem] overflow-hidden bg-[#f6f4ef] text-[#1c1d1a] dark:bg-[#141518] dark:text-[#eceae4]">
      <aside className="hidden w-40 shrink-0 flex-col gap-1 border-r border-black/8 p-3 text-[11px] sm:flex dark:border-white/8">
        <p className="mb-2 px-2 text-[10px] font-medium tracking-[0.14em] text-black/40 uppercase dark:text-white/40">
          acme
        </p>
        {["Machines", "Tunnels", "SSH", "Policy", "Audit"].map((item, i) => (
          <span
            key={item}
            className={cn(
              "rounded-md px-2 py-1.5",
              i ===
                (kind === "tunnel"
                  ? 1
                  : kind === "ssh"
                    ? 2
                    : kind === "policy"
                      ? 3
                      : 0)
                ? "bg-black/8 font-medium dark:bg-white/10"
                : "text-black/45 dark:text-white/40",
            )}
          >
            {item}
          </span>
        ))}
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center justify-between border-b border-black/8 px-4 py-2.5 text-[11px] dark:border-white/8">
          <span className="font-medium">
            {kind === "serve"
              ? "Internal services"
              : kind === "tunnel"
                ? "Public tunnels"
                : kind === "ssh"
                  ? "Sessions"
                  : kind === "policy"
                    ? "Policy"
                    : "Machines"}
          </span>
          <span className="rounded-full bg-black/6 px-2 py-0.5 font-mono text-[10px] dark:bg-white/8">
            {kind === "tunnel" ? "demo-api.tunnet.io" : "acme.tunnet"}
          </span>
        </div>
        <div className="flex-1 overflow-hidden p-3">
          {kind === "policy" ? (
            <pre className="h-full overflow-auto rounded-lg bg-black/[0.04] p-3 font-mono text-[10px] leading-relaxed text-black/70 dark:bg-white/5 dark:text-white/70">
              {`group "eng" { users = ["ori", "ada"] }

ssh {
  "eng" = ["tag:prod"]
}

acl {
  "eng" -> "tag:prod:443"
}`}
            </pre>
          ) : (
            <ul className="flex flex-col gap-1.5">
              {MACHINES.map((m) => (
                <li
                  key={m.name}
                  className="flex items-center justify-between rounded-lg border border-black/6 bg-white/70 px-3 py-2 dark:border-white/8 dark:bg-white/4"
                >
                  <span className="flex items-center gap-2">
                    <span className="size-1.5 rounded-full bg-emerald-600" />
                    <span className="font-mono text-[11px]">{m.name}</span>
                    <span className="text-[10px] text-black/40 dark:text-white/40">
                      {m.role}
                    </span>
                  </span>
                  <span className="font-mono text-[10px] text-black/40 dark:text-white/40">
                    {kind === "ssh"
                      ? "tunnet ssh"
                      : kind === "serve"
                        ? `${m.name}.mesh`
                        : kind === "tunnel"
                          ? "https"
                          : m.path}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
