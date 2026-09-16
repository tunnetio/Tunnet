import { cn } from "@tunnet/ui/lib/utils";
import type { ReactNode } from "react";

const KEYWORDS = ["sudo", "curl", "irm", "iex", "docker", "compose"];
const TUNNET_VERBS = [
  "enroll",
  "service",
  "status",
  "ping",
  "dns",
  "route",
  "serve",
  "tunnel",
  "send",
  "ssh",
  "invite",
  "join",
  "create",
  "upgrade-to-managed",
  "update",
  "diag",
  "netcheck",
  "login",
  "firewall",
  "requests",
  "accept",
  "deny",
  "kick",
  "connect",
  "recordings",
  "play",
  "sessions",
  "off",
  "list",
  "add",
  "remove",
  "config",
  "up",
  "down",
  "edge",
  "register",
  "run",
];

function tokenize(line: string, lineId: number) {
  if (line.trim().startsWith("#"))
    return [{ id: `${lineId}-0`, text: line, kind: "cmt" as const }];
  const parts = line.split(/(\s+|"[^"]*"|'[^']*')/g).filter(Boolean);
  return parts.map((p, i) => {
    const kind = /^\s+$/.test(p)
      ? ("plain" as const)
      : /^["'].*["']$/.test(p)
        ? ("str" as const)
        : p.startsWith("--") || (p.startsWith("-") && p.length <= 3)
          ? ("flag" as const)
          : p === "|" || p === "&&" || p === "$" || p === "\\"
            ? ("op" as const)
            : KEYWORDS.includes(p)
              ? ("cmd" as const)
              : p === "tunnet" || p === "tunnet-edge"
                ? ("cmd" as const)
                : TUNNET_VERBS.includes(p)
                  ? ("verb" as const)
                  : ("plain" as const);
    return { id: `${lineId}-${i}`, text: p, kind };
  });
}

export function CodeBlock({
  code,
  className,
  showPrompt = true,
}: {
  code: string;
  className?: string;
  showPrompt?: boolean;
}): ReactNode {
  const lines = code.split("\n");
  return (
    <pre
      className={cn(
        "l1-scroll overflow-x-auto font-mono text-[13px] leading-[1.75] text-[var(--l1-on-bezel)]",
        className,
      )}
    >
      <code className="block">
        {lines.map((line, lineIndex) => {
          const isComment = line.trim().startsWith("#");
          return (
            <div key={line} className="flex">
              <span
                className={cn(
                  "mr-3 select-none",
                  showPrompt && !isComment
                    ? "text-[var(--l1-on-bezel-muted)]"
                    : "opacity-0",
                )}
              >
                $
              </span>
              <span>
                {tokenize(line, lineIndex).map((tok) => {
                  const cls =
                    tok.kind === "cmt"
                      ? "text-[var(--l1-on-bezel-muted)] italic"
                      : tok.kind === "cmd"
                        ? "text-[var(--l1-on-bezel)]"
                        : tok.kind === "verb"
                          ? "text-[var(--l1-on-bezel)]"
                          : tok.kind === "flag"
                            ? "text-[var(--l1-on-bezel-muted)]"
                            : tok.kind === "str"
                              ? "text-[var(--l1-on-bezel)]"
                              : tok.kind === "op"
                                ? "text-[var(--l1-on-bezel-muted)]"
                                : "text-[var(--l1-on-bezel)]";
                  return (
                    <span key={tok.id} className={cls}>
                      {tok.text}
                    </span>
                  );
                })}
              </span>
            </div>
          );
        })}
      </code>
    </pre>
  );
}
