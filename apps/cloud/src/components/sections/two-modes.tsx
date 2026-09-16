import { cn } from "@tunnet/ui/lib/utils";
import { type ReactNode, useState } from "react";
import { FaGithub } from "react-icons/fa6";
import { TerminalDemo } from "#/components/shared/terminal-demo";

const GITHUB_URL = "https://github.com/tunnetio/Tunnet";
const APP_URL = "https://app.tunnet.io";

const MODES = {
  managed: {
    id: "managed" as const,
    title: "Managed",
    body: "SSO, a dashboard, and audit for the team. Hosted by us or you. This is how most companies run Tunnet.",
    code: `curl -fsSL https://get.tunnet.io | sh
sudo tunnet enroll --control-url https://app.tunnet.io --token $TOKEN
tunnet status --peers`,
  },
  direct: {
    id: "direct" as const,
    title: "Direct",
    body: "Open source. A private mesh with a passphrase. No account, no bill. Built for a personal fleet.",
    code: `sudo tunnet create --name my-net --secret "a-strong-passphrase"
tunnet invite --name my-net
sudo tunnet join <INVITE_CODE>`,
  },
};

export function TwoModesSection(): ReactNode {
  const [mode, setMode] = useState<"managed" | "direct">("managed");
  const current = MODES[mode];

  return (
    <section id="modes" className="px-4 py-20 sm:px-6 sm:py-28">
      <div className="mx-auto max-w-[1120px]">
        <h2 className="l1-h-section max-w-[18ch] text-[var(--l1-fg)]">
          Same open-source agent. Two ways to run it.
        </h2>
        <p className="l1-lead mt-4 max-w-[52ch]">
          Managed is the team product: SSO, audit, and a dashboard. Direct is a
          private mesh with nothing to host. Both are free to start.
        </p>

        <div className="mt-10 grid gap-3 sm:grid-cols-2">
          {(Object.values(MODES) as (typeof MODES)[keyof typeof MODES][]).map(
            (item) => {
              const selected = mode === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setMode(item.id)}
                  className={cn(
                    "rounded-[22px] border p-6 text-left transition-colors",
                    selected
                      ? "border-transparent bg-[var(--l1-fg)] text-[var(--primary-foreground)]"
                      : "border-[var(--l1-steel)] bg-[var(--l1-panel)] hover:border-[var(--l1-steel-strong)]",
                  )}
                >
                  <h3 className="text-[22px] font-semibold tracking-tight">
                    {item.title}
                  </h3>
                  <p
                    className={cn(
                      "mt-3 text-[14.5px] leading-relaxed",
                      selected
                        ? "text-[var(--l1-on-fg-muted)]"
                        : "text-[var(--l1-muted)]",
                    )}
                  >
                    {item.body}
                  </p>
                  {item.id === "direct" ? (
                    <span
                      className={cn(
                        "mt-5 inline-flex items-center gap-2 text-[13px] font-medium",
                        selected
                          ? "text-[var(--l1-on-fg)]"
                          : "text-[var(--l1-fg)]",
                      )}
                    >
                      <FaGithub className="size-4" />
                      Open source on GitHub
                    </span>
                  ) : (
                    <span
                      className={cn(
                        "mt-5 inline-block text-[13px] font-medium",
                        selected
                          ? "text-[var(--l1-on-fg)]"
                          : "text-[var(--l1-fg)]",
                      )}
                    >
                      Start for free →
                    </span>
                  )}
                </button>
              );
            },
          )}
        </div>

        <div className="mt-8 grid items-start gap-8 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
          <div>
            <h3 className="l1-h-sub mt-2 text-[var(--l1-fg)]">
              {mode === "direct"
                ? "Install the agent. Share a passphrase."
                : "Start for free. Invite the team."}
            </h3>
            {mode === "direct" ? (
              <div className="mt-6 flex flex-wrap items-center gap-3">
                <a
                  href={GITHUB_URL}
                  target="_blank"
                  rel="noreferrer"
                  className="l1-btn l1-btn--copper"
                >
                  <FaGithub className="size-4" />
                  View on GitHub
                </a>
              </div>
            ) : (
              <a href={APP_URL} className="l1-btn l1-btn--copper mt-6">
                Start for free
              </a>
            )}
          </div>
          <TerminalDemo title="zsh" code={current.code} />
        </div>
      </div>
    </section>
  );
}
