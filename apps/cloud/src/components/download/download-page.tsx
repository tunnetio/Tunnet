import { useGSAP } from "@gsap/react";
import { cn } from "@tunnet/ui/lib/utils";
import { DownloadIcon, TerminalIcon } from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { FaApple, FaLinux, FaWindows } from "react-icons/fa6";
import "@/marketing.css";
import { MarketingFooter } from "#/components/footer";
import {
  registerMarketingMotion,
  setupReveals,
} from "#/components/motion/landing-timeline";
import { initSmoothScroll } from "#/components/motion/smooth-scroll";
import { MarketingNav } from "#/components/nav";
import { CopyButton } from "#/components/shared/copy-button";
import { Panel } from "#/components/shared/panel";

type Platform = "windows" | "linux" | "macos";

const GET = "https://get.tunnet.io";

const PLATFORMS: {
  id: Platform;
  label: string;
  Icon: typeof FaWindows;
  command: string;
  note: string;
  gui: {
    available: boolean;
    file?: string;
    url?: string;
  };
}[] = [
  {
    id: "windows",
    label: "Windows",
    Icon: FaWindows,
    command: `irm ${GET}/windows | iex`,
    note: "Requires Administrator",
    gui: {
      available: true,
      file: "Windows installer",
      url: `${GET}/desktop/windows`,
    },
  },
  {
    id: "linux",
    label: "Linux",
    Icon: FaLinux,
    command: `curl -fsSL ${GET}/linux | sh`,
    note: "Requires root",
    gui: { available: false },
  },
  {
    id: "macos",
    label: "macOS",
    Icon: FaApple,
    command: `curl -fsSL ${GET}/macos | sh`,
    note: "Requires admin",
    gui: { available: false },
  },
];

function detectPlatform(): Platform {
  if (typeof navigator === "undefined") return "linux";
  const ua = navigator.userAgent.toLowerCase();
  const platform = (navigator.platform || "").toLowerCase();
  if (ua.includes("win") || platform.includes("win")) return "windows";
  if (ua.includes("mac") || platform.includes("mac")) return "macos";
  return "linux";
}

export function DownloadPage(): ReactNode {
  const root = useRef<HTMLElement>(null);
  const [selected, setSelected] = useState<Platform>("linux");

  useEffect(() => {
    const cleanup = initSmoothScroll();
    setSelected(detectPlatform());
    return cleanup;
  }, []);

  useGSAP(
    () => {
      registerMarketingMotion();
      if (root.current) setupReveals(root.current);
    },
    { scope: root },
  );

  const active = PLATFORMS.find((p) => p.id === selected) ?? PLATFORMS[0];

  return (
    <div className="marketing-root relative min-h-svh bg-[var(--l1-bg)] text-[var(--l1-fg)]">
      <MarketingNav />
      <main ref={root} className="overflow-x-hidden">
        {/* Hero */}
        <section className="relative isolate overflow-hidden px-5 py-15 sm:px-8">
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 -z-10"
          >
            <div className="absolute inset-0 bg-[var(--l1-bg)]" />
            <div
              className="absolute inset-x-0 top-0 h-[640px]"
              style={{
                background:
                  "radial-gradient(ellipse 62% 58% at 50% 0%, oklch(0.2 0.01 260 / 0.05), transparent 62%)",
              }}
            />
            <div className="p-perf absolute inset-x-0 top-0 h-[420px] opacity-40" />
            <div className="absolute inset-x-0 bottom-0 h-32 bg-[linear-gradient(180deg,transparent,var(--l1-bg))]" />
          </div>

          <div className="relative mx-auto max-w-[1160px] px-5 text-center sm:px-8">
            <h1 className="l1-h-hero l1-engraved mx-auto mt-5 max-w-[12ch] text-[var(--l1-fg)]">
              Download <span className="l1-copper-text">Tunnet</span>
            </h1>
            <p className="l1-lead mx-auto mt-6 max-w-[46ch]">
              One agent per machine. Nothing else to install.
            </p>

            <div className="l1-reveal mt-12">
              <div
                className="mx-auto inline-flex flex-col gap-1 rounded-[var(--l1-r-lg)] border border-[var(--l1-steel)] bg-[var(--l1-panel)]/70 p-1.5 backdrop-blur sm:flex-row"
                role="tablist"
                aria-label="Operating system"
              >
                {PLATFORMS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    role="tab"
                    aria-selected={selected === p.id}
                    onClick={() => setSelected(p.id)}
                    className={cn(
                      "flex items-center justify-center gap-3 rounded-xl px-7 py-3.5 text-[14px] font-medium transition-all sm:min-w-[160px]",
                      selected === p.id
                        ? "bg-[var(--l1-raised)] text-[var(--l1-fg)] shadow-[0_10px_24px_-14px_oklch(0_0_0/0.9)]"
                        : "text-[var(--l1-muted)] hover:text-[var(--l1-fg-dim)]",
                    )}
                  >
                    <p.Icon
                      className={cn(
                        "size-4.5",
                        selected === p.id
                          ? "text-[var(--l1-copper)]"
                          : "text-[var(--l1-muted-2)]",
                      )}
                    />
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Install card */}
        <section
          id="install"
          className="relative scroll-mt-24 px-5 pb-28 sm:px-8 sm:pb-36"
        >
          <div className="mx-auto max-w-[820px]">
            <div className="l1-reveal">
              <Panel raised screws className="p-brushed">
                <div className="flex flex-col p-7 sm:p-10">
                  {/* CLI + daemon */}
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3.5">
                      <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-[var(--l1-steel)] bg-[var(--l1-bg-2)] text-[var(--l1-fg)]">
                        <TerminalIcon className="size-4" />
                      </span>
                      <div>
                        <p className="text-[15px] font-medium text-[var(--l1-fg)]">
                          CLI + daemon
                        </p>
                        <p className="l1-readout mt-0.5 text-[var(--l1-muted-2)]">
                          {active.note}
                        </p>
                      </div>
                    </div>
                    <a
                      href={GET}
                      target="_blank"
                      rel="noreferrer"
                      className="l1-readout hidden text-[var(--l1-muted-2)] underline decoration-[var(--l1-steel-strong)] underline-offset-4 transition-colors hover:text-[var(--l1-copper)] sm:block"
                    >
                      install.ps1 / install.sh
                    </a>
                  </div>

                  <div className="p-bezel mt-8 flex items-center gap-3.5 rounded-xl px-5 py-4">
                    <span className="l1-readout select-none text-[var(--l1-on-bezel-muted)]">
                      $
                    </span>
                    <code className="flex-1 truncate text-left font-mono text-[13.5px] text-[var(--l1-on-bezel)]">
                      {active.command}
                    </code>
                    <CopyButton
                      value={active.command}
                      className="!border-white/20 !bg-white/10 !text-[var(--l1-on-bezel)] hover:!border-white/40 hover:!text-[var(--l1-on-bezel)]"
                    />
                  </div>

                  {/* Desktop */}
                  <div className="mt-8 flex items-center justify-between gap-6 border-t border-[var(--l1-steel)] pt-8">
                    <div className="flex items-center gap-3.5">
                      <active.Icon
                        className={cn(
                          "size-4.5",
                          active.gui.available
                            ? "text-[var(--l1-copper)]"
                            : "text-[var(--l1-muted-2)]",
                        )}
                      />
                      <div>
                        <p className="text-[15px] font-medium text-[var(--l1-fg)]">
                          Tunnet Desktop
                        </p>
                        <p className="l1-readout mt-0.5 text-[var(--l1-muted-2)]">
                          {active.gui.available && active.gui.file
                            ? active.gui.file
                            : `Coming soon on ${active.label}`}
                        </p>
                      </div>
                    </div>

                    {active.gui.available && active.gui.url ? (
                      <a
                        href={active.gui.url}
                        className="l1-btn l1-btn--copper group h-10 shrink-0 !px-5 !text-[12.5px]"
                      >
                        <DownloadIcon className="size-3.5" />
                        Download
                      </a>
                    ) : (
                      <span className="l1-readout shrink-0 rounded-full border border-[var(--l1-steel-strong)] px-3.5 py-1.5 text-[var(--l1-muted-2)]">
                        Soon
                      </span>
                    )}
                  </div>
                </div>
              </Panel>
            </div>

            <p className="l1-reveal mt-10 text-center">
              <a
                href="https://github.com/tunnetio/Tunnet/releases"
                target="_blank"
                rel="noreferrer"
                className="l1-readout text-[var(--l1-muted-2)] underline decoration-[var(--l1-steel-strong)] underline-offset-4 transition-colors hover:text-[var(--l1-copper)]"
              >
                Browse all releases on GitHub →
              </a>
            </p>
          </div>
        </section>
      </main>
      <MarketingFooter />
    </div>
  );
}
