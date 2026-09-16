import { cn } from "@tunnet/ui/lib/utils";
import type { ReactNode } from "react";
import { CodeBlock } from "#/components/shared/code-block";
import { CopyButton } from "#/components/shared/copy-button";

export function TerminalDemo({
  code,
  title = "zsh - tunnet",
  copyValue,
  className,
  showCopy = true,
  showPrompt = true,
}: {
  code: string;
  title?: string;
  copyValue?: string;
  className?: string;
  showCopy?: boolean;
  showPrompt?: boolean;
}): ReactNode {
  return (
    <div
      className={cn(
        "p-bezel relative overflow-hidden rounded-[var(--l1-r)]",
        className,
      )}
    >
      <div className="flex items-center justify-between gap-3 border-b border-black/50 px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex items-center gap-1.5" aria-hidden>
            <span className="size-2.5 rounded-full bg-[var(--l1-bad)]/70" />
            <span className="size-2.5 rounded-full bg-[var(--l1-warn)]/70" />
            <span className="size-2.5 rounded-full bg-[var(--l1-good)]/70" />
          </span>
          <span className="l1-readout truncate text-[var(--l1-on-bezel-muted)]">
            {title}
          </span>
        </div>
        {showCopy ? (
          <CopyButton
            value={copyValue ?? code}
            label="Copy"
            className="!border-white/20 !bg-white/10 !text-[var(--l1-on-bezel)] hover:!border-white/40 hover:!text-[var(--l1-on-bezel)]"
          />
        ) : null}
      </div>
      <div className="p-4">
        <CodeBlock code={code} showPrompt={showPrompt} />
      </div>
      <span
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,oklch(1_0_0/0.2),transparent)]"
      />
    </div>
  );
}
