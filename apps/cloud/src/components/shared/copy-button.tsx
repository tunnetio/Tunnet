import { cn } from "@tunnet/ui/lib/utils";
import { CheckIcon, CopyIcon } from "lucide-react";
import { type ReactNode, useState } from "react";

export function CopyButton({
  value,
  className,
  label = "Copy",
}: {
  value: string;
  className?: string;
  label?: string;
}): ReactNode {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1400);
        } catch {
          /* ignore */
        }
      }}
      className={cn(
        "inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md border border-[var(--l1-steel-strong)] bg-[var(--l1-panel)] px-2.5 text-[11.5px] font-medium text-[var(--l1-muted)] transition-colors hover:border-[var(--l1-fg)] hover:text-[var(--l1-fg)]",
        className,
      )}
      aria-label={copied ? "Copied" : label}
    >
      {copied ? (
        <CheckIcon className="size-3.5 text-[var(--l1-good)]" />
      ) : (
        <CopyIcon className="size-3.5" />
      )}
    </button>
  );
}
