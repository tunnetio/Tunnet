import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

type PageHeaderProps = {
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
  dense?: boolean;
};

export function PageHeader({
  title,
  description,
  actions,
  className,
  dense,
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between",
        className,
      )}
    >
      <div className={cn("min-w-0", dense ? "space-y-0.5" : "space-y-1")}>
        <h1
          className={cn(
            "font-semibold tracking-tight text-balance",
            dense ? "text-xl" : "text-2xl",
          )}
        >
          {title}
        </h1>
        {description ? (
          <p
            className={cn(
              "text-muted-foreground max-w-2xl text-pretty",
              dense ? "text-[13px] leading-relaxed" : "text-sm leading-relaxed",
            )}
          >
            {description}
          </p>
        ) : null}
      </div>
      {actions ? (
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {actions}
        </div>
      ) : null}
    </div>
  );
}
