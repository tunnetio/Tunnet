import { useRouterState } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { AppSidebar } from "@/components/app/app-sidebar";
import { OrgSwitcher } from "@/components/app/org-switcher";
import { Separator } from "@/components/ui/separator";
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { usePresenceStream } from "@/hooks/use-presence-stream";
import { useActiveOrganization } from "@/lib/auth-client";
import { cn } from "@/lib/utils";

type AppShellProps = {
  children: ReactNode;
};

function useCanvasMode(pathname: string): boolean {
  if (pathname === "/app" || pathname === "/app/") return true;
  if (/^\/app\/networks\/[^/]+\/?$/.test(pathname)) return true;
  if (/^\/app\/kubernetes\/networks\/[^/]+\/?$/.test(pathname)) return true;
  return false;
}

export function AppShell({ children }: AppShellProps) {
  const { data: activeOrg } = useActiveOrganization();
  usePresenceStream(activeOrg?.id);
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const canvasMode = useCanvasMode(pathname);

  return (
    <SidebarProvider className="h-svh overflow-hidden">
      <AppSidebar />
      <SidebarInset className="min-h-0 overflow-hidden">
        <header className="z-30 flex h-14 shrink-0 items-center gap-3 border-b border-border/80 bg-background px-4 sm:px-6">
          <SidebarTrigger className="-ml-1 text-muted-foreground hover:text-foreground" />
          <Separator orientation="vertical" className="hidden h-5 sm:block" />
          <div className="flex min-w-0 flex-1 items-center">
            <OrgSwitcher />
          </div>
        </header>
        <main
          className={cn(
            "min-h-0 flex-1",
            canvasMode ? "overflow-hidden" : "overflow-y-auto",
          )}
        >
          <div
            className={cn(
              canvasMode
                ? "flex h-full min-h-0 w-full flex-col"
                : "mx-auto w-full max-w-[1400px] space-y-6 px-4 py-6 sm:px-6 sm:py-8 lg:px-8",
            )}
          >
            {children}
          </div>
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
