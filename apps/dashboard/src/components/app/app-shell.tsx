import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { NavTabs } from "@/components/app/nav-tabs";
import { OrgSwitcher } from "@/components/app/org-switcher";
import { UserMenu } from "@/components/app/user-menu";
import { usePresenceStream } from "@/hooks/use-presence-stream";
import { useActiveOrganization } from "@/lib/auth-client";

type AppShellProps = {
  children: ReactNode;
};

export function AppShell({ children }: AppShellProps) {
  const { data: activeOrg } = useActiveOrganization();
  usePresenceStream(activeOrg?.id);

  return (
    <div className="bg-background min-h-screen">
      <header className="border-border/60 border-b">
        <div className="mx-auto flex h-12 max-w-[1400px] items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-4">
            <Link
              to="/app"
              className="text-foreground flex shrink-0 items-center gap-2 font-medium tracking-tight"
            >
              <img
                src="/logo.png"
                alt="Tuntun"
                className="h-6 w-6 rounded-md"
              />
              <span className="hidden sm:inline">TunTun</span>
            </Link>
            <div className="bg-border hidden h-4 w-px sm:block" />
            <OrgSwitcher />
          </div>
          <UserMenu />
        </div>
        <div className="mx-auto max-w-[1400px] px-4 sm:px-6">
          <NavTabs />
        </div>
      </header>
      <main className="mx-auto max-w-[1400px] space-y-6 px-4 py-6 sm:px-6 sm:py-8">
        {children}
      </main>
    </div>
  );
}
