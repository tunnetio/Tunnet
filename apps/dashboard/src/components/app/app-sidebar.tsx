import { Link, useRouterState } from "@tanstack/react-router";
import { type ComponentType, useEffect, useMemo, useState } from "react";
import {
  HiOutlineArrowsRightLeft,
  HiOutlineBolt,
  HiOutlineChartBarSquare,
  HiOutlineChevronDown,
  HiOutlineClipboardDocumentList,
  HiOutlineCog6Tooth,
  HiOutlineCommandLine,
  HiOutlineCube,
  HiOutlineServer,
  HiOutlineServerStack,
  HiOutlineShare,
  HiOutlineShieldCheck,
  HiOutlineUsers,
} from "react-icons/hi2";

import { UserMenu } from "@/components/app/user-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar";
import { useActiveOrganization } from "@/lib/auth-client";
import { useServes, useTunnels } from "@/lib/queries/management";
import { cn } from "@/lib/utils";

type NavIcon = ComponentType<{ className?: string }>;

type NavItem = {
  to: string;
  label: string;
  icon: NavIcon;
  exact?: boolean;
  badge?: "tunnels" | "serves";
};

type NavSection = {
  id: string;
  label: string;
  items: NavItem[];
  defaultOpen?: boolean;
};

const overviewItem: NavItem = {
  to: "/app",
  label: "Overview",
  icon: HiOutlineChartBarSquare,
  exact: true,
};

const navSections: NavSection[] = [
  {
    id: "infrastructure",
    label: "Infrastructure",
    defaultOpen: true,
    items: [
      { to: "/app/machines", label: "Machines", icon: HiOutlineServer },
      { to: "/app/relays", label: "Relays", icon: HiOutlineServerStack },
      { to: "/app/networks", label: "Networks", icon: HiOutlineShare },
    ],
  },
  {
    id: "connectivity",
    label: "Connectivity",
    defaultOpen: true,
    items: [
      {
        to: "/app/tunnels",
        label: "Tunnels",
        icon: HiOutlineBolt,
        badge: "tunnels",
      },
      {
        to: "/app/serves",
        label: "Serves",
        icon: HiOutlineCube,
        badge: "serves",
      },
      {
        to: "/app/ssh-sessions",
        label: "SSH",
        icon: HiOutlineCommandLine,
      },
      {
        to: "/app/transfers",
        label: "Transfers",
        icon: HiOutlineArrowsRightLeft,
      },
    ],
  },
  {
    id: "admin",
    label: "Administration",
    defaultOpen: false,
    items: [
      { to: "/app/users", label: "Users", icon: HiOutlineUsers },
      { to: "/app/access", label: "Access", icon: HiOutlineShieldCheck },
      {
        to: "/app/logs",
        label: "Logs",
        icon: HiOutlineClipboardDocumentList,
      },
      {
        to: "/app/organization",
        label: "Organization",
        icon: HiOutlineCog6Tooth,
      },
    ],
  },
];

function isNavActive(pathname: string, to: string, exact?: boolean): boolean {
  if (exact) {
    if (to === "/app") return pathname === "/app" || pathname === "/app/";
    return pathname === to;
  }
  return pathname === to || pathname.startsWith(`${to}/`);
}

function sectionContainsActive(pathname: string, section: NavSection): boolean {
  return section.items.some((item) =>
    isNavActive(pathname, item.to, item.exact),
  );
}

function NavMenuItem({
  item,
  pathname,
  badgeCount,
}: {
  item: NavItem;
  pathname: string;
  badgeCount: number;
}) {
  const active = isNavActive(pathname, item.to, item.exact);
  const Icon = item.icon;

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        render={<Link to={item.to} />}
        isActive={active}
        tooltip={item.label}
      >
        <Icon className="size-4" />
        <span>{item.label}</span>
      </SidebarMenuButton>
      {badgeCount > 0 ? (
        <SidebarMenuBadge>{badgeCount}</SidebarMenuBadge>
      ) : null}
    </SidebarMenuItem>
  );
}

function CollapsibleNavSection({
  section,
  pathname,
  badgeFor,
}: {
  section: NavSection;
  pathname: string;
  badgeFor: (item: NavItem) => number;
}) {
  const hasActive = sectionContainsActive(pathname, section);
  const [open, setOpen] = useState(section.defaultOpen || hasActive);

  useEffect(() => {
    if (hasActive) setOpen(true);
  }, [hasActive]);

  return (
    <SidebarGroup>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className={cn(
          "text-sidebar-foreground/60 hover:text-sidebar-foreground flex h-8 w-full items-center gap-1 rounded-md px-2 text-[11px] font-medium tracking-wide uppercase transition-colors",
          "group-data-[collapsible=icon]:hidden",
        )}
      >
        <span className="flex-1 truncate text-left">{section.label}</span>
        <HiOutlineChevronDown
          className={cn(
            "size-3.5 shrink-0 transition-transform duration-200 ease-out",
            open ? "rotate-0" : "-rotate-90",
          )}
        />
      </button>
      <SidebarGroupLabel className="hidden group-data-[collapsible=icon]:flex">
        {section.label}
      </SidebarGroupLabel>
      <SidebarGroupContent
        className={cn(
          "grid transition-[grid-template-rows,opacity] duration-200 ease-out",
          open
            ? "grid-rows-[1fr] opacity-100"
            : "grid-rows-[0fr] opacity-0 group-data-[collapsible=icon]:grid-rows-[1fr] group-data-[collapsible=icon]:opacity-100",
        )}
      >
        <div className="overflow-hidden">
          <SidebarMenu>
            {section.items.map((item) => (
              <NavMenuItem
                key={item.to}
                item={item}
                pathname={pathname}
                badgeCount={badgeFor(item)}
              />
            ))}
          </SidebarMenu>
        </div>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}

export function AppSidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const { data: activeOrg } = useActiveOrganization();
  const orgId = activeOrg?.id;
  const { data: tunnels } = useTunnels(orgId);
  const { data: serves } = useServes(orgId);

  const activeTunnelCount = useMemo(
    () => (tunnels ?? []).filter((t) => t.status === "active").length,
    [tunnels],
  );
  const activeServeCount = useMemo(
    () => (serves ?? []).filter((s) => s.status === "active").length,
    [serves],
  );

  function badgeFor(item: NavItem): number {
    if (item.badge === "tunnels") return activeTunnelCount;
    if (item.badge === "serves") return activeServeCount;
    return 0;
  }

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="border-sidebar-border gap-0 border-b">
        <Link
          to="/app"
          className="flex items-center gap-2.5 overflow-hidden rounded-lg py-2 transition-colors"
        >
          <img
            src="/logo.png"
            alt="Tuntun"
            className="size-7 shrink-0 rounded-md"
          />
          <p className="truncate text-sm font-semibold tracking-tight">
            TunTun
          </p>
        </Link>
      </SidebarHeader>

      <SidebarContent className="gap-1 py-2">
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              <NavMenuItem
                item={overviewItem}
                pathname={pathname}
                badgeCount={0}
              />
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {navSections.map((section) => (
          <CollapsibleNavSection
            key={section.id}
            section={section}
            pathname={pathname}
            badgeFor={badgeFor}
          />
        ))}
      </SidebarContent>

      <SidebarFooter className="border-sidebar-border border-t p-2">
        <SidebarMenu>
          <SidebarMenuItem>
            <UserMenu />
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
