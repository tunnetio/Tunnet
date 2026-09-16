import { Link } from "@tanstack/react-router";
import { ThemeToggle } from "@tunnet/ui/components/motion/theme-toggle";
import {
  MobileNav,
  MobileNavHeader,
  MobileNavMenu,
  MobileNavToggle,
  NavBody,
  Navbar,
} from "@tunnet/ui/components/ui/resizable-navbar";
import {
  MotionNavigationMenu,
  MotionNavigationMenuContent,
  MotionNavigationMenuItem,
  MotionNavigationMenuLink,
  MotionNavigationMenuList,
  MotionNavigationMenuTrigger,
  motionNavigationMenuTriggerStyle,
} from "@tunnet/ui/components/unlumen-ui/motion-navigation-menu";
import { cn } from "@tunnet/ui/lib/utils";
import { ArrowRightIcon } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import { FaGithub } from "react-icons/fa6";

const APP_URL = "https://app.tunnet.io";
const GITHUB_URL = "https://github.com/tunnetio/Tunnet";

const PRODUCT_LINKS = [
  {
    name: "Remote access",
    href: "/#product",
    blurb: "A private network for every machine.",
  },
  {
    name: "SSH",
    href: "/#product",
    blurb: "Connect by name. No keys to copy.",
  },
  {
    name: "Public HTTPS",
    href: "/#product",
    blurb: "Share a URL. Keep the origin private.",
  },
];

const RESOURCE_LINKS = [
  {
    name: "GitHub",
    href: GITHUB_URL,
    blurb: "Open source. Read every line.",
    external: true,
  },
  {
    name: "Discord",
    href: "https://discord.gg/y5bNc3MYKz",
    blurb: "Community and support.",
    external: true,
  },
  {
    name: "Status",
    href: "https://status.tunnet.io",
    blurb: "Cloud and relay uptime.",
    external: true,
  },
];

const triggerClass =
  "h-8 px-3 text-[13px] font-medium text-neutral-600 dark:text-neutral-300";

function MenuLink({
  href,
  name,
  blurb,
  external,
}: {
  href: string;
  name: string;
  blurb: string;
  external?: boolean;
}) {
  return (
    <MotionNavigationMenuLink
      href={href}
      {...(external ? { target: "_blank", rel: "noreferrer" } : {})}
      className="min-w-[15rem] rounded-xl px-3 py-2.5"
    >
      <span className="text-[13px] font-semibold text-neutral-900 dark:text-neutral-50">
        {name}
      </span>
      <span className="text-[12.5px] leading-snug text-neutral-500 dark:text-neutral-400">
        {blurb}
      </span>
    </MotionNavigationMenuLink>
  );
}

function DesktopMenu(): ReactNode {
  return (
    <MotionNavigationMenu
      className="relative z-10 hidden lg:flex"
      viewportClassName="rounded-2xl border-black/8 bg-white/95 shadow-[0_24px_80px_-28px_rgba(15,18,22,0.45)] dark:border-white/10 dark:bg-neutral-950/95"
    >
      <MotionNavigationMenuList
        className="gap-0"
        highlightClassName="rounded-full bg-neutral-100 dark:bg-neutral-800"
      >
        <MotionNavigationMenuItem value="product">
          <MotionNavigationMenuTrigger className={triggerClass}>
            Product
          </MotionNavigationMenuTrigger>
          <MotionNavigationMenuContent innerClassName="flex flex-col gap-0.5">
            {PRODUCT_LINKS.map((item) => (
              <MenuLink key={item.name} {...item} />
            ))}
          </MotionNavigationMenuContent>
        </MotionNavigationMenuItem>

        <MotionNavigationMenuItem value="resources">
          <MotionNavigationMenuTrigger className={triggerClass}>
            Resources
          </MotionNavigationMenuTrigger>
          <MotionNavigationMenuContent innerClassName="flex flex-col gap-0.5">
            {RESOURCE_LINKS.map((item) => (
              <MenuLink key={item.name} {...item} />
            ))}
          </MotionNavigationMenuContent>
        </MotionNavigationMenuItem>

        <MotionNavigationMenuItem>
          <a
            href="https://docs.tunnet.io"
            target="_blank"
            rel="noreferrer"
            className={cn(motionNavigationMenuTriggerStyle(), triggerClass)}
          >
            Docs
          </a>
        </MotionNavigationMenuItem>

        <MotionNavigationMenuItem>
          <Link
            to="/pricing"
            className={cn(motionNavigationMenuTriggerStyle(), triggerClass)}
          >
            Pricing
          </Link>
        </MotionNavigationMenuItem>

        <MotionNavigationMenuItem>
          <Link
            to="/download"
            className={cn(motionNavigationMenuTriggerStyle(), triggerClass)}
          >
            Download
          </Link>
        </MotionNavigationMenuItem>
      </MotionNavigationMenuList>
    </MotionNavigationMenu>
  );
}

function NavActions({ compact }: { compact?: boolean }): ReactNode {
  return (
    <div className="relative z-20 flex shrink-0 items-center gap-1.5">
      <ThemeToggle
        variant="circle-blur"
        start="top-right"
        className="size-9 rounded-full text-neutral-700 dark:text-neutral-200"
        iconClassName="size-4"
      />
      <a
        href={GITHUB_URL}
        target="_blank"
        rel="noreferrer"
        aria-label="Tunnet on GitHub"
        className="grid size-9 place-items-center rounded-full text-neutral-700 hover:bg-neutral-100 dark:text-neutral-200 dark:hover:bg-neutral-800"
      >
        <FaGithub className="size-4" />
      </a>
      {compact ? null : (
        <a
          href={APP_URL}
          className="l1-btn l1-btn--copper h-9 !px-3.5 !text-[12.5px]"
        >
          Start for free
          <ArrowRightIcon className="size-3.5" />
        </a>
      )}
    </div>
  );
}

export function MarketingNav(): ReactNode {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  useEffect(() => {
    const media = window.matchMedia("(min-width: 1024px)");
    const onChange = () => {
      if (media.matches) setOpen(false);
    };
    onChange();
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  return (
    <Navbar className="top-0">
      <NavBody className="max-w-[1120px] gap-4">
        <Link
          to="/"
          className="relative z-20 flex shrink-0 items-center gap-2 px-2 py-1"
        >
          <img alt="" src="/logo.png" className="size-7" />
          <span className="text-[15px] font-semibold tracking-tight text-neutral-900 dark:text-white">
            Tunnet
          </span>
        </Link>
        <div className="flex min-w-0 flex-1 justify-center">
          <DesktopMenu />
        </div>
        <NavActions />
      </NavBody>

      <MobileNav className="max-w-[calc(100vw-1.25rem)]">
        <MobileNavHeader>
          <Link to="/" className="flex items-center gap-2 px-1">
            <img alt="" src="/logo.png" className="size-7" />
            <span className="text-[15px] font-semibold tracking-tight">
              Tunnet
            </span>
          </Link>
          <div className="flex items-center gap-0.5">
            <NavActions compact />
            <MobileNavToggle
              isOpen={open}
              onClick={() => setOpen((value) => !value)}
            />
          </div>
        </MobileNavHeader>
        <MobileNavMenu isOpen={open} onClose={() => setOpen(false)}>
          <p className="px-3 pt-1 text-[11px] font-medium tracking-[0.14em] text-neutral-400 uppercase">
            Product
          </p>
          {PRODUCT_LINKS.map((item) => (
            <a
              key={item.name}
              href={item.href}
              className="rounded-xl px-3 py-2.5 text-[16px] font-medium text-neutral-800 dark:text-neutral-100"
              onClick={() => setOpen(false)}
            >
              {item.name}
            </a>
          ))}
          <p className="mt-3 px-3 text-[11px] font-medium tracking-[0.14em] text-neutral-400 uppercase">
            Resources
          </p>
          {RESOURCE_LINKS.map((item) => (
            <a
              key={item.name}
              href={item.href}
              {...(item.external
                ? { target: "_blank", rel: "noreferrer" }
                : {})}
              className="rounded-xl px-3 py-2.5 text-[16px] font-medium text-neutral-800 dark:text-neutral-100"
              onClick={() => setOpen(false)}
            >
              {item.name}
            </a>
          ))}
          <a
            href="https://docs.tunnet.io"
            target="_blank"
            rel="noreferrer"
            className="rounded-xl px-3 py-2.5 text-[16px] font-medium text-neutral-800 dark:text-neutral-100"
            onClick={() => setOpen(false)}
          >
            Docs
          </a>
          <Link
            to="/pricing"
            className="rounded-xl px-3 py-2.5 text-[16px] font-medium text-neutral-800 dark:text-neutral-100"
            onClick={() => setOpen(false)}
          >
            Pricing
          </Link>
          <Link
            to="/download"
            className="rounded-xl px-3 py-2.5 text-[16px] font-medium text-neutral-800 dark:text-neutral-100"
            onClick={() => setOpen(false)}
          >
            Download
          </Link>
          <div className="mt-auto flex flex-col gap-2 pt-4">
            <a
              href={APP_URL}
              className="l1-btn l1-btn--copper h-11 w-full"
              onClick={() => setOpen(false)}
            >
              Start for free
              <ArrowRightIcon className="size-4" />
            </a>
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noreferrer"
              className="l1-btn l1-btn--ghost h-11 w-full"
              onClick={() => setOpen(false)}
            >
              <FaGithub className="size-4" />
              Open source on GitHub
            </a>
          </div>
        </MobileNavMenu>
      </MobileNav>
    </Navbar>
  );
}
