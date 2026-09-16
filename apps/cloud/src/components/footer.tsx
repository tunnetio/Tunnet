import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { FaDiscord, FaGithub, FaXTwitter, FaYoutube } from "react-icons/fa6";

const COLUMNS = [
  {
    title: "Product",
    links: [
      { label: "Mesh", href: "/#product" },
      { label: "Modes", href: "/#modes" },
      { label: "Pricing", href: "/pricing" },
      { label: "Download", href: "/download" },
    ],
  },
  {
    title: "Resources",
    links: [
      { label: "Docs", href: "https://docs.tunnet.io", external: true },
      {
        label: "GitHub",
        href: "https://github.com/tunnetio/Tunnet",
        external: true,
      },
      {
        label: "Discord",
        href: "https://discord.gg/y5bNc3MYKz",
        external: true,
      },
      { label: "Status", href: "https://status.tunnet.io", external: true },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "About", href: "/about" },
      { label: "Blog", href: "/blog" },
      { label: "Contact", href: "mailto:hello@tunnet.io", external: true },
    ],
  },
  {
    title: "Legal",
    links: [
      { label: "Privacy", href: "/legal/privacy" },
      { label: "Terms", href: "/legal/terms" },
      {
        label: "Licenses",
        href: "https://github.com/tunnetio/Tunnet/blob/main/LICENSING.md",
        external: true,
      },
    ],
  },
];

export function MarketingFooter(): ReactNode {
  return (
    <footer className="border-t border-[var(--l1-steel)] bg-[var(--l1-bg-2)] text-[var(--l1-muted)]">
      <div className="mx-auto max-w-[1120px] px-5 pt-16 pb-8 sm:px-8">
        <div className="grid gap-12 lg:grid-cols-[1.1fr_2fr]">
          <div>
            <Link to="/" className="inline-flex items-center gap-2">
              <img alt="" src="/logo.png" className="size-7" />
              <span className="text-[15px] font-semibold tracking-tight text-[var(--l1-fg)]">
                Tunnet
              </span>
            </Link>
            <p className="mt-4 max-w-xs text-sm leading-relaxed">
              Private networking for every machine. Open source. Start for free.
            </p>
            <div className="mt-6 flex items-center gap-2">
              {[
                {
                  Icon: FaGithub,
                  href: "https://github.com/tunnetio/Tunnet",
                  label: "GitHub",
                },
                {
                  Icon: FaDiscord,
                  href: "https://discord.gg/y5bNc3MYKz",
                  label: "Discord",
                },
                {
                  Icon: FaXTwitter,
                  href: "https://x.com/tunnetio",
                  label: "X",
                },
                {
                  Icon: FaYoutube,
                  href: "https://youtube.com/@tunnet",
                  label: "YouTube",
                },
              ].map(({ Icon, href, label }) => (
                <a
                  key={label}
                  href={href}
                  target="_blank"
                  rel="noreferrer"
                  aria-label={label}
                  className="grid size-9 place-items-center rounded-full border border-[var(--l1-steel)] text-[var(--l1-fg-dim)] hover:text-[var(--l1-fg)]"
                >
                  <Icon className="size-4" />
                </a>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
            {COLUMNS.map((col) => (
              <div key={col.title}>
                <p className="text-[12px] font-medium tracking-[0.08em] text-[var(--l1-muted-2)] uppercase">
                  {col.title}
                </p>
                <ul className="mt-4 flex flex-col gap-2.5 text-sm">
                  {col.links.map((l) => (
                    <li key={l.label}>
                      <a
                        href={l.href}
                        {...("external" in l && l.external
                          ? { target: "_blank", rel: "noreferrer" }
                          : {})}
                        className="hover:text-[var(--l1-fg)]"
                      >
                        {l.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-14 h-px bg-[var(--l1-steel)]" />
        <p className="mt-6 font-mono text-[12px] text-[var(--l1-muted-2)]">
          © {new Date().getFullYear()} Tunnet
        </p>
      </div>
    </footer>
  );
}
