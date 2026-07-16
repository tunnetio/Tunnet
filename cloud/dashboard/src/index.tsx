import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

/** When true, `/` renders this marketing page instead of redirecting. */
export const hasMarketingLanding = true;

export function HomePage(): ReactNode {
  return (
    <div className="relative min-h-svh overflow-hidden bg-[#0c1210] text-[#e8f0ea]">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_20%_0%,#1a3d32_0%,transparent_55%),radial-gradient(ellipse_at_80%_20%,#243528_0%,transparent_50%),linear-gradient(180deg,#0c1210_0%,#101816_100%)]"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.07] [background-image:linear-gradient(rgba(232,240,234,0.5)_1px,transparent_1px),linear-gradient(90deg,rgba(232,240,234,0.5)_1px,transparent_1px)] [background-size:48px_48px]"
      />

      <header className="relative z-10 flex items-center justify-between px-6 py-5 sm:px-10">
        <span className="font-[family-name:var(--font-sans)] text-lg font-semibold tracking-tight">
          TunTun
        </span>
        <nav className="flex items-center gap-3">
          <Link
            to="/login"
            className="rounded-md px-3 py-2 text-sm text-[#e8f0ea]/80 transition-colors hover:text-[#e8f0ea]"
          >
            Sign in
          </Link>
          <Link
            to="/login"
            className="rounded-md bg-[#3d9b6e] px-3.5 py-2 text-sm font-medium text-[#0c1210] transition-colors hover:bg-[#4aad7d]"
          >
            Get started
          </Link>
        </nav>
      </header>

      <main className="relative z-10 mx-auto flex max-w-3xl flex-col items-start px-6 pb-24 pt-16 sm:px-10 sm:pt-24">
        <h1 className="max-w-2xl text-4xl font-semibold tracking-tight text-[#e8f0ea] sm:text-6xl sm:leading-[1.05]">
          TunTun
        </h1>
        <p className="mt-5 max-w-xl text-lg text-[#e8f0ea]/70 sm:text-xl">
          Zero-trust networking for teams — mesh, tunnels, and access control
          without the ops tax.
        </p>
        <div className="mt-10 flex flex-wrap items-center gap-3">
          <Link
            to="/login"
            className="rounded-md bg-[#3d9b6e] px-5 py-2.5 text-sm font-medium text-[#0c1210] transition-transform hover:bg-[#4aad7d] active:scale-[0.98]"
          >
            Start free
          </Link>
          <Link
            to="/login"
            className="rounded-md border border-[#e8f0ea]/20 px-5 py-2.5 text-sm font-medium text-[#e8f0ea] transition-colors hover:border-[#e8f0ea]/40"
          >
            Sign in
          </Link>
        </div>
      </main>
    </div>
  );
}
