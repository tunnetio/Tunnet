import type { ReactNode } from "react";

const APP_URL = "https://app.tunnet.io";

export function FinalCtaSection(): ReactNode {
  return (
    <section className="px-4 py-20 sm:px-6 sm:py-28">
      <div className="mx-auto max-w-[1120px] rounded-[28px] bg-[var(--l1-fg)] px-8 py-16 text-[var(--primary-foreground)] sm:px-14 sm:py-20">
        <h2 className="max-w-[14ch] text-[clamp(2.2rem,5vw,4rem)] leading-[0.98] font-semibold tracking-[-0.045em]">
          Start for free. Connect every machine.
        </h2>
        <p className="mt-5 max-w-[42ch] text-[16px] leading-relaxed text-[var(--l1-on-fg-muted)]">
          A private network for your team in minutes. Direct stays free for a
          personal mesh with no account.
        </p>
        <div className="mt-8 flex flex-wrap items-center gap-3">
          <a
            href={APP_URL}
            className="l1-btn h-11 bg-[var(--l1-on-fg)] text-[var(--l1-fg)] hover:opacity-90"
          >
            Start for free
          </a>
          <a
            href="mailto:sales@tunnet.io"
            className="l1-btn l1-btn--ghost h-11 text-[var(--l1-on-fg-muted)] hover:text-[var(--l1-on-fg)]"
          >
            Book a demo
          </a>
        </div>
      </div>
    </section>
  );
}
