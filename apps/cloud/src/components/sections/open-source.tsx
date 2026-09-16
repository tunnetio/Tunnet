import type { ReactNode } from "react";
import { FaGithub } from "react-icons/fa6";

const GITHUB_URL = "https://github.com/tunnetio/Tunnet";

export function OpenSourceSection(): ReactNode {
  return (
    <section id="open-source" className="px-4 py-16 sm:px-6 sm:py-20">
      <div className="mx-auto flex max-w-[1120px] flex-col gap-8 rounded-[28px] border border-[var(--l1-steel)] bg-[var(--l1-panel)] px-6 py-10 sm:flex-row sm:items-center sm:justify-between sm:px-10">
        <div className="max-w-[40rem]">
          <h2 className="mt-2 text-[clamp(1.7rem,3vw,2.2rem)] leading-[1.1] font-semibold tracking-[-0.04em] text-[var(--l1-fg)]">
            Open source. Direct and Managed both run it.
          </h2>
          <p className="mt-3 text-[15px] leading-relaxed text-[var(--l1-muted)]">
            Direct and Managed run the same open-source agent. Read the code,
            run it yourself, or start on our cloud.
          </p>
        </div>
        <a
          href={GITHUB_URL}
          target="_blank"
          rel="noreferrer"
          className="l1-btn l1-btn--copper shrink-0"
        >
          <FaGithub className="size-4" />
          View on GitHub
        </a>
      </div>
    </section>
  );
}
