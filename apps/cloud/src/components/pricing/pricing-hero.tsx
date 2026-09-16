import { useGSAP } from "@gsap/react";
import { type ReactNode, useRef } from "react";
import {
  registerMarketingMotion,
  setupReveals,
} from "#/components/motion/landing-timeline";

export function PricingHero(): ReactNode {
  const root = useRef<HTMLElement>(null);
  useGSAP(
    () => {
      registerMarketingMotion();
      if (root.current) setupReveals(root.current);
    },
    { scope: root },
  );

  return (
    <section
      ref={root}
      className="relative isolate overflow-hidden pt-20 pb-10 sm:pt-28 sm:pb-14"
    >
      <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute inset-0 bg-[var(--l1-bg)]" />
        <div
          className="absolute inset-x-0 top-0 h-[640px]"
          style={{
            background:
              "radial-gradient(ellipse 62% 58% at 50% 0%, oklch(0.2 0.01 260 / 0.05), transparent 62%)",
          }}
        />
        <div className="p-perf absolute inset-x-0 top-0 h-[420px] opacity-50" />
        <div className="absolute inset-x-0 bottom-0 h-32 bg-[linear-gradient(180deg,transparent,var(--l1-bg))]" />
      </div>

      <div className="relative mx-auto max-w-[1160px] px-5 text-center sm:px-8">
        <h1 className="l1-h-hero l1-engraved mt-6 mx-auto max-w-[14ch] text-[var(--l1-fg)]">
          Pricing that scales
          <br />
          <span className="l1-copper-text">with your mesh.</span>
        </h1>
        <p className="l1-reveal l1-lead mt-6 mx-auto max-w-[48ch]">
          Direct mode is free forever. Managed plans from $5/month - seats and
          managed traffic, never per device.
        </p>
      </div>
    </section>
  );
}
