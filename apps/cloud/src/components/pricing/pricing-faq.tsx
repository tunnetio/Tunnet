import { useGSAP } from "@gsap/react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@tunnet/ui/components/accordion";
import { type ReactNode, useRef } from "react";
import {
  registerMarketingMotion,
  setupReveals,
} from "#/components/motion/landing-timeline";

const FAQ = [
  {
    q: "What counts as a seat?",
    a: "One person in the organization. Personal is a single-seat flat plan. Team bills per seat with a 2-user minimum; Business with a 5-user minimum.",
  },
  {
    q: "Can I invite people on Personal?",
    a: "No. Personal is solo (1 seat). When you invite someone, you'll move to Team so seats and collaboration features match.",
  },
  {
    q: "What is a resource?",
    a: "A machine on your network - a laptop, server, CI runner, or edge. Caps scale with seats on Team and Business.",
  },
  {
    q: "What is managed traffic?",
    a: "Only traffic that goes through Tunnet relays or public tunnels counts toward your allowance. Peer-to-peer (direct) paths are free and never metered.",
  },
  {
    q: "What happens if I exceed my plan?",
    a: "You'll get soft warnings first. Upgrade seats or plan when you need more capacity - we don't hard-cut traffic mid-session without notice.",
  },
  {
    q: "Can I upgrade or downgrade anytime?",
    a: "Yes. Upgrades apply immediately, prorated; downgrades apply at the next cycle.",
  },
  {
    q: "Is Direct mode really free?",
    a: "Yes - including for commercial use. It's a first-class mode, not a trial.",
  },
  {
    q: "Do you offer annual billing?",
    a: "Coming soon at a discount. Enterprise agreements are annual by default.",
  },
];

export function PricingFaq(): ReactNode {
  const root = useRef<HTMLElement>(null);
  useGSAP(
    () => {
      registerMarketingMotion();
      if (root.current) setupReveals(root.current);
    },
    { scope: root },
  );

  return (
    <section id="faq" className="relative px-5 pt-20 sm:px-8 sm:pt-24">
      <div className="mx-auto max-w-[900px]">
        <div className="l1-reveal">
          <h2 className="l1-h-section l1-engraved mt-5 text-[var(--l1-fg)]">
            Billing, answered.
          </h2>
        </div>

        <div className="l1-reveal mt-9">
          <Accordion className="divide-y divide-[var(--l1-steel)]">
            {FAQ.map((f) => (
              <AccordionItem key={f.q} value={f.q} className="border-none">
                <AccordionTrigger className="py-5 text-left text-[15.5px] font-medium text-[var(--l1-fg)] transition-colors hover:text-[var(--l1-copper)] data-panel-open:text-[var(--l1-copper)]">
                  {f.q}
                </AccordionTrigger>
                <AccordionContent className="pb-5 pr-8 text-[14.5px] leading-relaxed text-[var(--l1-muted)]">
                  {f.a}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </div>
      </div>
    </section>
  );
}
