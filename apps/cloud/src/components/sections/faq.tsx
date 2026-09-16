import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@tunnet/ui/components/accordion";
import type { ReactNode } from "react";

const FAQ = [
  {
    q: "How is this different from Tailscale?",
    a: "One product for private access, SSH, internal apps, and public HTTPS. Open source. Run our cloud or yours.",
  },
  {
    q: "Do I need to open firewall ports?",
    a: "No. Machines connect out. Relays pick up when a firewall is in the way.",
  },
  {
    q: "What is Direct mode?",
    a: "A private mesh with a passphrase. No account, no bill. Built for a personal fleet. Move to Managed when you want SSO, audit, and a dashboard.",
  },
  {
    q: "Which platforms does the agent support?",
    a: "macOS, Linux, and Windows.",
  },
  {
    q: "Can I bring my own edges and certificates?",
    a: "Yes. Run edges on infrastructure you control, point DNS at them, and use built-in certificates or your own.",
  },
  {
    q: "What's the license?",
    a: "MPL-2.0 for the agent and SDKs, AGPL-3.0-only for the control plane, Apache-2.0 for protocol code. A Commercial License is an alternative for AGPL components.",
  },
];

export function FaqSection(): ReactNode {
  return (
    <section className="px-4 py-20 sm:px-6 sm:py-28">
      <div className="mx-auto max-w-[720px]">
        <h2 className="l1-h-section text-[var(--l1-fg)]">Questions</h2>
        <Accordion className="mt-8 divide-y divide-[var(--l1-steel)] border-y border-[var(--l1-steel)]">
          {FAQ.map((f) => (
            <AccordionItem key={f.q} value={f.q} className="border-none">
              <AccordionTrigger className="py-5 text-left text-[15.5px] font-medium text-[var(--l1-fg)]">
                {f.q}
              </AccordionTrigger>
              <AccordionContent className="pb-5 pr-4 text-[14.5px] leading-relaxed text-[var(--l1-muted)]">
                {f.a}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </div>
    </section>
  );
}
