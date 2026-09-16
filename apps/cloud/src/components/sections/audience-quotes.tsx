import { Marquee } from "@tunnet/ui/components/marquee";
import type { ReactNode } from "react";

const QUOTES = [
  {
    id: "ravi",
    quote:
      "New engineers install one binary and can SSH to prod within an hour, with audit already on.",
    author: "Ravi Nair",
    title: "Staff Platform Engineer, Halogen",
  },
  {
    id: "marta",
    quote:
      "Identity-scoped access, encrypted transport, and session recording without a six-week ZTNA project.",
    author: "Marta Cohen",
    title: "Head of Security, Northgate",
  },
  {
    id: "jonah",
    quote:
      "Direct got the homelab on a mesh in ten minutes. Same app we later used with the team.",
    author: "Jonah Pell",
    title: "Founder, Driftwood",
  },
  {
    id: "leah",
    quote:
      "We replaced a bastion and a tunnel box. Policy is one file. SSH follows the person.",
    author: "Leah Okonkwo",
    title: "SRE, Kiteworks Lab",
  },
  {
    id: "chris",
    quote: "CI runners get overlay IPs. No SSH keys sitting in GitHub secrets.",
    author: "Chris Vale",
    title: "Platform, Copperline",
  },
  {
    id: "ines",
    quote:
      "Self-hosted the control plane. Same dashboard the managed cloud uses.",
    author: "Ines Duarte",
    title: "Infra lead, Sable",
  },
];

function QuoteCard({
  quote,
  author,
  title,
}: (typeof QUOTES)[number]): ReactNode {
  return (
    <figure className="flex h-full w-[22rem] shrink-0 flex-col justify-between rounded-[28px] border border-[var(--l1-steel)] bg-[var(--l1-panel)] p-6 sm:w-[26rem]">
      <blockquote className="text-[16px] leading-snug font-medium tracking-[-0.02em] text-[var(--l1-fg)]">
        {quote}
      </blockquote>
      <figcaption className="mt-5 text-[13px] text-[var(--l1-muted)]">
        <span className="font-medium text-[var(--l1-fg)]">{author}</span>
        <span className="mt-0.5 block">{title}</span>
      </figcaption>
    </figure>
  );
}

export function AudienceQuotesSection(): ReactNode {
  const top = QUOTES.slice(0, 3);
  const bottom = QUOTES.slice(3);

  return (
    <section id="testimonials" className="overflow-hidden py-10">
      <div className="mx-auto mb-10 max-w-[1120px] px-4 sm:px-6">
        <h2 className="l1-h-section mt-3 max-w-[16ch] text-[var(--l1-fg)]">
          From people who already run machines.
        </h2>
      </div>
      <div className="relative">
        <Marquee
          pauseOnHover
          repeat={4}
          className="[--duration:48s] [--gap:0.85rem] p-0"
        >
          {top.map((item) => (
            <QuoteCard key={item.id} {...item} />
          ))}
        </Marquee>
        <Marquee
          reverse
          pauseOnHover
          repeat={4}
          className="mt-3 [--duration:56s] [--gap:0.85rem] p-0"
        >
          {bottom.map((item) => (
            <QuoteCard key={item.id} {...item} />
          ))}
        </Marquee>
      </div>
    </section>
  );
}
