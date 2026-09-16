"use client";

import { WobbleCard } from "@tunnet/ui/components/ui/wobble-card";
import type { ReactNode } from "react";

export function CapabilityBand(): ReactNode {
  return (
    <section className="px-4 py-20 sm:px-6 sm:py-28">
      <div className="mx-auto mb-10 max-w-[1120px]">
        <h2 className="l1-h-section max-w-[16ch] text-[var(--l1-fg)]">
          Stop gluing a VPN, a tunnel tool, and a bastion.
        </h2>
        <p className="l1-lead mt-4 max-w-[46ch]">
          Tunnet is the network, the dashboard, and the open-source agent. Run
          it on our cloud or yours.
        </p>
      </div>
      <div className="mx-auto grid w-full max-w-[1120px] grid-cols-1 gap-3 lg:grid-cols-3">
        <WobbleCard
          containerClassName="col-span-1 lg:col-span-2 min-h-[280px] bg-[#1c1d1a]"
          className="py-12"
        >
          <h3 className="max-w-sm text-left text-2xl font-semibold tracking-tight text-white">
            Managed cloud is the product.
          </h3>
          <p className="mt-3 max-w-sm text-[15px] leading-relaxed text-white/65">
            SSO, audit, and a dashboard for the team. Start for free and connect
            machines in minutes.
          </p>
        </WobbleCard>
        <WobbleCard containerClassName="min-h-[280px] bg-[#3f3f46]">
          <h3 className="text-2xl font-semibold tracking-tight text-white">
            Direct is the open-source on-ramp.
          </h3>
          <p className="mt-3 text-[15px] leading-relaxed text-white/65">
            Same GitHub agent. A private mesh with a passphrase, no account, and
            no bill.
          </p>
        </WobbleCard>
        <WobbleCard
          containerClassName="col-span-1 lg:col-span-3 min-h-[240px] bg-[#292524]"
          className="py-12"
        >
          <h3 className="max-w-lg text-2xl font-semibold tracking-tight text-white">
            Edges you can run. Certs you hold.
          </h3>
          <p className="mt-3 max-w-lg text-[15px] leading-relaxed text-white/65">
            Public tunnels terminate on infrastructure in your account. Point
            DNS, use ACME or bring a cert, pin a region.
          </p>
        </WobbleCard>
      </div>
    </section>
  );
}
