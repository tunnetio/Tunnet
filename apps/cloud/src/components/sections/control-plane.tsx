"use client";

import { ContainerScroll } from "@tunnet/ui/components/ui/container-scroll-animation";
import { PointerHighlight } from "@tunnet/ui/components/ui/pointer-highlight";
import type { ReactNode } from "react";
import { ConsolePreview } from "#/components/visuals/console-preview";

export function ControlPlaneSection(): ReactNode {
  return (
    <section className="relative overflow-hidden">
      <ContainerScroll
        titleComponent={
          <h2 className="mx-auto max-w-[18ch] text-[clamp(2rem,4.4vw,3.4rem)] leading-[1.05] font-semibold tracking-[-0.04em] text-[var(--l1-fg)] flex flex-col items-center">
            The control plane your team{" "}
            <PointerHighlight
              rectangleClassName="border-[var(--l1-fg)] bg-[var(--l1-copper-soft)]"
              pointerClassName="text-[var(--l1-fg)]"
            >
              <span>actually opens</span>
            </PointerHighlight>
            .
          </h2>
        }
      >
        {/* Drop /public/product/dashboard-full.png here. */}
        <ConsolePreview kind="mesh" />
      </ContainerScroll>
    </section>
  );
}
