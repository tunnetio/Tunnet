"use client";

import { useGSAP } from "@gsap/react";
import {
  AdaptiveStepper,
  AdaptiveStepperDecrement,
  AdaptiveStepperIncrement,
  AdaptiveStepperValue,
} from "@tunnet/ui/components/motion/adaptive-stepper";
import { type ReactNode, useMemo, useRef, useState } from "react";
import {
  registerMarketingMotion,
  setupReveals,
} from "#/components/motion/landing-timeline";
import { Lamp } from "#/components/shared/lamp";
import { Panel } from "#/components/shared/panel";
import {
  minimumSeats,
  PLANS,
  type Plan,
  planForResources,
  resourceLimit,
  seatCost,
} from "#/lib/pricing";

function requirePlan(id: "personal" | "team" | "business"): Plan {
  const plan = PLANS.find((p) => p.id === id);
  if (!plan) throw new Error(`Missing plan: ${id}`);
  return plan;
}

const PERSONAL = requirePlan("personal");
const TEAM = requirePlan("team");
const BUSINESS = requirePlan("business");

const MAX_RESOURCES = 1000;

function SeatStepper({
  value,
  onChange,
}: {
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <AdaptiveStepper
      value={value}
      onValueChange={onChange}
      min={1}
      max={500}
      aria-label="Seats"
      className="text-[var(--l1-fg)]"
    >
      <AdaptiveStepperDecrement />
      <AdaptiveStepperValue />
      <AdaptiveStepperIncrement />
    </AdaptiveStepper>
  );
}

function billedSeats(plan: Plan, seats: number): number {
  return Math.max(seats, minimumSeats(plan.id));
}

function costDetail(plan: Plan, seats: number): string {
  const resources = resourceLimit(plan.id, seats);
  const resourcesLabel =
    resources === null ? "custom resources" : `${resources} resources`;

  if (plan.pricing === "flat") {
    return `$${plan.price}/mo flat · 1 seat · ${resourcesLabel}`;
  }

  const n = billedSeats(plan, seats);
  const min = minimumSeats(plan.id);
  const minNote = seats < min ? ` (billed at ${min} min)` : "";
  return `$${plan.price} × ${n} seats${minNote} · ${resourcesLabel}`;
}

export function Calculator(): ReactNode {
  const root = useRef<HTMLElement>(null);
  const [seats, setSeats] = useState(5);
  const [resources, setResources] = useState(80);

  useGSAP(
    () => {
      registerMarketingMotion();
      if (root.current) setupReveals(root.current);
    },
    { scope: root },
  );

  const personalCost = useMemo(() => seatCost(PERSONAL, 1) ?? 0, []);
  const teamCost = useMemo(() => seatCost(TEAM, seats) ?? 0, [seats]);
  const bizCost = useMemo(() => seatCost(BUSINESS, seats) ?? 0, [seats]);
  const fit = useMemo(() => planForResources(resources), [resources]);
  const fitResources = useMemo(
    () => resourceLimit(fit.id, fit.limits.minSeats),
    [fit],
  );
  const fill = (resources / MAX_RESOURCES) * 100;

  return (
    <section id="calculator" className="relative px-5 pt-20 sm:px-8 sm:pt-24">
      <div className="mx-auto max-w-[1160px]">
        <div className="l1-reveal mx-auto max-w-[46rem] text-center">
          <h2 className="l1-h-section l1-engraved mt-5 text-[var(--l1-fg)]">
            Know your monthly number
            <br />
            <span className="l1-copper-text">before you sign up.</span>
          </h2>
        </div>

        <div className="l1-reveal mt-10">
          <Panel live screws raised className="p-brushed">
            <div className="grid gap-0 lg:grid-cols-[1fr_1fr]">
              <div className="border-b border-[var(--l1-steel)] p-6 sm:p-8 lg:border-b-0 lg:border-r">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="l1-label text-[var(--l1-muted)]">
                      Seats
                    </span>
                  </div>
                  <div className="mt-3 flex items-center justify-between gap-4">
                    <SeatStepper value={seats} onChange={setSeats} />
                    <span className="l1-readout text-right text-[12px] text-[var(--l1-muted)]">
                      Team min {minimumSeats(TEAM.id)} · Business min{" "}
                      {minimumSeats(BUSINESS.id)}
                    </span>
                  </div>
                </div>

                <div className="mt-8">
                  <div className="flex items-center justify-between">
                    <span className="l1-label text-[var(--l1-muted)]">
                      Resources
                    </span>
                    <span className="l1-readout text-[var(--l1-copper)]">
                      {resources}
                    </span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={MAX_RESOURCES}
                    value={resources}
                    onChange={(e) => setResources(Number(e.target.value))}
                    className="l1-range mt-4"
                    style={{ ["--l1-fill" as string]: `${fill}%` }}
                    aria-label="Number of resources"
                  />
                  <div className="mt-1.5 flex justify-between">
                    <span className="l1-label !text-[8.5px] text-[var(--l1-muted-2)]">
                      1
                    </span>
                    <span className="l1-label !text-[8.5px] text-[var(--l1-muted-2)]">
                      {MAX_RESOURCES}+
                    </span>
                  </div>
                </div>

                <div className="mt-8 flex flex-wrap items-center gap-2">
                  <span className="l1-label !text-[9.5px] text-[var(--l1-muted-2)]">
                    FITS
                  </span>
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--l1-steel)] bg-[var(--l1-bg-2)] px-2.5 py-1">
                    <span className="l1-readout text-[var(--l1-fg)]">
                      {fit.name}
                    </span>
                  </span>
                  <span className="l1-readout text-[11px] text-[var(--l1-muted-2)]">
                    {fit.id === "enterprise"
                      ? "- talk to sales"
                      : `- ${fitResources} resources at min seats`}
                  </span>
                </div>
              </div>

              <div className="p-6 sm:p-8">
                <div className="grid gap-4">
                  <CostRow
                    plan="Personal"
                    detail={costDetail(PERSONAL, 1)}
                    cost={personalCost}
                    highlighted={seats === 1}
                  />
                  <CostRow
                    plan="Team"
                    detail={costDetail(TEAM, seats)}
                    cost={teamCost}
                    highlighted={
                      seats >= 2 && seats < minimumSeats(BUSINESS.id)
                    }
                  />
                  <CostRow
                    plan="Business"
                    detail={costDetail(BUSINESS, seats)}
                    cost={bizCost}
                    highlighted={seats >= minimumSeats(BUSINESS.id)}
                  />
                </div>
              </div>
            </div>
          </Panel>
        </div>
      </div>
    </section>
  );
}

function CostRow({
  plan,
  detail,
  cost,
  highlighted,
}: {
  plan: string;
  detail: string;
  cost: number;
  highlighted?: boolean;
}) {
  return (
    <div
      className={
        highlighted
          ? "rounded-xl border border-[var(--l1-steel-strong)] bg-[var(--l1-bg-2)] p-4"
          : "rounded-xl border border-[var(--l1-steel)] bg-[var(--l1-panel)]/50 p-4"
      }
    >
      <div className="flex items-center justify-between gap-3">
        <span className="flex items-center gap-2">
          <Lamp
            status={highlighted ? "good" : "idle"}
            live={highlighted}
            className="!size-1.5"
          />
          <span className="l1-label text-[var(--l1-fg-dim)]">{plan}</span>
        </span>
        <span className="l1-readout text-[26px] font-semibold l1-engraved text-[var(--l1-fg)]">
          ${cost}
          <span className="ml-1 text-[12px] font-normal text-[var(--l1-muted-2)]">
            /mo
          </span>
        </span>
      </div>
      <p className="l1-readout mt-1.5 text-[11.5px] text-[var(--l1-muted)]">
        {detail}
      </p>
    </div>
  );
}
