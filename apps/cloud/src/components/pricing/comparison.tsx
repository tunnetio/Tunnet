import { useGSAP } from "@gsap/react";
import { CheckIcon } from "lucide-react";
import { type ReactNode, useRef } from "react";
import {
  registerMarketingMotion,
  setupReveals,
} from "#/components/motion/landing-timeline";

type Cell = string | "yes" | "no";

const HEADERS = ["Free", "Personal", "Team", "Business", "Enterprise"];
const HIGHLIGHT = "Personal";

const RAW_ROWS: { label: string; cells: Cell[] }[] = [
  {
    label: "Price",
    cells: ["$0", "$5 /mo", "$5 /user", "$10 /user", "Custom"],
  },
  {
    label: "Seats",
    cells: ["1", "1", "2 min", "5 min", "Custom"],
  },
  {
    label: "Resources",
    cells: ["20", "100", "100 + 25/extra", "500 + 50/extra", "Custom"],
  },
  {
    label: "Networks",
    cells: ["1", "5", "10", "50", "Custom"],
  },
  {
    label: "Public tunnels",
    cells: ["1", "5", "25", "100", "Custom"],
  },
  {
    label: "Managed traffic",
    cells: ["5 GB", "50 GB", "250 GB", "1 TB", "Custom"],
  },
  {
    label: "Audit retention",
    cells: ["24 hours", "30 days", "90 days", "365 days", "Custom"],
  },
  {
    label: "Mesh · DNS · Serve · Send · SSH",
    cells: ["yes", "yes", "yes", "yes", "yes"],
  },
  { label: "Invites", cells: ["no", "no", "yes", "yes", "yes"] },
  { label: "Custom domains", cells: ["no", "yes", "yes", "yes", "yes"] },
  { label: "REST API", cells: ["no", "yes", "yes", "yes", "yes"] },
  { label: "Kubernetes", cells: ["no", "yes", "yes", "yes", "yes"] },
  { label: "OIDC SSO", cells: ["no", "no", "yes", "yes", "yes"] },
  { label: "Custom roles", cells: ["no", "no", "yes", "yes", "yes"] },
  { label: "Policy as Code", cells: ["no", "no", "yes", "yes", "yes"] },
  { label: "SAML / SCIM", cells: ["no", "no", "no", "yes", "yes"] },
  { label: "SSH session recording", cells: ["no", "no", "no", "yes", "yes"] },
  { label: "Log streaming", cells: ["no", "no", "no", "yes", "yes"] },
  { label: "Compliance export", cells: ["no", "no", "no", "yes", "yes"] },
  { label: "Domain claiming", cells: ["no", "no", "no", "yes", "yes"] },
  { label: "Regional relays", cells: ["no", "no", "no", "yes", "yes"] },
  {
    label: "Dedicated edges & control plane",
    cells: ["no", "no", "no", "no", "yes"],
  },
  {
    label: "Self-host commercial license",
    cells: ["no", "no", "no", "no", "yes"],
  },
  { label: "24/7 support & SLA", cells: ["no", "no", "no", "no", "yes"] },
];

const ROWS = RAW_ROWS.map((r) => ({
  label: r.label,
  cols: HEADERS.map((h, i) => ({
    id: `${r.label}-${h}`,
    value: r.cells[i] as Cell,
  })),
}));

function Cell({ value }: { value: Cell }) {
  if (value === "yes")
    return <CheckIcon className="mx-auto size-4 text-[var(--l1-copper)]" />;
  if (value === "no")
    return <span className="l1-readout text-[var(--l1-muted-2)]">-</span>;
  return (
    <span className="l1-readout whitespace-nowrap text-[13px] text-[var(--l1-fg-dim)]">
      {value}
    </span>
  );
}

function isHighlightCol(id: string): boolean {
  return id.endsWith(`-${HIGHLIGHT}`);
}

export function Comparison(): ReactNode {
  const root = useRef<HTMLElement>(null);
  useGSAP(
    () => {
      registerMarketingMotion();
      if (root.current) setupReveals(root.current);
    },
    { scope: root },
  );

  return (
    <section id="compare" className="relative px-5 pt-20 sm:px-8 sm:pt-24">
      <div className="mx-auto max-w-[1160px]">
        <div className="l1-reveal max-w-[46rem]">
          <h2 className="l1-h-section l1-engraved mt-5 text-[var(--l1-fg)]">
            Compare plans.
          </h2>
        </div>

        <div className="l1-reveal mt-9 overflow-hidden rounded-[var(--l1-r-lg)] border border-[var(--l1-steel)] bg-[var(--l1-panel)]/30">
          <div className="l1-scroll overflow-x-auto">
            <table className="w-full min-w-[900px] border-collapse">
              <thead>
                <tr className="border-b border-[var(--l1-steel)]">
                  <th className="px-6 py-5 text-left">
                    <span className="l1-label !text-[10px] text-[var(--l1-muted-2)]">
                      plan
                    </span>
                  </th>
                  {HEADERS.map((h) => (
                    <th
                      key={h}
                      className={
                        h === HIGHLIGHT
                          ? "border-l border-[var(--l1-steel-strong)] bg-[var(--l1-bg-2)] px-5 py-5 text-center"
                          : "border-l border-[var(--l1-steel)] px-5 py-5 text-center"
                      }
                    >
                      <span
                        className={
                          h === HIGHLIGHT
                            ? "l1-label !text-[11px] text-[var(--l1-fg)]"
                            : "l1-label !text-[11px] text-[var(--l1-muted)]"
                        }
                      >
                        {h}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ROWS.map((row) => (
                  <tr
                    key={row.label}
                    className="border-b border-[var(--l1-steel)] transition-colors last:border-0 hover:bg-[var(--l1-copper-faint)]"
                  >
                    <td className="px-6 py-4 text-[14px] text-[var(--l1-fg-dim)]">
                      {row.label}
                    </td>
                    {row.cols.map((col) => (
                      <td
                        key={col.id}
                        className={
                          isHighlightCol(col.id)
                            ? "border-l border-[var(--l1-steel-strong)] bg-[var(--l1-bg-2)]/60 px-5 py-4 text-center"
                            : "border-l border-[var(--l1-steel)] px-5 py-4 text-center"
                        }
                      >
                        <Cell value={col.value} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  );
}
