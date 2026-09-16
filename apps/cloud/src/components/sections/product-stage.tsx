import { PointerHighlight } from "@tunnet/ui/components/ui/pointer-highlight";
import { cn } from "@tunnet/ui/lib/utils";
import {
  GlobeIcon,
  KeyRoundIcon,
  NetworkIcon,
  ShareIcon,
  TerminalSquareIcon,
} from "lucide-react";
import { type ReactNode, useState } from "react";
import { FaGithub } from "react-icons/fa6";
import {
  type ConsoleKind,
  ConsolePreview,
} from "#/components/visuals/console-preview";

const APP_URL = "https://app.tunnet.io";

type Job = {
  id: ConsoleKind;
  label: string;
  blurb: string;
  title: string;
  highlight: string;
  points: string[];
  overlay: { title: string; rows: [string, string][] };
  cta: string;
  icon: typeof NetworkIcon;
};

const JOBS: Job[] = [
  {
    id: "mesh",
    label: "Remote access",
    blurb: "Every laptop, server, and CI runner on one overlay.",
    title: "A private network for every machine you already run",
    highlight: "every machine",
    points: [
      "A private IP and hostname as soon as a machine joins",
      "Direct paths first, relay when a firewall gets in the way",
      "Same app on macOS, Linux, and Windows",
      "Works from a coffee shop or a locked-down VPC",
    ],
    overlay: {
      title: "Mesh",
      rows: [
        ["Peers", "Online"],
        ["Path", "Direct"],
        ["DNS", "ori-mbp.mesh"],
        ["Relay", "Idle"],
      ],
    },
    cta: "Connect machines",
    icon: NetworkIcon,
  },
  {
    id: "serve",
    label: "Internal apps",
    blurb: "HTTPS for Grafana, admin UIs, and APIs. No VPN client dance.",
    title: "Expose a local port to the mesh with TLS from your org CA",
    highlight: "your org CA",
    points: [
      "One command: tunnet serve 3000",
      "ACLs decide who reaches it",
      "No public bind, no extra reverse proxy",
      "Same identity as SSH and tunnels",
    ],
    overlay: {
      title: "Serve",
      rows: [
        ["Host", "grafana.mesh"],
        ["TLS", "Org CA"],
        ["ACL", "role:ops"],
        ["Port", "3000"],
      ],
    },
    cta: "Publish an app",
    icon: ShareIcon,
  },
  {
    id: "tunnel",
    label: "Public HTTPS",
    blurb: "Webhooks, demos, and customer URLs on edges you can run.",
    title: "Give any local port a public URL Keep the origin private",
    highlight: "public URL",
    points: [
      "tunnet tunnel 3000 returns HTTPS immediately",
      "Bring your own edge, DNS, and certs",
      "ACME out of the box, BYO cert supported",
      "Pin a region, drain without dropping identity",
    ],
    overlay: {
      title: "Tunnel",
      rows: [
        ["URL", "demo.tunnet.io"],
        ["Cert", "ACME"],
        ["Edge", "sfo"],
        ["Origin", "Private"],
      ],
    },
    cta: "Open a tunnel",
    icon: GlobeIcon,
  },
  {
    id: "ssh",
    label: "Identity SSH",
    blurb: "ssh db-prod by name. No keys to copy, rotate, or leak.",
    title: "SSH follows the person not a file on disk",
    highlight: "the person",
    points: [
      "tunnet ssh db-prod uses your Tunnet identity",
      "Record and replay sessions by policy",
      "Re-auth by role when it matters",
      "No bastion to maintain",
    ],
    overlay: {
      title: "SSH",
      rows: [
        ["Target", "db-prod"],
        ["Auth", "Identity"],
        ["Record", "On"],
        ["Bastion", "None"],
      ],
    },
    cta: "SSH by identity",
    icon: TerminalSquareIcon,
  },
  {
    id: "policy",
    label: "One policy",
    blurb: "Mesh, serve, tunnel, and SSH share one ACL system.",
    title: "Write policy once It follows every connection",
    highlight: "once",
    points: [
      "SSO and OIDC on the managed control plane",
      "Policy as code in Git, or the dashboard",
      "Tags, groups, and posture on the same engine",
      "Audit on sessions, tunnels, and file sends",
    ],
    overlay: {
      title: "Policy",
      rows: [
        ["SSO", "OIDC"],
        ["Source", "Git"],
        ["Posture", "Required"],
        ["Audit", "On"],
      ],
    },
    cta: "Start for free",
    icon: KeyRoundIcon,
  },
];

function renderTitleWithHighlight(job: Job): ReactNode[] {
  const parts = job.title.split(job.highlight);
  const nodes: ReactNode[] = [];
  let position = 0;

  for (const [partIndex, part] of parts.entries()) {
    nodes.push(<span key={`${job.id}-text-${position}`}>{part}</span>);
    position += part.length;

    if (partIndex < parts.length - 1) {
      nodes.push(
        <PointerHighlight
          key={`${job.id}-highlight-${position}`}
          rectangleClassName="border-[var(--l1-fg)] bg-[var(--l1-copper-soft)]"
          pointerClassName="text-[var(--l1-fg)]"
        >
          <span>{job.highlight}</span>
        </PointerHighlight>,
      );
      position += job.highlight.length;
    }
  }

  return nodes;
}

export function ProductStage(): ReactNode {
  const [active, setActive] = useState(0);
  const job = JOBS[active] ?? JOBS[0];

  return (
    <section id="product" className="relative px-4 pb-6 sm:px-6">
      <div className="mx-auto flex max-w-[820px] flex-col items-center pt-14 text-center sm:pt-20">
        <h1 className="text-[clamp(2.5rem,6.2vw,4.7rem)] leading-[1.04] font-semibold tracking-[-0.045em] text-[var(--l1-fg)] text-balance">
          Private networking for every machine you run
        </h1>
        <p className="mt-6 max-w-[40rem] text-[17px] leading-relaxed text-[var(--l1-muted)] sm:text-[19px]">
          Connect laptops, servers, and CI on one private network. SSH by name,
          share internal apps, and publish HTTPS - without a VPN or a bastion.
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <a href={APP_URL} className="l1-btn l1-btn--copper">
            Start for free
          </a>
          <a href="mailto:sales@tunnet.io" className="l1-btn l1-btn--ghost">
            Book a demo
          </a>
        </div>
        <a
          href="https://github.com/tunnetio/Tunnet"
          target="_blank"
          rel="noreferrer"
          className="mt-5 inline-flex items-center gap-2 text-[13px] font-medium text-[var(--l1-fg-dim)] hover:text-[var(--l1-fg)]"
        >
          <FaGithub className="size-4" />
          Open source on GitHub
        </a>
      </div>

      <div className="mx-auto mt-10 grid max-w-[1120px] gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {JOBS.map((item, i) => {
          const Icon = item.icon;
          const selected = i === active;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActive(i)}
              className={cn(
                "rounded-2xl border p-4 text-left transition-colors",
                selected
                  ? "border-transparent bg-[var(--l1-fg)] text-[var(--primary-foreground)]"
                  : "border-[var(--l1-steel)] bg-[var(--l1-panel)] text-[var(--l1-fg)] hover:border-[var(--l1-steel-strong)]",
              )}
            >
              <Icon className="size-4 opacity-80" />
              <p className="mt-3 text-[14px] font-semibold tracking-tight">
                {item.label}
              </p>
              <p
                className={cn(
                  "mt-1 text-[12.5px] leading-snug",
                  selected
                    ? "text-[var(--l1-on-fg-muted)]"
                    : "text-[var(--l1-muted)]",
                )}
              >
                {item.blurb}
              </p>
            </button>
          );
        })}
      </div>

      <div className="mx-auto mt-3 max-w-[1120px] overflow-hidden rounded-[28px] bg-[var(--l1-bg-2)] px-5 py-8 sm:px-8 sm:py-12 lg:px-12">
        <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.15fr)]">
          <div>
            <h2 className="max-w-[18ch] text-[clamp(1.85rem,3.4vw,2.75rem)] leading-[1.08] font-semibold tracking-[-0.04em] text-[var(--l1-fg)]">
              {renderTitleWithHighlight(job)}
            </h2>
            <ul className="mt-6 flex flex-col gap-2.5">
              {job.points.map((point) => (
                <li
                  key={point}
                  className="flex gap-2.5 text-[14.5px] leading-snug text-[var(--l1-fg-dim)]"
                >
                  <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-[var(--l1-fg)]" />
                  {point}
                </li>
              ))}
            </ul>
            <a href={APP_URL} className="l1-btn l1-btn--copper mt-8">
              {job.cta}
            </a>
          </div>

          <div className="relative">
            {/* Drop /public/product/control-plane.png here when a real dashboard screenshot is ready. */}
            <div className="overflow-hidden rounded-[22px] border-[6px] border-[#2a2b2e] bg-[#2a2b2e] shadow-[0_40px_80px_-36px_rgba(20,22,26,0.55)]">
              <div className="flex h-7 items-center gap-1.5 bg-[#2a2b2e] px-3">
                <span className="size-2 rounded-full bg-white/20" />
                <span className="size-2 rounded-full bg-white/20" />
                <span className="size-2 rounded-full bg-white/20" />
              </div>
              <div className="overflow-hidden rounded-[14px] bg-[var(--l1-panel)]">
                <ConsolePreview kind={job.id} />
              </div>
            </div>

            <aside className="relative mt-4 w-full rounded-2xl border border-black/8 bg-white p-4 shadow-[0_18px_50px_-24px_rgba(20,22,26,0.45)] lg:absolute lg:top-6 lg:right-0 lg:mt-0 lg:w-[17.5rem] lg:-right-3 dark:border-white/10 dark:bg-[#1b1c1f]">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[13px] font-semibold tracking-tight">
                  {job.overlay.title}
                </p>
                <span className="flex items-center gap-1.5 text-[11px] text-[var(--l1-muted)]">
                  <span className="size-1.5 rounded-full bg-emerald-600" />
                  Live demo
                </span>
              </div>
              <dl className="mt-3 flex flex-col gap-2">
                {job.overlay.rows.map(([k, v]) => (
                  <div
                    key={k}
                    className="flex items-center justify-between border-t border-black/6 pt-2 text-[12px] dark:border-white/8"
                  >
                    <dt className="text-[var(--l1-muted)]">{k}</dt>
                    <dd className="flex items-center gap-1.5 font-medium">
                      <span className="size-1.5 rounded-full bg-emerald-600" />
                      {v}
                    </dd>
                  </div>
                ))}
              </dl>
            </aside>
          </div>
        </div>
      </div>
    </section>
  );
}
