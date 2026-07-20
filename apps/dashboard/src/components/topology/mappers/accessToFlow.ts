import type {
  Device,
  Network,
  Policy,
  Selector,
  Serve,
  TagDefinition,
} from "@tunnet/api/management";
import { formatPolicySelector } from "@/components/app/policy-selector-fields";
import type {
  AccessSourceSelection,
  TopologyFlowEdge,
  TopologyFlowNode,
} from "@/components/topology/types";
import { getMachinePresence } from "@/lib/machine-utils";

function policyTitle(policy: Policy): string {
  if (policy.slug) return policy.slug;
  return `${formatPolicySelector(policy.srcSelector)} → ${formatPolicySelector(policy.dstSelector)}`;
}

function policySubtitle(policy: Policy): string {
  const proto = policy.protocol ?? "any";
  const ports =
    policy.ports.length === 0
      ? "All"
      : policy.ports
          .map((p) =>
            p.start === p.end ? `${p.start}` : `${p.start}-${p.end}`,
          )
          .join(", ");
  return `${policy.action.toUpperCase()} · ${String(proto).toUpperCase()}:${ports}`;
}

function selectorMatchesSource(
  selector: Selector,
  source: NonNullable<AccessSourceSelection>,
  machines: Device[],
): boolean {
  if (selector.kind === "any") return true;
  if (source.kind === "peer") {
    if (selector.kind === "endpoint") {
      return selector.value === source.endpointId;
    }
    if (selector.kind === "tag") {
      const machine = machines.find((m) => m.endpointId === source.endpointId);
      return Boolean(machine?.tags.includes(selector.value));
    }
    if (selector.kind === "network") {
      return (
        selector.value === source.networkId ||
        machines.some(
          (m) =>
            m.endpointId === source.endpointId &&
            m.networkId === selector.value,
        )
      );
    }
    return false;
  }
  if (source.kind === "tag") {
    if (selector.kind === "tag") return selector.value === source.tag;
    return false;
  }
  if (source.kind === "group") {
    if (selector.kind === "network") {
      return (
        selector.value === source.networkId || selector.value === source.label
      );
    }
    return false;
  }
  return false;
}

function resolveDestinations(
  selector: Selector,
  machines: Device[],
  networks: Network[],
  tags: TagDefinition[],
  serves: Serve[],
  now: number,
): Array<{
  id: string;
  title: string;
  subtitle?: string;
  destKind: "peer" | "tag" | "network" | "cidr" | "any" | "serve" | "user";
  peerCount?: number;
}> {
  if (selector.kind === "any") {
    return [
      {
        id: "dest:any",
        title: "Any",
        subtitle: "All peers / resources",
        destKind: "any",
        peerCount: machines.length,
      },
    ];
  }
  if (selector.kind === "endpoint") {
    const m = machines.find((x) => x.endpointId === selector.value);
    return [
      {
        id: `dest:ep:${selector.value}`,
        title: m?.hostname || selector.value.slice(0, 12),
        subtitle: m?.assignedIp ?? selector.value.slice(0, 16),
        destKind: "peer",
        peerCount: 1,
      },
    ];
  }
  if (selector.kind === "tag") {
    const matched = machines.filter((m) => m.tags.includes(selector.value));
    const def = tags.find((t) => t.name === selector.value);
    return [
      {
        id: `dest:tag:${selector.value}`,
        title: selector.value,
        subtitle: `${matched.length} peers · tag`,
        destKind: "tag",
        peerCount: def?.machineCount ?? matched.length,
      },
    ];
  }
  if (selector.kind === "network") {
    const net =
      networks.find((n) => n.id === selector.value) ??
      networks.find((n) => n.name === selector.value);
    const peers = machines.filter(
      (m) => m.networkId === net?.id || m.networkId === selector.value,
    );
    return [
      {
        id: `dest:net:${selector.value}`,
        title: net?.name ?? selector.value,
        subtitle: net?.cidr ?? "network",
        destKind: "network",
        peerCount: peers.length,
      },
    ];
  }
  if (selector.kind === "cidr") {
    return [
      {
        id: `dest:cidr:${selector.value}`,
        title: selector.value,
        subtitle: "CIDR",
        destKind: "cidr",
      },
    ];
  }
  if (selector.kind === "user") {
    return [
      {
        id: `dest:user:${selector.value}`,
        title: selector.value,
        subtitle: "user",
        destKind: "user",
      },
    ];
  }
  void serves;
  void now;
  return [];
}

const COL_SOURCE_X = 40;
const COL_POLICY_X = 320;
const COL_DEST_X = 620;
const ROW_H = 88;
const START_Y = 40;

export function accessToFlow(
  source: AccessSourceSelection,
  policies: Policy[],
  machines: Device[],
  networks: Network[],
  tags: TagDefinition[],
  serves: Serve[],
  now: number,
): { nodes: TopologyFlowNode[]; edges: TopologyFlowEdge[] } {
  if (!source) return { nodes: [], edges: [] };

  const nodes: TopologyFlowNode[] = [];
  const edges: TopologyFlowEdge[] = [];

  const sourceTitle = source.label;
  let sourceSubtitle: string | undefined;
  let sourceTags: string[] | undefined;
  let online: boolean | undefined;

  if (source.kind === "peer") {
    const m = machines.find((x) => x.endpointId === source.endpointId);
    sourceSubtitle = m?.assignedIp ?? source.endpointId.slice(0, 16);
    sourceTags = m?.tags;
    online = m ? getMachinePresence(m, now) === "online" : undefined;
  } else if (source.kind === "tag") {
    const matched = machines.filter((m) => m.tags.includes(source.tag));
    sourceSubtitle = `${matched.length} peers`;
  } else if (source.kind === "group") {
    const net = networks.find((n) => n.id === source.networkId);
    sourceSubtitle = net?.cidr;
  }

  nodes.push({
    id: "access:source",
    type: "accessSource",
    position: { x: COL_SOURCE_X, y: START_Y },
    data: {
      role: "source",
      title: sourceTitle,
      subtitle: sourceSubtitle,
      tags: sourceTags,
      online,
    },
    draggable: false,
  });

  const matching = policies.filter((p) =>
    selectorMatchesSource(p.srcSelector, source, machines),
  );

  const destIndex = new Map<string, number>();
  let policyRow = 0;

  for (const policy of matching) {
    const policyId = `access:policy:${policy.id}`;
    nodes.push({
      id: policyId,
      type: "accessPolicy",
      position: { x: COL_POLICY_X, y: START_Y + policyRow * ROW_H },
      data: {
        role: "policy",
        policyId: policy.id,
        title: policyTitle(policy),
        subtitle: policySubtitle(policy),
        action: policy.action,
        networkId: policy.networkId,
      },
      draggable: false,
    });

    edges.push({
      id: `e:src-${policy.id}`,
      source: "access:source",
      target: policyId,
      type: "policy",
      style: {
        stroke: policy.action === "allow" ? "#3b82f6" : "#ef4444",
        strokeWidth: 1.5,
      },
      data: {
        kind: "policy",
        intensity: 0.5,
        label: policy.action,
      },
    });

    const dests = resolveDestinations(
      policy.dstSelector,
      machines,
      networks,
      tags,
      serves,
      now,
    );

    for (const dest of dests) {
      if (!destIndex.has(dest.id)) {
        const idx = destIndex.size;
        destIndex.set(dest.id, idx);
        nodes.push({
          id: dest.id,
          type: "accessDestination",
          position: { x: COL_DEST_X, y: START_Y + idx * ROW_H },
          data: {
            role: "destination",
            title: dest.title,
            subtitle: dest.subtitle,
            destKind: dest.destKind,
            peerCount: dest.peerCount,
          },
          draggable: false,
        });
      }
      edges.push({
        id: `e:${policy.id}-${dest.id}`,
        source: policyId,
        target: dest.id,
        type: "policy",
        style: {
          stroke: policy.action === "allow" ? "#3b82f6" : "#ef4444",
          strokeWidth: 1.25,
          strokeDasharray: "4 3",
        },
        data: { kind: "policy", intensity: 0.4 },
      });
    }

    policyRow += 1;
  }

  return { nodes, edges };
}
