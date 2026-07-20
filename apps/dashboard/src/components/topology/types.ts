import type { TopologyEdge, TopologyNode } from "@tunnet/api/management";
import type { Edge, Node } from "@xyflow/react";

export type MeshStatusFilter = "all" | "online" | "offline";
export type MeshKindFilter =
  | "all"
  | "machine"
  | "k8s"
  | "subnet"
  | "hostname"
  | "exit"
  | "relay"
  | "serve"
  | "tunnel";

export type OverviewMode = "topology" | "access";
export type AccessEntityTab = "peers" | "groups" | "tags";

export type AccessSourceSelection =
  | { kind: "peer"; endpointId: string; label: string; networkId: string }
  | { kind: "group"; networkId: string; label: string }
  | { kind: "tag"; tag: string; label: string }
  | null;

export type NetworkGroupNodeData = {
  networkId: string;
  name: string;
  cidr: string;
  totalPeers: number;
  onlinePeers: number;
  tunnelCount: number;
  serveCount: number;
  health: "online" | "degraded" | "empty";
};

export type PeerNodeData = {
  topology: TopologyNode;
  isGateway?: boolean;
};

export type ResourceNodeData = {
  topology: TopologyNode;
};

export type ServeSatelliteData = {
  serveId: string;
  label: string;
  secondary?: string;
  endpointId: string;
  networkId: string;
};

export type TunnelSatelliteData = {
  tunnelId: string;
  label: string;
  secondary?: string;
  endpointId: string;
  networkId: string;
  publicHostname?: string | null;
};

export type EnrollZoneData = {
  networkId: string;
  label: string;
};

export type AccessSourceNodeData = {
  role: "source";
  title: string;
  subtitle?: string;
  tags?: string[];
  online?: boolean;
};

export type AccessPolicyNodeData = {
  role: "policy";
  policyId: string;
  title: string;
  subtitle: string;
  action: "allow" | "deny";
  networkId: string | null;
};

export type AccessDestinationNodeData = {
  role: "destination";
  title: string;
  subtitle?: string;
  destKind: "peer" | "tag" | "network" | "cidr" | "any" | "serve" | "user";
  peerCount?: number;
};

export type TopologyNodeData =
  | NetworkGroupNodeData
  | PeerNodeData
  | ResourceNodeData
  | ServeSatelliteData
  | TunnelSatelliteData
  | EnrollZoneData
  | AccessSourceNodeData
  | AccessPolicyNodeData
  | AccessDestinationNodeData;

export type NetworkGroupFlowNode = Node<NetworkGroupNodeData, "networkGroup">;
export type PeerFlowNode = Node<PeerNodeData, "peer">;
export type GatewayFlowNode = Node<PeerNodeData, "gateway">;
export type K8sFlowNode = Node<PeerNodeData, "k8s">;
export type RelayFlowNode = Node<ResourceNodeData, "relay">;
export type SubnetFlowNode = Node<ResourceNodeData, "subnet">;
export type HostnameFlowNode = Node<ResourceNodeData, "hostname">;
export type ExitFlowNode = Node<ResourceNodeData, "exit">;
export type ServeFlowNode = Node<ServeSatelliteData, "serve">;
export type TunnelFlowNode = Node<TunnelSatelliteData, "tunnel">;
export type EnrollFlowNode = Node<EnrollZoneData, "enroll">;
export type AccessSourceFlowNode = Node<AccessSourceNodeData, "accessSource">;
export type AccessPolicyFlowNode = Node<AccessPolicyNodeData, "accessPolicy">;
export type AccessDestinationFlowNode = Node<
  AccessDestinationNodeData,
  "accessDestination"
>;

export type TopologyFlowNode =
  | NetworkGroupFlowNode
  | PeerFlowNode
  | GatewayFlowNode
  | K8sFlowNode
  | RelayFlowNode
  | SubnetFlowNode
  | HostnameFlowNode
  | ExitFlowNode
  | ServeFlowNode
  | TunnelFlowNode
  | EnrollFlowNode
  | AccessSourceFlowNode
  | AccessPolicyFlowNode
  | AccessDestinationFlowNode;

export type MeshEdgeData = {
  kind: TopologyEdge["kind"] | "subnetRoute" | "policy";
  intensity: number;
  latencyMs?: number | null;
  direct?: boolean;
  label?: string;
  highlighted?: boolean;
};

export type TopologyFlowEdge = Edge<MeshEdgeData>;

export type ConnectIntent =
  | {
      type: "policy";
      sourceEndpointId: string;
      targetEndpointId: string;
      sourceLabel: string;
      targetLabel: string;
      networkId: string;
    }
  | {
      type: "serve";
      endpointId: string;
      networkId: string;
    }
  | {
      type: "tunnel";
      endpointId: string;
      networkId: string;
    }
  | {
      type: "enroll";
      networkId: string;
    };

export type SelectedTopology =
  | { kind: "topology"; node: TopologyNode }
  | { kind: "serve"; data: ServeSatelliteData }
  | { kind: "tunnel"; data: TunnelSatelliteData }
  | { kind: "network"; data: NetworkGroupNodeData }
  | { kind: "accessPolicy"; data: AccessPolicyNodeData }
  | { kind: "accessDestination"; data: AccessDestinationNodeData }
  | null;
