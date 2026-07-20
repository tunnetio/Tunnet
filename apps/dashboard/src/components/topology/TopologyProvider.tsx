import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";

import type {
  AccessEntityTab,
  AccessSourceSelection,
  ConnectIntent,
  MeshKindFilter,
  MeshStatusFilter,
  OverviewMode,
  SelectedTopology,
} from "@/components/topology/types";

type TopologyContextValue = {
  overviewMode: OverviewMode;
  setOverviewMode: (v: OverviewMode) => void;
  accessTab: AccessEntityTab;
  setAccessTab: (v: AccessEntityTab) => void;
  accessSource: AccessSourceSelection;
  setAccessSource: (v: AccessSourceSelection) => void;
  statusFilter: MeshStatusFilter;
  setStatusFilter: (v: MeshStatusFilter) => void;
  kindFilter: MeshKindFilter;
  setKindFilter: (v: MeshKindFilter) => void;
  heatmap: boolean;
  setHeatmap: (v: boolean) => void;
  searchQuery: string;
  setSearchQuery: (v: string) => void;
  selected: SelectedTopology;
  setSelected: (v: SelectedTopology) => void;
  connectIntent: ConnectIntent | null;
  setConnectIntent: (v: ConnectIntent | null) => void;
  highlightedPath: Set<string>;
  setHighlightedPath: (v: Set<string>) => void;
  pathPickMode: boolean;
  setPathPickMode: (v: boolean) => void;
  pathEndpoints: string[];
  setPathEndpoints: (v: string[]) => void;
  layoutNonce: number;
  requestRelayout: () => void;
};

const TopologyContext = createContext<TopologyContextValue | null>(null);

export function TopologyProvider({
  children,
  initialKind = "all",
}: {
  children: ReactNode;
  initialKind?: MeshKindFilter;
}) {
  const [overviewMode, setOverviewMode] = useState<OverviewMode>("topology");
  const [accessTab, setAccessTab] = useState<AccessEntityTab>("peers");
  const [accessSource, setAccessSource] = useState<AccessSourceSelection>(null);
  const [statusFilter, setStatusFilter] = useState<MeshStatusFilter>("all");
  const [kindFilter, setKindFilter] = useState<MeshKindFilter>(initialKind);
  const [heatmap, setHeatmap] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selected, setSelected] = useState<SelectedTopology>(null);
  const [connectIntent, setConnectIntent] = useState<ConnectIntent | null>(
    null,
  );
  const [highlightedPath, setHighlightedPath] = useState<Set<string>>(
    () => new Set(),
  );
  const [pathPickMode, setPathPickMode] = useState(false);
  const [pathEndpoints, setPathEndpoints] = useState<string[]>([]);
  const [layoutNonce, setLayoutNonce] = useState(0);

  const requestRelayout = useCallback(() => {
    setLayoutNonce((n) => n + 1);
  }, []);

  const value = useMemo(
    () => ({
      overviewMode,
      setOverviewMode,
      accessTab,
      setAccessTab,
      accessSource,
      setAccessSource,
      statusFilter,
      setStatusFilter,
      kindFilter,
      setKindFilter,
      heatmap,
      setHeatmap,
      searchQuery,
      setSearchQuery,
      selected,
      setSelected,
      connectIntent,
      setConnectIntent,
      highlightedPath,
      setHighlightedPath,
      pathPickMode,
      setPathPickMode,
      pathEndpoints,
      setPathEndpoints,
      layoutNonce,
      requestRelayout,
    }),
    [
      overviewMode,
      accessTab,
      accessSource,
      statusFilter,
      kindFilter,
      heatmap,
      searchQuery,
      selected,
      connectIntent,
      highlightedPath,
      pathPickMode,
      pathEndpoints,
      layoutNonce,
      requestRelayout,
    ],
  );

  return (
    <TopologyContext.Provider value={value}>
      {children}
    </TopologyContext.Provider>
  );
}

export function useTopologyUi() {
  const ctx = useContext(TopologyContext);
  if (!ctx) {
    throw new Error("useTopologyUi must be used within TopologyProvider");
  }
  return ctx;
}
