/** Selected-cluster context — drives the cluster switcher and every lens query. */
import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

interface ClusterState {
  cluster: string | undefined;
  setCluster: (id: string | undefined) => void;
}

const ClusterContext = createContext<ClusterState | null>(null);

export function ClusterProvider({ children, initial }: { children: ReactNode; initial?: string }) {
  const [cluster, setCluster] = useState<string | undefined>(initial);
  const value = useMemo(() => ({ cluster, setCluster }), [cluster]);
  return <ClusterContext.Provider value={value}>{children}</ClusterContext.Provider>;
}

export function useCluster(): ClusterState {
  const ctx = useContext(ClusterContext);
  if (!ctx) throw new Error("useCluster must be used within ClusterProvider");
  return ctx;
}
