/** App shell: top bar (brand, tenant + cluster switcher, auth/role), left nav, outlet. */
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useApi } from "./apiContext";
import { useAuth } from "./auth";
import { useCluster } from "./cluster";
import { useScanStream } from "./useScanStream";
import { LiveStatus, ScanNowButton } from "@/components/LiveControls";

import type { Role } from "./auth";

const NAV: ReadonlyArray<{ to: string; label: string; minRole?: Role }> = [
  { to: "/", label: "Overview" },
  { to: "/findings", label: "Findings" },
  { to: "/compliance", label: "Compliance" },
  { to: "/attack-paths", label: "Attack Paths" },
  { to: "/clusters", label: "Clusters" },
  { to: "/history", label: "History" },
  { to: "/reports", label: "Reports" },
  { to: "/audit", label: "Audit", minRole: "admin" }, // admin-only (UI gate; server re-checks)
];

function ClusterSwitcher() {
  const apiClient = useApi();
  const { cluster, setCluster } = useCluster();
  const { data } = useQuery({ queryKey: ["clusters"], queryFn: () => apiClient.listClusters() });
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="text-fg-subtle">Cluster</span>
      <select
        aria-label="Select cluster"
        className="rounded-md border border-border bg-bg-raised px-2 py-1 text-fg"
        value={cluster ?? ""}
        onChange={(e) => setCluster(e.target.value || undefined)}
      >
        <option value="">All clusters</option>
        {data?.clusters.map((c) => (
          <option key={c.id} value={c.id}>{c.name}</option>
        ))}
      </select>
    </label>
  );
}

const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

export function Shell() {
  const { session, logout } = useAuth();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const role = session?.role ?? "viewer";
  // Role-gate nav items: a viewer never sees the admin-only Audit link.
  const navItems = NAV.filter((item) => !item.minRole || ROLE_RANK[role] >= ROLE_RANK[item.minRole]);
  // Live scan stream — drives the status pill and auto-refreshes the lenses.
  const live = useScanStream();

  return (
    <div className="min-h-screen bg-bg text-fg">
      <header className="flex items-center justify-between border-b border-border bg-bg-surface px-4 py-2">
        <div className="flex items-center gap-3">
          <span className="font-mono text-sm font-bold tracking-tight text-accent">KubeGuard</span>
          {session && (
            <span className="rounded bg-bg-raised px-2 py-0.5 text-xs text-fg-muted" aria-label="tenant">
              {session.tenant}
            </span>
          )}
        </div>
        <div className="flex items-center gap-4">
          {session && <LiveStatus live={live} />}
          {session && <ScanNowButton />}
          <ClusterSwitcher />
          {session ? (
            <div className="flex items-center gap-2 text-sm">
              <span className="text-fg-muted">{session.user}</span>
              <span className="rounded bg-bg-raised px-2 py-0.5 text-xs uppercase text-fg-subtle">{session.role}</span>
              <button className="text-fg-subtle hover:text-fg" onClick={logout}>Sign out</button>
            </div>
          ) : (
            <Link to="/login" className="text-sm text-accent">Sign in</Link>
          )}
        </div>
      </header>

      <div className="flex">
        <nav aria-label="Primary" className="w-48 shrink-0 border-r border-border bg-bg-surface p-2">
          <ul className="space-y-1">
            {navItems.map((item) => {
              const active = item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
              return (
                <li key={item.to}>
                  <Link
                    to={item.to}
                    className={`block rounded-md px-3 py-1.5 text-sm ${
                      active ? "bg-accent/15 text-accent" : "text-fg-muted hover:bg-bg-raised hover:text-fg"
                    }`}
                    aria-current={active ? "page" : undefined}
                  >
                    {item.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        <main className="flex-1 p-6" id="main-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
