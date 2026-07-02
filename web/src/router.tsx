/** Code-based TanStack Router route tree. */
import {
  createRootRoute,
  createRoute,
  createRouter,
  type RouterHistory,
} from "@tanstack/react-router";
import { Shell } from "@/app/Shell";
import { Overview } from "@/routes/Overview";
import { Login } from "@/routes/Login";
import { AuthCallback } from "@/routes/AuthCallback";
import { Findings } from "@/routes/Findings";
import { Triage } from "@/routes/Triage";
import { Compliance } from "@/routes/Compliance";
import { AttackPaths } from "@/routes/AttackPaths";
import { Clusters } from "@/routes/Clusters";
import { History } from "@/routes/History";
import { Reports } from "@/routes/Reports";
import { Audit } from "@/routes/Audit";

const rootRoute = createRootRoute({ component: Shell });

const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: Overview });
const findingsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/findings", component: Findings });
const triageRoute = createRoute({ getParentRoute: () => rootRoute, path: "/triage", component: Triage });
const complianceRoute = createRoute({ getParentRoute: () => rootRoute, path: "/compliance", component: Compliance });
const attackPathsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/attack-paths", component: AttackPaths });
const clustersRoute = createRoute({ getParentRoute: () => rootRoute, path: "/clusters", component: Clusters });
const historyRoute = createRoute({ getParentRoute: () => rootRoute, path: "/history", component: History });
const reportsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/reports", component: Reports });
const auditRoute = createRoute({ getParentRoute: () => rootRoute, path: "/audit", component: Audit });
const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "/login", component: Login });
const callbackRoute = createRoute({ getParentRoute: () => rootRoute, path: "/auth/callback", component: AuthCallback });

const routeTree = rootRoute.addChildren([
  indexRoute,
  findingsRoute,
  triageRoute,
  complianceRoute,
  attackPathsRoute,
  clustersRoute,
  historyRoute,
  reportsRoute,
  auditRoute,
  loginRoute,
  callbackRoute,
]);

export function makeRouter(history?: RouterHistory) {
  return createRouter({ routeTree, history });
}

// Type registration for TanStack Router (exported so it isn't flagged unused).
export const router = makeRouter();
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
