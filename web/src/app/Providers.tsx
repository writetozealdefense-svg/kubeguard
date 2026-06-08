/** Composes the app-wide providers. Tests reuse this with injected props. */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { useMemo, type ReactNode } from "react";
import { ApiClient } from "@/lib/api/client";
import { mockTransport } from "@/lib/api/mock";
import { ApiProvider } from "./apiContext";
import { AuthProvider, loadSession, type Session } from "./auth";
import { ClusterProvider } from "./cluster";
import { makeRouter } from "@/router";

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  });
}

export function AppProviders({
  client,
  queryClient,
  session,
  children,
}: {
  client: ApiClient;
  queryClient: QueryClient;
  session?: Session | null;
  children: ReactNode;
}) {
  return (
    <QueryClientProvider client={queryClient}>
      <ApiProvider client={client}>
        <AuthProvider initial={session ?? null}>
          <ClusterProvider>{children}</ClusterProvider>
        </AuthProvider>
      </ApiProvider>
    </QueryClientProvider>
  );
}

/** Production composition: real router + API client that carries the persisted
 * session token (fresh on every call, so it tracks login/logout). */
export function App() {
  const queryClient = useMemo(makeQueryClient, []);
  const router = useMemo(() => makeRouter(), []);
  // VITE_USE_MOCK lets e2e/dev run the UI off the in-memory fixtures (no backend).
  const useMock = import.meta.env.VITE_USE_MOCK === "1";
  const client = useMemo(
    () => new ApiClient(useMock ? mockTransport : undefined, () => loadSession()?.token ?? null),
    [useMock],
  );
  return (
    <AppProviders client={client} queryClient={queryClient} session={loadSession()}>
      <RouterProvider router={router} />
    </AppProviders>
  );
}
