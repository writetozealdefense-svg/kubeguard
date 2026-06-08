/** Provides the ApiClient to the tree so tests can inject a mock transport. */
import { createContext, useContext, type ReactNode } from "react";
import { ApiClient, api as defaultApi } from "@/lib/api/client";

const ApiContext = createContext<ApiClient>(defaultApi);

export function ApiProvider({ client, children }: { client: ApiClient; children: ReactNode }) {
  return <ApiContext.Provider value={client}>{children}</ApiContext.Provider>;
}

export function useApi(): ApiClient {
  return useContext(ApiContext);
}
