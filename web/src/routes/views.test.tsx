import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { ApiClient } from "@/lib/api/client";
import { mockTransport } from "@/lib/api/mock";
import { AppProviders, makeQueryClient } from "@/app/Providers";
import { makeRouter } from "@/router";
import type { Session } from "@/app/auth";

const admin: Session = { user: "admin", role: "admin", tenant: "default", token: "t" };

function renderApp(initialPath: string) {
  const client = new ApiClient(mockTransport, () => "t");
  const router = makeRouter(createMemoryHistory({ initialEntries: [initialPath] }));
  return render(
    <AppProviders client={client} queryClient={makeQueryClient()} session={admin}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
}

beforeEach(() => localStorage.clear());

describe("D4 core views render real API data", () => {
  it("Findings: server-filtered table + detail drawer", async () => {
    renderApp("/findings");
    await waitFor(() => expect(screen.getByText("Privileged container")).toBeInTheDocument());
    // Open the detail drawer by clicking a row.
    await userEvent.click(screen.getByText("Privileged container"));
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText(/Remediation/)).toBeInTheDocument();
    expect(within(drawer).getByText(/secrets redacted/i)).toBeInTheDocument();
  });

  it("Findings: severity filter narrows the table", async () => {
    renderApp("/findings");
    await waitFor(() => expect(screen.getByText("RBAC allows reading Secrets")).toBeInTheDocument());
    // Filter to critical only — the high finding disappears.
    await userEvent.click(screen.getByRole("button", { name: "critical" }));
    await waitFor(() => expect(screen.queryByText("RBAC allows reading Secrets")).not.toBeInTheDocument());
    expect(screen.getByText("Privileged container")).toBeInTheDocument();
  });

  it("Compliance: expands to breached controls with the dents causing them", async () => {
    renderApp("/compliance");
    await waitFor(() => expect(screen.getByText("CIS Kubernetes Benchmark")).toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: /CIS Kubernetes Benchmark/ }));
    await waitFor(() => expect(screen.getByText(/Minimize privileged containers/)).toBeInTheDocument());
    expect(screen.getByText(/KG-001 — view remediation/)).toBeInTheDocument();
  });

  it("Clusters: fleet table lists both clusters", async () => {
    renderApp("/clusters");
    // "prod-eu" also appears in the header switcher, so scope to the fleet table.
    const table = await screen.findByRole("table");
    await waitFor(() => expect(within(table).getByText("prod-eu")).toBeInTheDocument());
    expect(within(table).getByText("staging-us")).toBeInTheDocument();
  });

  it("History: renders the drift diff (improved) between first and last scan", async () => {
    renderApp("/history");
    await waitFor(() => expect(screen.getByText("Drift between two scans")).toBeInTheDocument());
    // prod history improves over time → "Improved" + "control(s) fixed".
    expect(await screen.findByText("Improved")).toBeInTheDocument();
    expect(screen.getByLabelText("drift summary")).toHaveTextContent(/fixed/);
  });

  it("Attack Paths: renders the active path with its impact filter", async () => {
    renderApp("/attack-paths");
    await waitFor(() => expect(screen.getByText("Cluster-admin takeover via checkout")).toBeInTheDocument());
    expect(screen.getByLabelText("Filter by impact")).toBeInTheDocument();
  });

  it("Audit: admin sees the privileged-action log", async () => {
    renderApp("/audit");
    await waitFor(() => expect(screen.getByText("Audit log")).toBeInTheDocument());
    expect(await screen.findByText("scan.trigger")).toBeInTheDocument();
  });
});
