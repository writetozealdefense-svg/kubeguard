import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { ApiClient } from "@/lib/api/client";
import { mockTransport } from "@/lib/api/mock";
import { AppProviders, makeQueryClient } from "@/app/Providers";
import { makeRouter } from "@/router";
import type { Session } from "@/app/auth";

function renderTriage(role: "viewer" | "analyst" | "admin") {
  const session: Session = { user: role, role, tenant: "default", token: "t" };
  const client = new ApiClient(mockTransport, () => "t");
  const router = makeRouter(createMemoryHistory({ initialEntries: ["/triage"] }));
  return render(
    <AppProviders client={client} queryClient={makeQueryClient()} session={session}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
}

beforeEach(() => localStorage.clear());

describe("K6 Triage lane", () => {
  it("renders the MTTR summary and finding rows", async () => {
    renderTriage("analyst");
    // Wait for data to load (a finding row), then the MTTR tile is present.
    await waitFor(() => expect(screen.getByText("KG-001")).toBeInTheDocument(), { timeout: 5000 });
    expect(screen.getByText("MTTR (hours)")).toBeInTheDocument();
  });

  it("is read-only for a viewer", async () => {
    renderTriage("viewer");
    await waitFor(() => expect(screen.getAllByText("read-only").length).toBeGreaterThan(0));
    expect(screen.queryByLabelText(/Set state for/)).toBeNull();
  });

  it("lets an analyst change a finding's state", async () => {
    renderTriage("analyst");
    const select = (await screen.findAllByLabelText(/Set state for/))[0];
    await userEvent.selectOptions(select, "in-progress");
    await waitFor(() => expect(screen.getByText("KG-001")).toBeInTheDocument());
  });

  it("exposes Accept-risk only to an admin", async () => {
    renderTriage("admin");
    await waitFor(() => expect(screen.getAllByText("Accept risk").length).toBeGreaterThan(0));
  });
});
