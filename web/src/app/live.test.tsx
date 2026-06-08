import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { ApiClient } from "@/lib/api/client";
import { mockTransport } from "@/lib/api/mock";
import { AppProviders, makeQueryClient } from "@/app/Providers";
import { makeRouter } from "@/router";
import type { Session } from "@/app/auth";

function renderApp(session: Session | null) {
  const client = new ApiClient(mockTransport, () => session?.token ?? null);
  const router = makeRouter(createMemoryHistory({ initialEntries: ["/"] }));
  return render(
    <AppProviders client={client} queryClient={makeQueryClient()} session={session}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
}

const admin: Session = { user: "admin", role: "admin", tenant: "default", token: "t" };
const viewer: Session = { user: "v", role: "viewer", tenant: "acme", token: "t" };

beforeEach(() => localStorage.clear());

describe("D5 live experience", () => {
  it("triggering a scan streams progress and settles back to Live (no reload)", async () => {
    renderApp(admin);
    // Live indicator connects.
    await waitFor(() => expect(screen.getByLabelText("live")).toBeInTheDocument());

    // Select a cluster so Scan now is enabled.
    const switcher = await screen.findByLabelText("Select cluster");
    await waitFor(() => expect(screen.getByRole("option", { name: "prod-eu" })).toBeInTheDocument());
    await userEvent.selectOptions(switcher, "prod-eu");

    // Trigger an on-demand scan.
    await userEvent.click(screen.getByRole("button", { name: "Scan now" }));

    // The SSE stream drives a live "Scanning…" status, then completes and the
    // lenses are invalidated — status returns to Live without any reload.
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/Scanning/));
    await waitFor(() => expect(screen.getByLabelText("live")).toBeInTheDocument(), { timeout: 3000 });
  });

  it("hides Scan now from a viewer (RBAC, UI gate)", async () => {
    renderApp(viewer);
    await waitFor(() => expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Scan now" })).not.toBeInTheDocument();
  });
});
