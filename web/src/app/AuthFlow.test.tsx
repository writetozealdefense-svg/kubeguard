import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "@/lib/api/client";
import { mockTransport } from "@/lib/api/mock";
import { AppProviders, makeQueryClient } from "@/app/Providers";
import { makeRouter } from "@/router";
import type { Session } from "@/app/auth";

function renderApp(initialPath: string, session: Session | null) {
  const client = new ApiClient(mockTransport, () => session?.token ?? null);
  const router = makeRouter(createMemoryHistory({ initialEntries: [initialPath] }));
  return render(
    <AppProviders client={client} queryClient={makeQueryClient()} session={session}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
}

beforeEach(() => localStorage.clear());

describe("login flow + UI role gating (D3)", () => {
  it("local-admin login lands on the dashboard with the admin-only Audit nav", async () => {
    renderApp("/login", null);
    await waitFor(() => expect(screen.getByText("Continue as local admin")).toBeInTheDocument());
    await userEvent.click(screen.getByText("Continue as local admin"));
    // Routed to Overview, and as admin the Audit nav link is visible.
    await waitFor(() => expect(screen.getByRole("link", { name: "Audit" })).toBeInTheDocument());
  });

  it("a viewer never sees the admin-only Audit nav link", async () => {
    const viewer: Session = { user: "v", role: "viewer", tenant: "acme", token: "t" };
    renderApp("/", viewer);
    await waitFor(() => expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument());
    expect(screen.queryByRole("link", { name: "Audit" })).not.toBeInTheDocument();
  });

  it("shows the SSO button when OIDC is configured", async () => {
    vi.stubEnv("VITE_OIDC_AUTHORIZE_URL", "https://idp.example.com/authorize");
    renderApp("/login", null);
    await waitFor(() => expect(screen.getByRole("button", { name: "Sign in with SSO" })).toBeInTheDocument());
    vi.unstubAllEnvs();
  });
});
