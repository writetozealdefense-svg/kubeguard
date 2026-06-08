import { render, screen, waitFor } from "@testing-library/react";
import { RouterProvider } from "@tanstack/react-router";
import { createMemoryHistory } from "@tanstack/react-router";
import { describe, expect, it } from "vitest";
import { ApiClient } from "@/lib/api/client";
import { mockTransport } from "@/lib/api/mock";
import { AppProviders, makeQueryClient } from "@/app/Providers";
import { makeRouter } from "@/router";
import type { Session } from "@/app/auth";

function renderApp(initialPath = "/") {
  const client = new ApiClient(mockTransport, () => "t");
  const queryClient = makeQueryClient();
  const router = makeRouter(createMemoryHistory({ initialEntries: [initialPath] }));
  const session: Session = { user: "admin", role: "admin", tenant: "default", token: "t" };
  return render(
    <AppProviders client={client} queryClient={queryClient} session={session}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
}

describe("Shell + Overview (renders with mocked API)", () => {
  it("renders the brand, primary nav, and auth-aware header", async () => {
    renderApp();
    // RouterProvider mounts asynchronously; wait for the shell to paint.
    await waitFor(() => expect(screen.getByText("KubeGuard")).toBeInTheDocument());
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    expect(screen.getByText("Sign out")).toBeInTheDocument();
    // tenant chip
    expect(screen.getByLabelText("tenant")).toHaveTextContent("default");
  });

  it("populates the cluster switcher from the API", async () => {
    renderApp();
    await waitFor(() => expect(screen.getByRole("option", { name: "prod-eu" })).toBeInTheDocument());
  });

  it("renders Overview posture with honest, denominator-carrying metrics", async () => {
    renderApp();
    // Severity cards
    await waitFor(() => expect(screen.getByText("Total findings")).toBeInTheDocument());
    expect(screen.getByText("Overall control pass")).toBeInTheDocument();
    // Honest pass label includes the assessed denominator, not a bare %.
    expect(screen.getByText(/of \d+ passed/)).toBeInTheDocument();
    // Indicative-mapping disclaimer present.
    expect(screen.getByText(/indicative control mapping/i)).toBeInTheDocument();
  });

  it("routes to a D4-stub view", async () => {
    renderApp("/findings");
    await waitFor(() => expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument());
  });
});
