import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "@/lib/api/client";
import { mockTransport } from "@/lib/api/mock";
import { AppProviders, makeQueryClient } from "@/app/Providers";
import { makeRouter } from "@/router";
import type { Session } from "@/app/auth";

const admin: Session = { user: "admin", role: "admin", tenant: "default", token: "t" };

function renderReports() {
  const client = new ApiClient(mockTransport, () => "t");
  const router = makeRouter(createMemoryHistory({ initialEntries: ["/reports"] }));
  return render(
    <AppProviders client={client} queryClient={makeQueryClient()} session={admin}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
}

beforeEach(() => {
  localStorage.clear();
  // jsdom lacks URL.createObjectURL / Blob.text streaming for downloads.
  globalThis.URL.createObjectURL = vi.fn(() => "blob:mock");
  globalThis.URL.revokeObjectURL = vi.fn();
});

describe("downloadReport client", () => {
  it("carries the token and parses the filename from Content-Disposition", async () => {
    let auth: string | null = null;
    const client = new ApiClient(async (_path, init) => {
      auth = (init?.headers as Record<string, string>)?.Authorization ?? null;
      return new Response("data", { status: 200, headers: { "Content-Disposition": 'attachment; filename="prod-eu-report.pdf"' } });
    }, () => "tok");
    const { filename } = await client.downloadReport("pdf", "prod-eu");
    expect(auth).toBe("Bearer tok");
    expect(filename).toBe("prod-eu-report.pdf");
  });
});

describe("Reports view", () => {
  it("offers PDF, CSV and SARIF exports with the honest-metrics note", async () => {
    renderReports();
    await waitFor(() => expect(screen.getByText("Reports & export")).toBeInTheDocument());
    expect(screen.getByText("Co-branded PDF")).toBeInTheDocument();
    expect(screen.getByText("Findings CSV")).toBeInTheDocument();
    expect(screen.getByText("SARIF 2.1.0")).toBeInTheDocument();
    expect(screen.getByText(/indicative-mapping disclaimer/i)).toBeInTheDocument();
  });

  it("downloads a report when an export button is clicked", async () => {
    renderReports();
    const createUrl = globalThis.URL.createObjectURL as ReturnType<typeof vi.fn>;
    await waitFor(() => expect(screen.getByLabelText("Export SARIF 2.1.0")).toBeInTheDocument());
    await userEvent.click(screen.getByLabelText("Export SARIF 2.1.0"));
    await waitFor(() => expect(createUrl).toHaveBeenCalled());
  });
});
