import { test, expect } from "@playwright/test";

// Seed an admin session so the authenticated shell + all lenses render (mock mode).
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      "kg.session",
      JSON.stringify({ user: "admin", role: "admin", tenant: "default", token: "t" }),
    );
  });
});

test("Findings: row opens the detail drawer; severity filter narrows", async ({ page }) => {
  await page.goto("/findings");
  await expect(page.getByText("Privileged container")).toBeVisible();
  await page.getByText("Privileged container").click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByText(/Remediation/)).toBeVisible();
  await page.getByRole("button", { name: "Close" }).click();

  await page.getByRole("button", { name: "critical", exact: true }).click();
  await expect(page.getByText("RBAC allows reading Secrets")).toHaveCount(0);
});

test("Attack graph node is clickable and keyboard-accessible (React Flow)", async ({ page }) => {
  await page.goto("/attack-paths");
  await expect(page.getByText("Cluster-admin takeover via checkout")).toBeVisible();

  // Click a capability node → its ATT&CK technique appears in the detail panel.
  const escapeNode = page.getByRole("button", { name: /Capability ContainerEscape/ });
  await expect(escapeNode).toBeVisible();
  await escapeNode.click();
  await expect(page.getByText("T1611")).toBeVisible();

  // Keyboard: focus a different node and activate with Enter.
  const adminNode = page.getByRole("button", { name: /Capability ClusterAdmin/ });
  await adminNode.focus();
  await expect(adminNode).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByText("T1078")).toBeVisible();
});

test("Compliance: expands to the breached controls and dents", async ({ page }) => {
  await page.goto("/compliance");
  await page.getByRole("button", { name: /CIS Kubernetes Benchmark/ }).click();
  await expect(page.getByText(/Minimize privileged containers/)).toBeVisible();
  await expect(page.getByText(/KG-001 — view remediation/)).toBeVisible();
});

test("Clusters: fleet table drills into a cluster", async ({ page }) => {
  await page.goto("/clusters");
  await page.getByRole("row", { name: /prod-eu/ }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
});
