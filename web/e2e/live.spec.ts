import { test, expect } from "@playwright/test";

// D5: on-demand scan streams live progress and auto-updates the views (no reload).
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      "kg.session",
      JSON.stringify({ user: "admin", role: "admin", tenant: "default", token: "t" }),
    );
  });
});

test("Scan now streams live progress then returns to Live", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByLabel("live")).toBeVisible();

  // Pick a cluster, then trigger a scan.
  await page.getByLabel("Select cluster").selectOption("prod-eu");
  await page.getByRole("button", { name: "Scan now" }).click();

  // Live status shows the streamed progress, then settles back to Live —
  // all driven by SSE, no page reload.
  await expect(page.getByRole("status")).toContainText("Scanning", { timeout: 4000 });
  await expect(page.getByLabel("live")).toBeVisible({ timeout: 4000 });
});

test("viewer does not get a Scan now button", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("kg.session", JSON.stringify({ user: "v", role: "viewer", tenant: "acme", token: "t" }));
  });
  await page.goto("/");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Scan now" })).toHaveCount(0);
});
