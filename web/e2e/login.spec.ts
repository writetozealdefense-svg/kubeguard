import { test, expect } from "@playwright/test";

// D3 acceptance: login via both modes + UI role gating, in a real browser.

test("local-admin login lands on the dashboard with admin nav", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByText("Sign in to KubeGuard")).toBeVisible();
  await page.getByRole("button", { name: "Continue as local admin" }).click();

  // Overview renders off the (mock) API and the admin-only Audit nav appears.
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Audit" })).toBeVisible();
  await expect(page.getByText(/of \d+ passed/)).toBeVisible(); // honest pass metric
});

test("a viewer (seeded session) does not see the admin-only Audit nav", async ({ page }) => {
  // Seed a viewer session before the app boots.
  await page.addInitScript(() => {
    localStorage.setItem(
      "kg.session",
      JSON.stringify({ user: "v", role: "viewer", tenant: "acme", token: "t" }),
    );
  });
  await page.goto("/");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Audit" })).toHaveCount(0);
});

test("SSO button appears only when OIDC is configured", async ({ page }) => {
  // Not configured in this build → no SSO button (local-admin only).
  await page.goto("/login");
  await expect(page.getByRole("button", { name: "Sign in with SSO" })).toHaveCount(0);
});
