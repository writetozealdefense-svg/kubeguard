import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      "kg.session",
      JSON.stringify({ user: "admin", role: "admin", tenant: "default", token: "t" }),
    );
  });
});

test("Reports page exports a SARIF download", async ({ page }) => {
  await page.goto("/reports");
  await expect(page.getByText("Reports & export")).toBeVisible();
  await expect(page.getByText(/indicative-mapping disclaimer/)).toBeVisible();

  const downloadPromise = page.waitForEvent("download");
  await page.getByLabel("Export SARIF 2.1.0").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain(".sarif");
});

test("CSV export downloads", async ({ page }) => {
  await page.goto("/reports");
  const downloadPromise = page.waitForEvent("download");
  await page.getByLabel("Export Findings CSV").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain(".csv");
});
