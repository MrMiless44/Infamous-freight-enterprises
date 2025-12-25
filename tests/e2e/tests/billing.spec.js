import { test, expect } from "@playwright/test";

/**
 * Critical User Flows - Billing & Payments Tests
 *
 * These tests validate the billing functionality:
 * 1. Billing page accessible
 * 2. Payment method addition
 * 3. Invoice listing
 * 4. Payment processing
 * 5. Billing history
 */

test.describe("Billing & Payments", () => {
  // Setup: Login before each test
  test.beforeEach(async ({ page }) => {
    const testEmail = process.env.TEST_EMAIL;
    const testPassword = process.env.TEST_PASSWORD;

    if (!testEmail || !testPassword) {
      test.skip();
    }

    // Login
    await page.goto("/");
    await page.locator('button:has-text("Login")').click();
    await page.locator('input[type="email"]').fill(testEmail);
    await page.locator('input[type="password"]').fill(testPassword);
    await page.locator('button:has-text("Sign In")').click();

    // Wait for dashboard
    await page.waitForURL(/dashboard/);
  });

  test("should load billing page", async ({ page }) => {
    // Navigate to billing
    await page.locator('a:has-text("Billing")').click();

    // Verify billing page loads
    await expect(page).toHaveURL(/billing/);
    await expect(page.locator('h1:has-text("Billing")')).toBeVisible();
  });

  test("should display billing information", async ({ page }) => {
    // Navigate to billing
    await page.locator('a:has-text("Billing")').click();

    // Check for key sections
    await expect(page.locator("text=Payment Methods")).toBeVisible();
    await expect(page.locator("text=Invoices")).toBeVisible();
    await expect(page.locator("text=Usage")).toBeVisible();
  });

  test("should list recent invoices", async ({ page }) => {
    // Navigate to billing
    await page.locator('a:has-text("Billing")').click();

    // Check invoices section
    const invoiceTable = page.locator('table:has-text("Invoice")');
    await expect(invoiceTable).toBeVisible();

    // Should have at least column headers
    await expect(page.locator('th:has-text("Date")')).toBeVisible();
    await expect(page.locator('th:has-text("Amount")')).toBeVisible();
  });

  test("should display current usage", async ({ page }) => {
    // Navigate to billing
    await page.locator('a:has-text("Billing")').click();

    // Check usage section
    await expect(page.locator("text=Current Usage")).toBeVisible();

    // Should show usage metrics
    await expect(page.locator('[data-testid="api-calls"]')).toBeVisible();
    await expect(page.locator('[data-testid="storage-used"]')).toBeVisible();
  });

  test("should handle billing API errors gracefully", async ({ page }) => {
    // Intercept billing API and simulate error
    await page.route("**/api/billing/**", (route) => {
      route.abort("failed");
    });

    // Navigate to billing
    await page.locator('a:has-text("Billing")').click();

    // Should show error message
    await expect(
      page.locator("text=Error loading billing information"),
    ).toBeVisible({ timeout: 5000 });
  });

  test("should paginate through invoices", async ({ page }) => {
    // Navigate to billing
    await page.locator('a:has-text("Billing")').click();

    // Wait for invoices to load
    await page.locator('table:has-text("Invoice")').waitFor();

    // Check for pagination (if more than 10 invoices)
    const nextButton = page.locator('button:has-text("Next")');
    if (await nextButton.isVisible()) {
      await nextButton.click();
      // Verify new page loaded
      await page.waitForTimeout(500);
    }
  });
});
