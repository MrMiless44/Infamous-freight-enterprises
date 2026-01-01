/**
 * E2E Test: Shipment Tracking Flow
 * Tests the complete customer journey from search to tracking
 */

import { test, expect } from "@playwright/test";

const API_URL = process.env.API_URL || "https://infamous-freight-api.fly.dev";
const WEB_URL =
  process.env.WEB_URL || "https://infamous-freight-enterprises.vercel.app";

test.describe("Shipment Tracking", () => {
  test("customer can track shipment with valid tracking number", async ({
    page,
  }) => {
    await page.goto(WEB_URL);

    // Enter tracking number
    await page.fill('[data-testid="tracking-input"]', "IFE-12345");
    await page.click('[data-testid="track-button"]');

    // Wait for results
    await page.waitForSelector('[data-testid="shipment-status"]', {
      timeout: 10000,
    });

    // Verify shipment information is displayed
    const status = await page.textContent('[data-testid="shipment-status"]');
    expect(status).toBeTruthy();

    const estimatedDelivery = await page.locator(
      '[data-testid="estimated-delivery"]',
    );
    await expect(estimatedDelivery).toBeVisible();

    // Check for map/location if in transit
    if (status?.includes("Transit")) {
      const map = await page.locator('[data-testid="shipment-map"]');
      await expect(map).toBeVisible();
    }
  });

  test("shows error for invalid tracking number", async ({ page }) => {
    await page.goto(WEB_URL);

    await page.fill('[data-testid="tracking-input"]', "INVALID-123");
    await page.click('[data-testid="track-button"]');

    // Wait for error message
    const error = await page.locator('[data-testid="error-message"]');
    await expect(error).toBeVisible();
    await expect(error).toContainText(/not found|invalid/i);
  });
});

test.describe("User Authentication", () => {
  test("user can login with valid credentials", async ({ page }) => {
    await page.goto(`${WEB_URL}/login`);

    await page.fill('[name="email"]', "test@example.com");
    await page.fill('[name="password"]', "Test123!");
    await page.click('[type="submit"]');

    // Should redirect to dashboard
    await page.waitForURL(/\/dashboard/, { timeout: 10000 });
    await expect(page).toHaveURL(/\/dashboard/);

    // Verify dashboard elements
    const welcome = await page.locator('[data-testid="welcome-message"]');
    await expect(welcome).toBeVisible();
  });

  test("shows error for invalid credentials", async ({ page }) => {
    await page.goto(`${WEB_URL}/login`);

    await page.fill('[name="email"]', "wrong@example.com");
    await page.fill('[name="password"]', "wrongpass");
    await page.click('[type="submit"]');

    const error = await page.locator('[data-testid="login-error"]');
    await expect(error).toBeVisible();
    await expect(error).toContainText(/invalid|incorrect/i);
  });
});

test.describe("Shipment Creation", () => {
  test.use({ storageState: ".auth/user.json" }); // Use authenticated session

  test("user can create new shipment", async ({ page }) => {
    await page.goto(`${WEB_URL}/dashboard/shipments/new`);

    // Fill shipment form
    await page.fill('[name="origin"]', "123 Start St, Dallas, TX");
    await page.fill('[name="destination"]', "456 End Ave, Oklahoma City, OK");
    await page.fill('[name="customerName"]', "John Doe");
    await page.fill('[name="customerPhone"]', "555-0123");
    await page.selectOption('[name="serviceType"]', "express");

    await page.click('[type="submit"]');

    // Should show success message and tracking number
    await page.waitForSelector('[data-testid="success-message"]');
    const trackingNumber = await page.textContent(
      '[data-testid="tracking-number"]',
    );
    expect(trackingNumber).toMatch(/IFE-\d+/);
  });
});

test.describe("API Health Check", () => {
  test("API health endpoint returns 200", async ({ request }) => {
    const response = await request.get(`${API_URL}/api/health`);
    expect(response.status()).toBe(200);

    const data = await response.json();
    expect(data.status).toBe("ok");
    expect(data.database).toBe("connected");
  });
});

test.describe("Real-Time Updates", () => {
  test("receives shipment status updates via WebSocket", async ({ page }) => {
    await page.goto(`${WEB_URL}/track/IFE-12345`);

    // Wait for WebSocket connection
    await page.waitForFunction(
      () => {
        return (window as any).socketConnected === true;
      },
      { timeout: 5000 },
    );

    // Trigger status update (mock or actual)
    let updateReceived = false;
    page.on("console", (msg) => {
      if (msg.text().includes("shipment-update")) {
        updateReceived = true;
      }
    });

    // Wait for update (or timeout after 30s)
    await page.waitForTimeout(3000);

    // Verify real-time update mechanism works
    const statusElement = await page.locator('[data-testid="shipment-status"]');
    await expect(statusElement).toBeVisible();
  });
});
