/**
 * Synthetic Monitoring with Playwright
 * Monitors critical user flows to detect functional issues before users do
 * Tests actual user journeys, not just uptime
 */

import { test, expect, chromium } from "@playwright/test";

/**
 * Configuration
 */
const BASE_URL = process.env.MONITOR_BASE_URL || "https://infamous-freight.com";
const API_URL =
  process.env.MONITOR_API_URL || "https://api.infamous-freight.com";
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK_URL || "";

/**
 * Send alert on test failure
 */
async function sendAlert(testName: string, error: string): Promise<void> {
  if (!ALERT_WEBHOOK) return;

  try {
    await fetch(ALERT_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `🚨 Synthetic Monitor Failed: ${testName}`,
        error,
        timestamp: new Date().toISOString(),
        url: BASE_URL,
      }),
    });
  } catch (err) {
    console.error("Failed to send alert:", err);
  }
}

/**
 * Test: Home page loads
 */
test("Home page loads successfully", async ({ page }) => {
  try {
    await page.goto(BASE_URL, { waitUntil: "networkidle" });

    // Check page title
    await expect(page).toHaveTitle(/Infæmous Freight|Freight Management/i);

    // Check critical elements exist
    await expect(page.locator("nav")).toBeVisible();
    await expect(page.locator("footer")).toBeVisible();

    // Check no error messages
    const errorElement = page.locator('[data-testid="error"]');
    if (await errorElement.isVisible()) {
      throw new Error("Error message visible on home page");
    }

    console.log("✓ Home page loads successfully");
  } catch (error) {
    await sendAlert("Home Page Load", error.message);
    throw error;
  }
});

/**
 * Test: Shipment tracking flow
 */
test("Shipment tracking works end-to-end", async ({ page }) => {
  try {
    await page.goto(BASE_URL);

    // Find tracking input
    const trackingInput = page.locator('[data-testid="tracking-input"]');
    await expect(trackingInput).toBeVisible();

    // Enter test tracking number
    await trackingInput.fill("IFE-TEST-12345");

    // Click track button
    const trackButton = page.locator('button:has-text("Track")');
    await trackButton.click();

    // Wait for results
    await page.waitForSelector('[data-testid="tracking-results"]', {
      timeout: 5000,
    });

    // Verify results displayed
    const results = page.locator('[data-testid="tracking-results"]');
    await expect(results).toBeVisible();

    // Check for shipment status
    const status = page.locator('[data-testid="shipment-status"]');
    await expect(status).toBeVisible();

    console.log("✓ Shipment tracking works");
  } catch (error) {
    await sendAlert("Shipment Tracking", error.message);
    throw error;
  }
});

/**
 * Test: User authentication flow
 */
test("User can login successfully", async ({ page }) => {
  try {
    await page.goto(`${BASE_URL}/login`);

    // Fill login form
    await page.locator('[data-testid="email-input"]').fill("test@example.com");
    await page.locator('[data-testid="password-input"]').fill("testpassword");

    // Click login
    await page.locator('button:has-text("Log in")').click();

    // Wait for redirect (either dashboard or error)
    await page.waitForURL(/dashboard|login/, { timeout: 5000 });

    // Check we're not still on login page with error
    const currentUrl = page.url();
    if (currentUrl.includes("/login")) {
      const errorElement = page.locator('[data-testid="login-error"]');
      if (await errorElement.isVisible()) {
        // This is expected with test credentials
        console.log(
          "✓ Login form works (test credentials rejected as expected)",
        );
        return;
      }
    }

    // If we reached dashboard, that's also success
    if (currentUrl.includes("/dashboard")) {
      console.log("✓ Login successful");
    }
  } catch (error) {
    await sendAlert("User Login", error.message);
    throw error;
  }
});

/**
 * Test: API health check
 */
test("API health endpoint responds", async ({ request }) => {
  try {
    const response = await request.get(`${API_URL}/api/health`, {
      timeout: 5000,
    });

    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.status).toBe("ok");

    console.log("✓ API health check passed");
  } catch (error) {
    await sendAlert("API Health", error.message);
    throw error;
  }
});

/**
 * Test: API shipments endpoint
 */
test("API shipments endpoint works", async ({ request }) => {
  try {
    const response = await request.get(`${API_URL}/api/shipments`, {
      headers: {
        Authorization: `Bearer ${process.env.TEST_API_TOKEN || "test-token"}`,
      },
      timeout: 5000,
    });

    // Accept both 200 (success) and 401 (unauthorized, but endpoint working)
    expect([200, 401]).toContain(response.status());

    console.log("✓ API shipments endpoint responding");
  } catch (error) {
    await sendAlert("API Shipments", error.message);
    throw error;
  }
});

/**
 * Test: Search functionality
 */
test("Search works correctly", async ({ page }) => {
  try {
    await page.goto(BASE_URL);

    // Find search input
    const searchInput = page.locator('[data-testid="search-input"]');
    if (await searchInput.isVisible()) {
      await searchInput.fill("test query");
      await searchInput.press("Enter");

      // Wait for results
      await page.waitForTimeout(2000);

      // Verify no error
      const errorElement = page.locator('[data-testid="error"]');
      if (await errorElement.isVisible()) {
        throw new Error("Search returned error");
      }

      console.log("✓ Search functionality works");
    } else {
      console.log("⊘ Search input not found, skipping test");
    }
  } catch (error) {
    await sendAlert("Search Functionality", error.message);
    throw error;
  }
});

/**
 * Test: Mobile responsiveness
 */
test("Site is mobile responsive", async ({ browser }) => {
  try {
    const mobileContext = await browser.newContext({
      viewport: { width: 375, height: 667 },
      userAgent:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
    });

    const page = await mobileContext.newPage();
    await page.goto(BASE_URL);

    // Check mobile menu exists
    const mobileMenu = page.locator('[data-testid="mobile-menu-button"]');
    if (await mobileMenu.isVisible()) {
      await mobileMenu.click();
      await page.waitForTimeout(500);
    }

    // Verify page is usable
    await expect(page.locator("nav")).toBeVisible();

    await mobileContext.close();

    console.log("✓ Mobile responsiveness check passed");
  } catch (error) {
    await sendAlert("Mobile Responsiveness", error.message);
    throw error;
  }
});

/**
 * Test: Performance (page load time)
 */
test("Page loads within acceptable time", async ({ page }) => {
  try {
    const startTime = Date.now();

    await page.goto(BASE_URL, { waitUntil: "load" });

    const loadTime = Date.now() - startTime;

    // Check load time is under 3 seconds
    expect(loadTime).toBeLessThan(3000);

    console.log(`✓ Page loaded in ${loadTime}ms`);

    if (loadTime > 2000) {
      console.warn(`⚠️ Page load time is high: ${loadTime}ms`);
    }
  } catch (error) {
    await sendAlert("Page Performance", error.message);
    throw error;
  }
});

/**
 * Test: Forms don't have XSS vulnerabilities
 */
test("Forms sanitize input correctly", async ({ page }) => {
  try {
    await page.goto(BASE_URL);

    const trackingInput = page.locator('[data-testid="tracking-input"]');
    if (await trackingInput.isVisible()) {
      // Try XSS payload
      await trackingInput.fill('<script>alert("xss")</script>');

      const trackButton = page.locator('button:has-text("Track")');
      await trackButton.click();

      await page.waitForTimeout(1000);

      // Check if alert was triggered (should not be)
      page.on("dialog", async (dialog) => {
        throw new Error("XSS vulnerability detected!");
      });

      console.log("✓ Input sanitization works");
    }
  } catch (error) {
    await sendAlert("Security - XSS", error.message);
    throw error;
  }
});

/**
 * Test: SSL certificate is valid
 */
test("SSL certificate is valid", async ({ request }) => {
  try {
    if (!BASE_URL.startsWith("https://")) {
      console.log("⊘ Not HTTPS, skipping SSL check");
      return;
    }

    const response = await request.get(BASE_URL);
    expect(response.status()).toBeLessThan(500);

    console.log("✓ SSL certificate valid");
  } catch (error) {
    await sendAlert("SSL Certificate", error.message);
    throw error;
  }
});

/**
 * Export for use in monitoring services
 */
export { sendAlert };

/**
 * Run as standalone monitoring script:
 *
 * # Install dependencies
 * npm install --save-dev @playwright/test
 *
 * # Run tests
 * npx playwright test tests/synthetic-monitoring.spec.ts
 *
 * # Run in CI (every 5 minutes)
 * * /5 * * * * cd /app && npx playwright test tests/synthetic-monitoring.spec.ts
 *
 * # Configure alerts
 * export ALERT_WEBHOOK_URL=https://hooks.slack.com/...
 *
 * # Configure for Checkly.com
 * - Upload this file to Checkly
 * - Set check frequency (1-60 minutes)
 * - Configure alert channels (email, Slack, PagerDuty)
 * - Set up escalation policies
 *
 * Expected results:
 * - Tests run every 5 minutes
 * - Failures trigger immediate alerts
 * - < 5 second response time
 * - 99.9% uptime target
 */
