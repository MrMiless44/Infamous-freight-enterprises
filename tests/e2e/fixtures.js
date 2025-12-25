import { test as base } from "@playwright/test";

/**
 * Fixtures for E2E tests
 * Provides authenticated browser context for tests that need login
 */

export const test = base.extend({
  // Fixture: authenticatedPage - returns logged-in browser context
  authenticatedPage: async ({ page }, use) => {
    const testEmail = process.env.TEST_EMAIL;
    const testPassword = process.env.TEST_PASSWORD;

    if (!testEmail || !testPassword) {
      throw new Error(
        "TEST_EMAIL and TEST_PASSWORD environment variables are required",
      );
    }

    // Navigate to login
    await page.goto("/");
    await page.locator('button:has-text("Login")').click();

    // Login
    await page.locator('input[type="email"]').fill(testEmail);
    await page.locator('input[type="password"]').fill(testPassword);
    await page.locator('button:has-text("Sign In")').click();

    // Wait for dashboard
    await page.waitForURL(/dashboard/);

    // Use the authenticated page
    await use(page);

    // Cleanup: logout
    try {
      await page.locator('button[aria-label="User menu"]').click();
      await page.locator('button:has-text("Logout")').click();
      await page.waitForURL(/login/);
    } catch {
      // Logout might fail, but that's ok for cleanup
    }
  },

  // Fixture: api - helper for API calls within tests
  api: async ({ page }, use) => {
    const apiHelper = {
      // Helper to make authenticated API calls
      async call(method, endpoint, body = null) {
        const response = await page.request[method.toLowerCase()](
          `${process.env.BASE_URL || "http://localhost:3000"}/api${endpoint}`,
          {
            headers: {
              "Content-Type": "application/json",
            },
            data: body ? JSON.stringify(body) : undefined,
          },
        );
        return response.json();
      },

      // Get request
      get: (endpoint) => apiHelper.call("GET", endpoint),

      // Post request
      post: (endpoint, body) => apiHelper.call("POST", endpoint, body),

      // Put request
      put: (endpoint, body) => apiHelper.call("PUT", endpoint, body),

      // Delete request
      delete: (endpoint) => apiHelper.call("DELETE", endpoint),
    };

    await use(apiHelper);
  },
});

export { expect } from "@playwright/test";
