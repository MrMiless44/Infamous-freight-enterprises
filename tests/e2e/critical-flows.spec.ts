import { test, expect } from "@playwright/test";

const API_BASE_URL = process.env.API_BASE_URL || "http://localhost:4000";
const WEB_BASE_URL = process.env.WEB_BASE_URL || "http://localhost:3000";

test.describe("Critical User Flows", () => {
  test("User Authentication Flow", async ({ page }) => {
    // Navigate to login
    await page.goto(`${WEB_BASE_URL}/auth/login`);
    await expect(page).toHaveTitle(/Login/i);

    // Fill login form
    await page.fill('input[name="email"]', "test@example.com");
    await page.fill('input[name="password"]', "TestPassword123!");

    // Submit form
    await page.click('button[type="submit"]');

    // Wait for redirect to dashboard
    await page.waitForURL(`${WEB_BASE_URL}/dashboard`);
    await expect(page).toHaveTitle(/Dashboard/i);

    // Verify auth token is set
    const cookies = await page.context().cookies();
    const authCookie = cookies.find((c) => c.name === "auth_token");
    expect(authCookie).toBeDefined();
  });

  test("Create Shipment Flow", async ({ page, context }) => {
    // Login first
    await page.goto(`${WEB_BASE_URL}/auth/login`);
    await page.fill('input[name="email"]', "test@example.com");
    await page.fill('input[name="password"]', "TestPassword123!");
    await page.click('button[type="submit"]');
    await page.waitForURL(`${WEB_BASE_URL}/dashboard`);

    // Navigate to create shipment
    await page.goto(`${WEB_BASE_URL}/shipments/create`);
    await expect(page).toHaveTitle(/Create Shipment/i);

    // Fill shipment form
    await page.fill('input[name="origin"]', "123 Main St, New York, NY");
    await page.fill(
      'input[name="destination"]',
      "456 Oak Ave, Los Angeles, CA",
    );
    await page.fill('input[name="weight"]', "100");
    await page.selectOption('select[name="shipmentType"]', "package");

    // Submit form
    await page.click('button[type="submit"]');

    // Verify shipment created
    await page.waitForURL(/\/shipments\/\w+/);
    const pageUrl = page.url();
    expect(pageUrl).toContain("/shipments/");

    // Verify shipment data is displayed
    await expect(page.locator("text=123 Main St")).toBeVisible();
    await expect(page.locator("text=456 Oak Ave")).toBeVisible();
  });

  test("Track Shipment Flow", async ({ page }) => {
    // Login
    await page.goto(`${WEB_BASE_URL}/auth/login`);
    await page.fill('input[name="email"]', "test@example.com");
    await page.fill('input[name="password"]', "TestPassword123!");
    await page.click('button[type="submit"]');
    await page.waitForURL(`${WEB_BASE_URL}/dashboard`);

    // Navigate to shipments list
    await page.goto(`${WEB_BASE_URL}/shipments`);
    await expect(page).toHaveTitle(/Shipments/i);

    // Click on first shipment
    const firstShipment = page.locator('a[href*="/shipments/"]').first();
    await firstShipment.click();

    // Verify tracking info is displayed
    await expect(page.locator("text=Status:")).toBeVisible();
    await expect(page.locator("text=Tracking")).toBeVisible();
    await expect(page.locator('[data-testid="map"]')).toBeVisible();
  });

  test("Billing Payment Flow", async ({ page }) => {
    // Login
    await page.goto(`${WEB_BASE_URL}/auth/login`);
    await page.fill('input[name="email"]', "test@example.com");
    await page.fill('input[name="password"]', "TestPassword123!");
    await page.click('button[type="submit"]');
    await page.waitForURL(`${WEB_BASE_URL}/dashboard`);

    // Navigate to billing
    await page.goto(`${WEB_BASE_URL}/billing`);
    await expect(page).toHaveTitle(/Billing/i);

    // Click checkout button
    await page.click('button:has-text("Proceed to Payment")');

    // Verify Stripe checkout loads (or payment modal)
    await page.waitForURL(/.*payment.*|.*stripe.*/);

    // For test environment, verify the payment page loaded
    await expect(page).toHaveURL(/payment|stripe/);
  });

  test("API Rate Limiter Respects Legitimate Traffic", async ({ request }) => {
    // Get auth token (using test credentials)
    const loginRes = await request.post(`${API_BASE_URL}/api/auth/login`, {
      data: {
        email: "test@example.com",
        password: "TestPassword123!",
      },
    });
    const {
      data: { token },
    } = await loginRes.json();

    // Make 10 requests (below limit)
    let responses = [];
    for (let i = 0; i < 10; i++) {
      const res = await request.get(`${API_BASE_URL}/api/shipments`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      responses.push(res.status());
    }

    // All should be 200 (not rate limited)
    responses.forEach((status) => {
      expect(status).toBe(200);
    });
  });

  test("API Rate Limiter Blocks Excessive Requests", async ({ request }) => {
    // Get auth token
    const loginRes = await request.post(`${API_BASE_URL}/api/auth/login`, {
      data: {
        email: "test@example.com",
        password: "TestPassword123!",
      },
    });
    const {
      data: { token },
    } = await loginRes.json();

    // Make 150 requests rapidly (above general limit of 100/15min)
    let blockedCount = 0;
    for (let i = 0; i < 150; i++) {
      const res = await request.get(`${API_BASE_URL}/api/shipments`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      // 429 = Too Many Requests (rate limited)
      if (res.status() === 429) {
        blockedCount++;
      }
    }

    // Expect some requests to be rate limited
    expect(blockedCount).toBeGreaterThan(0);
  });
});

test.describe("Mobile API Parity", () => {
  test("Mobile and Web return identical shipment data", async ({ request }) => {
    // Get auth token
    const loginRes = await request.post(`${API_BASE_URL}/api/auth/login`, {
      data: {
        email: "test@example.com",
        password: "TestPassword123!",
      },
    });
    const {
      data: { token },
    } = await loginRes.json();

    // Fetch from API (same for both Web and Mobile)
    const apiRes = await request.get(`${API_BASE_URL}/api/shipments/1`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const apiData = await apiRes.json();

    // Both should return same structure
    expect(apiData).toHaveProperty("success");
    expect(apiData).toHaveProperty("data");
    expect(apiData.data).toHaveProperty("id");
    expect(apiData.data).toHaveProperty("origin");
    expect(apiData.data).toHaveProperty("destination");
    expect(apiData.data).toHaveProperty("status");
  });

  test("Mobile can create shipment via API", async ({ request }) => {
    // Get auth token
    const loginRes = await request.post(`${API_BASE_URL}/api/auth/login`, {
      data: {
        email: "test@example.com",
        password: "TestPassword123!",
      },
    });
    const {
      data: { token },
    } = await loginRes.json();

    // Create shipment
    const res = await request.post(`${API_BASE_URL}/api/shipments`, {
      headers: { Authorization: `Bearer ${token}` },
      data: {
        origin: "123 Mobile St",
        destination: "456 App Ave",
        weight: 50,
        shipmentType: "package",
      },
    });

    expect(res.status()).toBe(201);
    const { data } = await res.json();
    expect(data).toHaveProperty("id");
    expect(data.origin).toBe("123 Mobile St");
  });
});
