/**
 * Load Testing Script (k6)
 * Tests API performance under various load conditions
 *
 * Run: k6 run tests/load/api-load.js
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";

// Custom metrics
const errorRate = new Rate("errors");
const apiDuration = new Trend("api_duration");
const requestCount = new Counter("request_count");

// Test configuration
export const options = {
  stages: [
    { duration: "30s", target: 20 }, // Ramp up to 20 users
    { duration: "1m", target: 50 }, // Ramp up to 50 users
    { duration: "2m", target: 100 }, // Ramp up to 100 users
    { duration: "2m", target: 100 }, // Stay at 100 users
    { duration: "1m", target: 50 }, // Ramp down to 50
    { duration: "30s", target: 0 }, // Ramp down to 0
  ],
  thresholds: {
    http_req_duration: ["p(95)<500", "p(99)<1000"], // 95% < 500ms, 99% < 1s
    http_req_failed: ["rate<0.01"], // Error rate < 1%
    errors: ["rate<0.05"], // Custom error rate < 5%
  },
};

const API_URL = __ENV.API_URL || "https://infamous-freight-api.fly.dev";
const AUTH_TOKEN = __ENV.AUTH_TOKEN || "";

// Setup function (runs once per VU)
export function setup() {
  // Get auth token if not provided
  if (!AUTH_TOKEN) {
    console.warn("No AUTH_TOKEN provided, some tests will fail");
  }
  return { token: AUTH_TOKEN };
}

// Main test function
export default function (data) {
  const headers = {
    "Content-Type": "application/json",
    ...(data.token && { Authorization: `Bearer ${data.token}` }),
  };

  // Test 1: Health check
  group("Health Check", () => {
    const res = http.get(`${API_URL}/api/health`);

    check(res, {
      "health check status is 200": (r) => r.status === 200,
      "health check response time < 200ms": (r) => r.timings.duration < 200,
      "database is connected": (r) => {
        const body = JSON.parse(r.body);
        return body.database === "connected";
      },
    });

    apiDuration.add(res.timings.duration);
    requestCount.add(1);
    errorRate.add(res.status !== 200);
  });

  sleep(1);

  // Test 2: List shipments (authenticated)
  if (data.token) {
    group("List Shipments", () => {
      const res = http.get(`${API_URL}/api/shipments`, { headers });

      check(res, {
        "list shipments status is 200": (r) => r.status === 200,
        "list shipments response time < 500ms": (r) => r.timings.duration < 500,
        "returns array of shipments": (r) => {
          const body = JSON.parse(r.body);
          return Array.isArray(body.data);
        },
      });

      apiDuration.add(res.timings.duration);
      requestCount.add(1);
      errorRate.add(res.status !== 200);
    });
  }

  sleep(1);

  // Test 3: Search shipment by tracking number
  group("Track Shipment", () => {
    const trackingNumber = "IFE-12345";
    const res = http.get(`${API_URL}/api/shipments/track/${trackingNumber}`, {
      headers,
    });

    check(res, {
      "track shipment status is 200 or 404": (r) =>
        [200, 404].includes(r.status),
      "track shipment response time < 300ms": (r) => r.timings.duration < 300,
    });

    apiDuration.add(res.timings.duration);
    requestCount.add(1);
    errorRate.add(![200, 404].includes(res.status));
  });

  sleep(2);

  // Test 4: Create shipment (authenticated, POST)
  if (data.token) {
    group("Create Shipment", () => {
      const payload = JSON.stringify({
        origin: "123 Test St, Dallas, TX",
        destination: "456 Demo Ave, Oklahoma City, OK",
        customerName: "Load Test User",
        customerPhone: "555-0000",
        serviceType: "standard",
      });

      const res = http.post(`${API_URL}/api/shipments`, payload, { headers });

      check(res, {
        "create shipment status is 201": (r) => r.status === 201,
        "create shipment response time < 1000ms": (r) =>
          r.timings.duration < 1000,
        "returns tracking number": (r) => {
          const body = JSON.parse(r.body);
          return body.data?.trackingNumber !== undefined;
        },
      });

      apiDuration.add(res.timings.duration);
      requestCount.add(1);
      errorRate.add(res.status !== 201);
    });
  }

  sleep(1);

  // Test 5: AI decision endpoint (if available)
  if (data.token) {
    group("AI Decision", () => {
      const payload = JSON.stringify({
        invoiceId: "test-invoice-" + Math.random().toString(36).substring(7),
        amount: Math.floor(Math.random() * 10000),
        vendor: "Test Vendor",
      });

      const res = http.post(`${API_URL}/api/ai/decision`, payload, { headers });

      check(res, {
        "AI decision status is 200 or 429": (r) =>
          [200, 429].includes(r.status),
        "AI decision response time < 2000ms": (r) => r.timings.duration < 2000,
      });

      apiDuration.add(res.timings.duration);
      requestCount.add(1);
      errorRate.add(![200, 429].includes(res.status));
    });
  }

  sleep(3);
}

// Teardown function
export function teardown(data) {
  console.log("Load test complete");
  console.log(`Total requests: ${requestCount.value}`);
}
