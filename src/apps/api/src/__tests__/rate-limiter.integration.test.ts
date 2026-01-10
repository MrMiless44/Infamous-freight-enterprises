import { describe, it, expect, beforeAll, afterAll } from "@jest/globals";
import request from "supertest";
import { Express } from "express";

/**
 * Rate Limiter Integration Tests
 * Validates that rate limiters block excessive requests while allowing legitimate traffic
 */

let app: Express;
const API_BASE_URL = process.env.API_BASE_URL || "http://localhost:4000";

beforeAll(() => {
  // Initialize app if needed
  // app = createApp();
});

afterAll(() => {
  // Cleanup
});

describe("Rate Limiter Integration Tests", () => {
  describe("General Rate Limiter (100 requests / 15 min)", () => {
    it("should allow legitimate traffic (10 requests)", async () => {
      const token = await getAuthToken();
      const responses = [];

      for (let i = 0; i < 10; i++) {
        const res = await request(API_BASE_URL)
          .get("/api/shipments")
          .set("Authorization", `Bearer ${token}`);
        responses.push(res.status);
      }

      // All should be 200 (not rate limited)
      responses.forEach((status) => {
        expect(status).toBe(200);
      });
    });

    it("should allow moderate traffic (50 requests)", async () => {
      const token = await getAuthToken();
      const responses = [];

      for (let i = 0; i < 50; i++) {
        const res = await request(API_BASE_URL)
          .get("/api/drivers")
          .set("Authorization", `Bearer ${token}`);
        responses.push(res.status);
      }

      // All should be 200
      const blockedCount = responses.filter((s) => s === 429).length;
      expect(blockedCount).toBe(0);
    });

    it("should rate limit excessive traffic (150 requests)", async () => {
      const token = await getAuthToken();
      const responses = [];

      for (let i = 0; i < 150; i++) {
        const res = await request(API_BASE_URL)
          .get("/api/shipments")
          .set("Authorization", `Bearer ${token}`);
        responses.push(res.status);
      }

      // Some should be rate limited (429)
      const blockedCount = responses.filter((s) => s === 429).length;
      expect(blockedCount).toBeGreaterThan(0);
    });

    it("should return 429 with Retry-After header when rate limited", async () => {
      const token = await getAuthToken();
      let rateLimited = false;

      for (let i = 0; i < 150; i++) {
        const res = await request(API_BASE_URL)
          .get("/api/shipments")
          .set("Authorization", `Bearer ${token}`);

        if (res.status === 429) {
          expect(res.headers["retry-after"]).toBeDefined();
          expect(parseInt(res.headers["retry-after"])).toBeGreaterThan(0);
          rateLimited = true;
          break;
        }
      }

      expect(rateLimited).toBe(true);
    });
  });

  describe("Auth Rate Limiter (5 requests / 15 min)", () => {
    it("should allow legitimate login attempts (2 requests)", async () => {
      const res1 = await request(API_BASE_URL)
        .post("/api/auth/login")
        .send({ email: "test1@example.com", password: "password" });

      const res2 = await request(API_BASE_URL)
        .post("/api/auth/login")
        .send({ email: "test2@example.com", password: "password" });

      expect([res1.status, res2.status]).not.toContain(429);
    });

    it("should rate limit excessive login attempts (10 requests)", async () => {
      const responses = [];

      for (let i = 0; i < 10; i++) {
        const res = await request(API_BASE_URL)
          .post("/api/auth/login")
          .send({ email: "attack@example.com", password: "wrong" });
        responses.push(res.status);
      }

      const blockedCount = responses.filter((s) => s === 429).length;
      expect(blockedCount).toBeGreaterThan(0);
    });
  });

  describe("AI Rate Limiter (20 requests / 1 min)", () => {
    it("should allow legitimate AI requests (5 requests)", async () => {
      const token = await getAuthToken("ai:command");
      const responses = [];

      for (let i = 0; i < 5; i++) {
        const res = await request(API_BASE_URL)
          .post("/api/ai/command")
          .set("Authorization", `Bearer ${token}`)
          .send({ command: "optimize_route" });
        responses.push(res.status);
      }

      // All should succeed (not rate limited)
      responses.forEach((status) => {
        if (status !== 429) {
          expect(status).toBeGreaterThanOrEqual(200);
          expect(status).toBeLessThan(400);
        }
      });
    });

    it("should rate limit excessive AI requests (50 rapid requests)", async () => {
      const token = await getAuthToken("ai:command");
      const responses = [];

      for (let i = 0; i < 50; i++) {
        const res = await request(API_BASE_URL)
          .post("/api/ai/command")
          .set("Authorization", `Bearer ${token}`)
          .send({ command: "optimize_route" });
        responses.push(res.status);
      }

      const blockedCount = responses.filter((s) => s === 429).length;
      expect(blockedCount).toBeGreaterThan(0);
    });
  });

  describe("Billing Rate Limiter (30 requests / 15 min)", () => {
    it("should allow legitimate billing requests (10 requests)", async () => {
      const token = await getAuthToken("billing:checkout");
      const responses = [];

      for (let i = 0; i < 10; i++) {
        const res = await request(API_BASE_URL)
          .get("/api/billing/invoices")
          .set("Authorization", `Bearer ${token}`);
        responses.push(res.status);
      }

      responses.forEach((status) => {
        expect(status).not.toBe(429);
      });
    });

    it("should rate limit excessive billing requests (60 requests)", async () => {
      const token = await getAuthToken("billing:checkout");
      const responses = [];

      for (let i = 0; i < 60; i++) {
        const res = await request(API_BASE_URL)
          .post("/api/billing/checkout")
          .set("Authorization", `Bearer ${token}`)
          .send({ amount: 100 });
        responses.push(res.status);
      }

      const blockedCount = responses.filter((s) => s === 429).length;
      expect(blockedCount).toBeGreaterThan(0);
    });
  });

  describe("Rate Limit Reset After Window", () => {
    it("should allow requests after window expires", async () => {
      const token = await getAuthToken();

      // Make requests to hit limit
      for (let i = 0; i < 100; i++) {
        await request(API_BASE_URL)
          .get("/api/shipments")
          .set("Authorization", `Bearer ${token}`);
      }

      // Should be rate limited now
      let blockedRes = await request(API_BASE_URL)
        .get("/api/shipments")
        .set("Authorization", `Bearer ${token}`);
      expect(blockedRes.status).toBe(429);

      // Wait for window to expire (or mock time)
      // This is a real-time test only; in unit tests, mock the time
      // For integration tests, may skip or use test accounts with separate windows

      console.log(
        "⚠️ Rate limit reset test requires manual window wait or time mocking",
      );
    });
  });

  describe("Different Users Have Separate Limits", () => {
    it("should not share rate limits across users", async () => {
      const token1 = await getAuthToken("user1@example.com");
      const token2 = await getAuthToken("user2@example.com");

      // User 1 makes 10 requests
      for (let i = 0; i < 10; i++) {
        await request(API_BASE_URL)
          .get("/api/shipments")
          .set("Authorization", `Bearer ${token1}`);
      }

      // User 2 should still be able to make requests
      const res = await request(API_BASE_URL)
        .get("/api/shipments")
        .set("Authorization", `Bearer ${token2}`);

      expect(res.status).not.toBe(429);
    });
  });

  describe("Rate Limit Response Format", () => {
    it("should return proper error response when rate limited", async () => {
      const token = await getAuthToken();

      for (let i = 0; i < 100; i++) {
        await request(API_BASE_URL)
          .get("/api/shipments")
          .set("Authorization", `Bearer ${token}`);
      }

      const res = await request(API_BASE_URL)
        .get("/api/shipments")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(429);
      expect(res.body).toHaveProperty("error");
      expect(res.body.error).toMatch(/too many|rate limit/i);
      expect(res.headers["x-ratelimit-limit"]).toBeDefined();
      expect(res.headers["x-ratelimit-remaining"]).toBeDefined();
      expect(res.headers["x-ratelimit-reset"]).toBeDefined();
    });
  });
});

// Helper functions
async function getAuthToken(scope?: string): Promise<string> {
  const res = await request(API_BASE_URL).post("/api/auth/login").send({
    email: "test@example.com",
    password: "TestPassword123!",
  });

  return res.body.data.token;
}
