/**
 * Health Routes Tests
 * Tests for API health check endpoints
 */

import request from "supertest";
import express from "express";
import { healthRouter } from "../../routes/health";

describe("Health Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use("/api", healthRouter);
  });

  describe("GET /api/health", () => {
    it("should return 200 OK with health status", async () => {
      const response = await request(app).get("/api/health");

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("status");
      expect(response.body).toHaveProperty("timestamp");
      expect(response.body).toHaveProperty("uptime");
    });

    it("should indicate database connection status", async () => {
      const response = await request(app).get("/api/health");

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("database");
    });
  });

  describe("GET /api/health/detailed", () => {
    it("should return detailed health information", async () => {
      const response = await request(app).get("/api/health/detailed");

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("database");
      expect(response.body).toHaveProperty("redis");
      expect(response.body).toHaveProperty("uptime");
      expect(response.body).toHaveProperty("memory");
      expect(response.body).toHaveProperty("cpu");
    });

    it("should include version information", async () => {
      const response = await request(app).get("/api/health/detailed");

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("version");
      expect(response.body).toHaveProperty("nodeVersion");
    });
  });

  describe("Health check response times", () => {
    it("should respond quickly to health checks", async () => {
      const start = Date.now();
      await request(app).get("/api/health");
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(100); // Should respond in less than 100ms
    });
  });
});
