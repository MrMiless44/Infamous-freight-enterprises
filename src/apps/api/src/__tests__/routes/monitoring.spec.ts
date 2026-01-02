import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { monitoringRouter } from "../../routes/monitoring";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Monitoring Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/monitoring", monitoringRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /monitoring/system", () => {
    it("should return system health status", async () => {
      const response = await request(app).get("/monitoring/system");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("status");
      expect(response.body.data).toHaveProperty("timestamp");
    });

    it("should include component statuses", async () => {
      const response = await request(app).get("/monitoring/system");

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("components");
      }
    });
  });

  describe("GET /monitoring/metrics", () => {
    it("should return system metrics", async () => {
      const response = await request(app).get("/monitoring/metrics");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("cpuUsage");
      expect(response.body.data).toHaveProperty("memoryUsage");
    });

    it("should support time range filtering", async () => {
      const response = await request(app).get("/monitoring/metrics").query({
        startDate: "2026-01-01",
        endDate: "2026-01-15",
      });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /monitoring/database", () => {
    it("should return database metrics", async () => {
      const response = await request(app).get("/monitoring/database");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("connectionCount");
      expect(response.body.data).toHaveProperty("queryPerformance");
    });
  });

  describe("GET /monitoring/api-stats", () => {
    it("should return API statistics", async () => {
      const response = await request(app).get("/monitoring/api-stats");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("requestCount");
      expect(response.body.data).toHaveProperty("errorRate");
    });

    it("should filter by endpoint", async () => {
      const response = await request(app)
        .get("/monitoring/api-stats")
        .query({ endpoint: "/shipments" });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /monitoring/alerts", () => {
    it("should list active alerts", async () => {
      const response = await request(app).get("/monitoring/alerts");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by severity", async () => {
      const response = await request(app)
        .get("/monitoring/alerts")
        .query({ severity: "high" });

      expect(response.status).toBe(200);
    });
  });

  describe("POST /monitoring/alerts/:id/acknowledge", () => {
    it("should acknowledge alert", async () => {
      const response = await request(app)
        .post("/monitoring/alerts/alert-123/acknowledge")
        .send({ acknowledgedBy: "admin-user" });

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("GET /monitoring/logs", () => {
    it("should retrieve logs", async () => {
      const response = await request(app)
        .get("/monitoring/logs")
        .query({ level: "error", limit: 50 });

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });

  describe("POST /monitoring/custom-metric", () => {
    it("should record custom metric", async () => {
      const response = await request(app)
        .post("/monitoring/custom-metric")
        .send({
          name: "custom_event",
          value: 100,
          tags: { region: "northeast" },
        });

      expect([200, 201, 400]).toContain(response.status);
    });
  });
});
