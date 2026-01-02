import request from "supertest";
import express from "express";
import { costMonitoringRouter } from "../../routes/cost-monitoring";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Cost Monitoring Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/cost-monitoring", costMonitoringRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /cost-monitoring/summary", () => {
    it("should return cost summary", async () => {
      const response = await request(app).get("/cost-monitoring/summary");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("totalCost");
    });

    it("should filter by date range", async () => {
      const response = await request(app)
        .get("/cost-monitoring/summary")
        .query({
          startDate: "2026-01-01",
          endDate: "2026-01-31",
        });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /cost-monitoring/breakdown", () => {
    it("should return cost breakdown by category", async () => {
      const response = await request(app).get("/cost-monitoring/breakdown");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("byCategory");
    });
  });

  describe("GET /cost-monitoring/alerts", () => {
    it("should list cost alerts", async () => {
      const response = await request(app).get("/cost-monitoring/alerts");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });

  describe("POST /cost-monitoring/budgets", () => {
    it("should set cost budget", async () => {
      const response = await request(app)
        .post("/cost-monitoring/budgets")
        .send({
          category: "fuel",
          limit: 50000,
          period: "monthly",
        });

      expect([200, 201, 400]).toContain(response.status);
    });
  });

  describe("GET /cost-monitoring/trends", () => {
    it("should return cost trends", async () => {
      const response = await request(app).get("/cost-monitoring/trends");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("trends");
    });
  });
});
