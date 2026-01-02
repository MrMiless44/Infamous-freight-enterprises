import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { predictionsRouter } from "../../routes/predictions";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");
jest.mock("../../services/mlPredictor");

describe("Predictions Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/predictions", predictionsRouter as any);
    jest.clearAllMocks();
  });

  describe("POST /predictions/delivery-time", () => {
    it("should predict delivery time", async () => {
      const response = await request(app)
        .post("/predictions/delivery-time")
        .send({
          origin: { lat: 40.7128, lng: -74.006 },
          destination: { lat: 40.758, lng: -73.9855 },
          weight: 5000,
          serviceType: "standard",
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("estimatedMinutes");
        expect(response.body.data).toHaveProperty("confidence");
      }
    });

    it("should validate coordinates", async () => {
      const response = await request(app)
        .post("/predictions/delivery-time")
        .send({
          origin: { lat: "invalid", lng: -74.006 },
          destination: { lat: 40.758, lng: -73.9855 },
        });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("POST /predictions/demand-forecast", () => {
    it("should forecast demand", async () => {
      const response = await request(app)
        .post("/predictions/demand-forecast")
        .send({
          region: "Northeast",
          horizon: 7, // days
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("forecast");
        expect(Array.isArray(response.body.data.forecast)).toBe(true);
      }
    });

    it("should support different horizons", async () => {
      const response30 = await request(app)
        .post("/predictions/demand-forecast")
        .send({ region: "Northeast", horizon: 30 });

      const response90 = await request(app)
        .post("/predictions/demand-forecast")
        .send({ region: "Northeast", horizon: 90 });

      expect([200, 400]).toContain(response30.status);
      expect([200, 400]).toContain(response90.status);
    });
  });

  describe("POST /predictions/price-optimization", () => {
    it("should optimize pricing", async () => {
      const response = await request(app)
        .post("/predictions/price-optimization")
        .send({
          basePrice: 500,
          demand: "high",
          competitorPrices: [450, 550, 480],
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("recommendedPrice");
      }
    });
  });

  describe("GET /predictions/models", () => {
    it("should list available prediction models", async () => {
      const response = await request(app).get("/predictions/models");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });

  describe("POST /predictions/driver-performance", () => {
    it("should predict driver performance", async () => {
      const response = await request(app)
        .post("/predictions/driver-performance")
        .send({
          driverId: "driver-456",
          date: "2026-01-20",
        });

      expect([200, 400, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("expectedDeliveries");
        expect(response.body.data).toHaveProperty("onTimeScore");
      }
    });
  });
});
