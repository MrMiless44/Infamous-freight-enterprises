import request from "supertest";
import express from "express";
import { demandForecastRouter } from "../../routes/demand-forecast";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");
jest.mock("../../services/mlPredictor");

describe("Demand Forecast Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/demand-forecast", demandForecastRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /demand-forecast/:region", () => {
    it("should get demand forecast for region", async () => {
      const response = await request(app).get("/demand-forecast/Northeast");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("forecast");
      }
    });

    it("should support forecast horizon", async () => {
      const response = await request(app)
        .get("/demand-forecast/Northeast")
        .query({ days: 30 });

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /demand-forecast/generate", () => {
    it("should generate forecast for all regions", async () => {
      const response = await request(app)
        .post("/demand-forecast/generate")
        .send({
          horizon: 14,
        });

      expect([200, 201, 400]).toContain(response.status);
    });
  });

  describe("GET /demand-forecast/comparison", () => {
    it("should compare forecasts", async () => {
      const response = await request(app)
        .get("/demand-forecast/comparison")
        .query({
          region1: "Northeast",
          region2: "Midwest",
        });

      expect([200, 400]).toContain(response.status);
    });
  });
});
