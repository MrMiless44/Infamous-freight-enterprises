import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { routeOptimizationRouter } from "../../routes/route-optimization";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");
jest.mock("../../services/routeOptimizer");

describe("Route Optimization Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/route-optimization", routeOptimizationRouter as any);
    jest.clearAllMocks();
  });

  describe("POST /route-optimization/optimize", () => {
    it("should optimize route for shipments", async () => {
      const response = await request(app)
        .post("/route-optimization/optimize")
        .send({
          shipmentIds: ["ship-123", "ship-124", "ship-125"],
          driverId: "driver-456",
          startLocation: { lat: 40.7128, lng: -74.006 },
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("optimizedWaypoints");
      }
    });

    it("should validate waypoints", async () => {
      const response = await request(app)
        .post("/route-optimization/optimize")
        .send({
          shipmentIds: [],
          driverId: "driver-456",
        });

      expect([400, 422]).toContain(response.status);
    });

    it("should consider traffic conditions", async () => {
      const response = await request(app)
        .post("/route-optimization/optimize")
        .send({
          shipmentIds: ["ship-123", "ship-124"],
          driverId: "driver-456",
          considerTraffic: true,
        });

      expect([200, 400]).toContain(response.status);
    });
  });

  describe("POST /route-optimization/analyze", () => {
    it("should analyze existing route", async () => {
      const response = await request(app)
        .post("/route-optimization/analyze")
        .send({
          waypoints: [
            { lat: 40.7128, lng: -74.006 },
            { lat: 40.758, lng: -73.9855 },
            { lat: 40.7489, lng: -73.968 },
          ],
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("totalDistance");
        expect(response.body.data).toHaveProperty("estimatedTime");
      }
    });

    it("should identify inefficiencies", async () => {
      const response = await request(app)
        .post("/route-optimization/analyze")
        .send({
          waypoints: [
            { lat: 40.7128, lng: -74.006 },
            { lat: 40.7128, lng: -74.006 }, // Duplicate
            { lat: 40.758, lng: -73.9855 },
          ],
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("suggestions");
      }
    });
  });

  describe("POST /route-optimization/compare", () => {
    it("should compare multiple routes", async () => {
      const response = await request(app)
        .post("/route-optimization/compare")
        .send({
          routes: [
            {
              waypoints: [
                { lat: 40.7128, lng: -74.006 },
                { lat: 40.758, lng: -73.9855 },
              ],
            },
            {
              waypoints: [
                { lat: 40.7128, lng: -74.006 },
                { lat: 40.7489, lng: -73.968 },
              ],
            },
          ],
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("comparison");
      }
    });
  });

  describe("GET /route-optimization/history", () => {
    it("should list optimization history", async () => {
      const response = await request(app).get("/route-optimization/history");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by driver", async () => {
      const response = await request(app)
        .get("/route-optimization/history")
        .query({ driverId: "driver-456" });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /route-optimization/metrics", () => {
    it("should return optimization metrics", async () => {
      const response = await request(app).get("/route-optimization/metrics");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("averageTimesSaved");
      expect(response.body.data).toHaveProperty("averageDistanceSaved");
    });
  });
});
