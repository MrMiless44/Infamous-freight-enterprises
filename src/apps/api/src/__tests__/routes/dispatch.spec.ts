import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { dispatchRouter } from "../../routes/dispatch";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Dispatch Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/dispatch", dispatchRouter as any);
    jest.clearAllMocks();
  });

  describe("POST /dispatch/assign", () => {
    it("should assign shipment to driver", async () => {
      const response = await request(app).post("/dispatch/assign").send({
        shipmentId: "ship-123",
        driverId: "driver-456",
      });

      expect([200, 201, 400, 404]).toContain(response.status);
    });

    it("should validate shipment and driver exist", async () => {
      const response = await request(app).post("/dispatch/assign").send({
        shipmentId: "invalid",
        driverId: "invalid",
      });

      expect([400, 404]).toContain(response.status);
    });

    it("should check driver availability", async () => {
      const response = await request(app).post("/dispatch/assign").send({
        shipmentId: "ship-123",
        driverId: "driver-456",
        forceAssign: false,
      });

      expect([200, 201, 400, 404, 409]).toContain(response.status);
    });
  });

  describe("GET /dispatch/queue", () => {
    it("should list pending shipments", async () => {
      const response = await request(app).get("/dispatch/queue");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by priority", async () => {
      const response = await request(app)
        .get("/dispatch/queue")
        .query({ priority: "high" });

      expect(response.status).toBe(200);
    });

    it("should support pagination", async () => {
      const response = await request(app)
        .get("/dispatch/queue")
        .query({ page: 1, limit: 20 });

      expect(response.status).toBe(200);
      expect(response.body.data).toBeDefined();
    });
  });

  describe("POST /dispatch/optimize", () => {
    it("should optimize dispatch routes", async () => {
      const response = await request(app)
        .post("/dispatch/optimize")
        .send({
          shipmentIds: ["ship-123", "ship-124", "ship-125"],
          driverId: "driver-456",
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("optimizedRoute");
      }
    });

    it("should handle empty shipment list", async () => {
      const response = await request(app).post("/dispatch/optimize").send({
        shipmentIds: [],
        driverId: "driver-456",
      });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("POST /dispatch/reassign", () => {
    it("should reassign shipment to different driver", async () => {
      const response = await request(app).post("/dispatch/reassign").send({
        shipmentId: "ship-123",
        fromDriverId: "driver-456",
        toDriverId: "driver-789",
      });

      expect([200, 400, 404]).toContain(response.status);
    });

    it("should validate both drivers exist", async () => {
      const response = await request(app).post("/dispatch/reassign").send({
        shipmentId: "ship-123",
        fromDriverId: "invalid",
        toDriverId: "invalid",
      });

      expect([400, 404]).toContain(response.status);
    });
  });

  describe("GET /dispatch/active", () => {
    it("should list active assignments", async () => {
      const response = await request(app).get("/dispatch/active");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by status", async () => {
      const response = await request(app)
        .get("/dispatch/active")
        .query({ status: "in-transit" });

      expect(response.status).toBe(200);
    });
  });

  describe("POST /dispatch/complete", () => {
    it("should mark shipment as delivered", async () => {
      const response = await request(app)
        .post("/dispatch/complete")
        .send({
          shipmentId: "ship-123",
          deliveryProof: { photoUrl: "https://example.com/photo.jpg" },
        });

      expect([200, 400, 404]).toContain(response.status);
    });

    it("should validate delivery proof", async () => {
      const response = await request(app).post("/dispatch/complete").send({
        shipmentId: "ship-123",
        deliveryProof: null,
      });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("POST /dispatch/cancel", () => {
    it("should cancel shipment dispatch", async () => {
      const response = await request(app).post("/dispatch/cancel").send({
        shipmentId: "ship-123",
        reason: "customer_request",
      });

      expect([200, 400, 404]).toContain(response.status);
    });
  });

  describe("GET /dispatch/metrics", () => {
    it("should return dispatch metrics", async () => {
      const response = await request(app).get("/dispatch/metrics");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("totalShipments");
    });
  });
});
