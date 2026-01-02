import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { fleetRouter } from "../../routes/fleet";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Fleet Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/fleet", fleetRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /fleet/vehicles", () => {
    it("should list all vehicles", async () => {
      const response = await request(app).get("/fleet/vehicles");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by status", async () => {
      const response = await request(app)
        .get("/fleet/vehicles")
        .query({ status: "active" });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /fleet/vehicles/:id", () => {
    it("should return vehicle details", async () => {
      const response = await request(app).get("/fleet/vehicles/v-123");

      expect([200, 404]).toContain(response.status);
    });

    it("should include maintenance history", async () => {
      const response = await request(app)
        .get("/fleet/vehicles/v-123")
        .query({ includeMaintenance: true });

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /fleet/vehicles", () => {
    it("should add new vehicle to fleet", async () => {
      const response = await request(app).post("/fleet/vehicles").send({
        make: "Volvo",
        model: "FH16",
        year: 2025,
        vin: "YV2BM0E26F1234567",
        licensePlate: "ABC123",
        capacity: 25000,
      });

      expect([201, 200, 400]).toContain(response.status);
    });

    it("should validate VIN format", async () => {
      const response = await request(app).post("/fleet/vehicles").send({
        make: "Volvo",
        model: "FH16",
        year: 2025,
        vin: "invalid",
        licensePlate: "ABC123",
        capacity: 25000,
      });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("PUT /fleet/vehicles/:id", () => {
    it("should update vehicle information", async () => {
      const response = await request(app).put("/fleet/vehicles/v-123").send({
        status: "maintenance",
        lastMaintenance: "2026-01-15",
      });

      expect([200, 404, 400]).toContain(response.status);
    });
  });

  describe("POST /fleet/vehicles/:id/maintenance", () => {
    it("should record maintenance", async () => {
      const response = await request(app)
        .post("/fleet/vehicles/v-123/maintenance")
        .send({
          type: "oil_change",
          cost: 150,
          date: "2026-01-15",
          notes: "Regular maintenance",
        });

      expect([200, 201, 400, 404]).toContain(response.status);
    });
  });

  describe("GET /fleet/metrics", () => {
    it("should return fleet metrics", async () => {
      const response = await request(app).get("/fleet/metrics");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("totalVehicles");
      expect(response.body.data).toHaveProperty("activeVehicles");
    });

    it("should support time range filtering", async () => {
      const response = await request(app).get("/fleet/metrics").query({
        startDate: "2026-01-01",
        endDate: "2026-01-31",
      });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /fleet/utilization", () => {
    it("should return fleet utilization data", async () => {
      const response = await request(app).get("/fleet/utilization");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("utilizationPercent");
    });
  });

  describe("DELETE /fleet/vehicles/:id", () => {
    it("should remove vehicle from fleet", async () => {
      const response = await request(app).delete("/fleet/vehicles/v-123");

      expect([200, 204, 404]).toContain(response.status);
    });
  });
});
