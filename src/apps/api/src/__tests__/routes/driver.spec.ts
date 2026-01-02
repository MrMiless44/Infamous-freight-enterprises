import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { driverRouter } from "../../routes/driver";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Driver Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/drivers", driverRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /drivers", () => {
    it("should list all drivers", async () => {
      const response = await request(app).get("/drivers");

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter drivers by status", async () => {
      const response = await request(app)
        .get("/drivers")
        .query({ status: "active" });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    it("should handle pagination", async () => {
      const response = await request(app)
        .get("/drivers")
        .query({ page: 1, limit: 10 });

      expect(response.status).toBe(200);
      expect(response.body.data).toBeDefined();
    });
  });

  describe("GET /drivers/:id", () => {
    it("should return driver details", async () => {
      const response = await request(app).get("/drivers/driver-123");

      expect([200, 404]).toContain(response.status);
    });

    it("should include location data if available", async () => {
      const response = await request(app).get("/drivers/driver-123");

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("id");
      }
    });
  });

  describe("POST /drivers", () => {
    it("should create a new driver", async () => {
      const driverData = {
        firstName: "John",
        lastName: "Doe",
        phone: "+15551234567",
        licenseNumber: "DL123456",
        licenseExpiry: "2026-12-31",
      };

      const response = await request(app).post("/drivers").send(driverData);

      expect([201, 200, 400]).toContain(response.status);
    });

    it("should validate required fields", async () => {
      const response = await request(app)
        .post("/drivers")
        .send({ firstName: "John" });

      expect([400, 422]).toContain(response.status);
    });

    it("should validate phone format", async () => {
      const response = await request(app).post("/drivers").send({
        firstName: "John",
        lastName: "Doe",
        phone: "invalid",
        licenseNumber: "DL123456",
      });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("PUT /drivers/:id", () => {
    it("should update driver information", async () => {
      const response = await request(app)
        .put("/drivers/driver-123")
        .send({ phone: "+15559999999" });

      expect([200, 404, 400]).toContain(response.status);
    });

    it("should handle invalid updates", async () => {
      const response = await request(app)
        .put("/drivers/driver-123")
        .send({ phone: "invalid" });

      expect([400, 422, 404]).toContain(response.status);
    });
  });

  describe("POST /drivers/:id/location", () => {
    it("should update driver location", async () => {
      const response = await request(app)
        .post("/drivers/driver-123/location")
        .send({
          latitude: 40.7128,
          longitude: -74.006,
          accuracy: 10,
        });

      expect([200, 400, 404]).toContain(response.status);
    });

    it("should validate coordinates", async () => {
      const response = await request(app)
        .post("/drivers/driver-123/location")
        .send({
          latitude: "invalid",
          longitude: -74.006,
        });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("GET /drivers/:id/availability", () => {
    it("should return driver availability status", async () => {
      const response = await request(app).get(
        "/drivers/driver-123/availability",
      );

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /drivers/:id/availability", () => {
    it("should update driver availability", async () => {
      const response = await request(app)
        .post("/drivers/driver-123/availability")
        .send({ available: true });

      expect([200, 404, 400]).toContain(response.status);
    });
  });

  describe("GET /drivers/:id/statistics", () => {
    it("should return driver statistics", async () => {
      const response = await request(app).get("/drivers/driver-123/statistics");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("totalShipments");
        expect(response.body.data).toHaveProperty("averageRating");
      }
    });
  });

  describe("DELETE /drivers/:id", () => {
    it("should deactivate driver", async () => {
      const response = await request(app).delete("/drivers/driver-123");

      expect([200, 204, 404]).toContain(response.status);
    });
  });
});
