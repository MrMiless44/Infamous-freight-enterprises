/**
 * Shipment Routes Tests
 * Tests for shipment CRUD operations
 */

import request from "supertest";
import express from "express";
import { shipmentRouter } from "../../routes/shipment";
import { prisma } from "../../lib/prisma";

jest.mock("../../lib/prisma");
jest.mock("../../middleware/auth", () => ({
  authenticate: (req: any, res: any, next: any) => {
    req.user = { id: "user-1", role: "ADMIN" };
    next();
  },
}));

describe("Shipment Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use("/api", shipmentRouter);
  });

  describe("GET /api/shipments", () => {
    it("should list all shipments", async () => {
      const mockShipments = [
        {
          id: "ship-1",
          trackingNumber: "IF-ABC123",
          status: "PENDING",
          customerId: "cust-1",
        },
        {
          id: "ship-2",
          trackingNumber: "IF-DEF456",
          status: "IN_TRANSIT",
          customerId: "cust-2",
        },
      ];

      (prisma.shipment.findMany as jest.Mock).mockResolvedValue(mockShipments);

      const response = await request(app).get("/api/shipments");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
      expect(response.body.data.length).toBe(2);
    });

    it("should filter shipments by status", async () => {
      const mockShipments = [
        {
          id: "ship-1",
          trackingNumber: "IF-ABC123",
          status: "PENDING",
        },
      ];

      (prisma.shipment.findMany as jest.Mock).mockResolvedValue(mockShipments);

      const response = await request(app).get("/api/shipments?status=PENDING");

      expect(response.status).toBe(200);
      expect(response.body.data[0].status).toBe("PENDING");
    });

    it("should support pagination", async () => {
      (prisma.shipment.findMany as jest.Mock).mockResolvedValue([]);

      const response = await request(app).get("/api/shipments?page=1&limit=10");

      expect(response.status).toBe(200);
      expect(prisma.shipment.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 0,
          take: 10,
        }),
      );
    });
  });

  describe("GET /api/shipments/:id", () => {
    it("should get shipment by ID", async () => {
      const mockShipment = {
        id: "ship-1",
        trackingNumber: "IF-ABC123",
        status: "IN_TRANSIT",
        customerId: "cust-1",
        driverId: "driver-1",
      };

      (prisma.shipment.findUnique as jest.Mock).mockResolvedValue(mockShipment);

      const response = await request(app).get("/api/shipments/ship-1");

      expect(response.status).toBe(200);
      expect(response.body.data.id).toBe("ship-1");
      expect(response.body.data.trackingNumber).toBe("IF-ABC123");
    });

    it("should return 404 for non-existent shipment", async () => {
      (prisma.shipment.findUnique as jest.Mock).mockResolvedValue(null);

      const response = await request(app).get("/api/shipments/nonexistent");

      expect(response.status).toBe(404);
    });
  });

  describe("POST /api/shipments", () => {
    it("should create new shipment", async () => {
      const newShipment = {
        trackingNumber: "IF-NEW123",
        customerId: "cust-1",
        originCity: "New York",
        destinationCity: "Los Angeles",
        weight: 1000,
        status: "PENDING",
      };

      (prisma.shipment.create as jest.Mock).mockResolvedValue({
        id: "ship-new",
        ...newShipment,
      });

      const response = await request(app)
        .post("/api/shipments")
        .send(newShipment);

      expect(response.status).toBe(201);
      expect(response.body.data.trackingNumber).toBe("IF-NEW123");
    });

    it("should validate required fields", async () => {
      const incompleteShipment = {
        trackingNumber: "IF-ABC123",
        // missing customerId
      };

      const response = await request(app)
        .post("/api/shipments")
        .send(incompleteShipment);

      expect(response.status).toBe(400);
    });
  });

  describe("PATCH /api/shipments/:id", () => {
    it("should update shipment status", async () => {
      const updatedShipment = {
        id: "ship-1",
        status: "IN_TRANSIT",
      };

      (prisma.shipment.update as jest.Mock).mockResolvedValue(updatedShipment);

      const response = await request(app)
        .patch("/api/shipments/ship-1")
        .send({ status: "IN_TRANSIT" });

      expect(response.status).toBe(200);
      expect(response.body.data.status).toBe("IN_TRANSIT");
    });

    it("should prevent invalid status transitions", async () => {
      const response = await request(app)
        .patch("/api/shipments/ship-1")
        .send({ status: "INVALID_STATUS" });

      expect(response.status).toBe(400);
    });
  });

  describe("DELETE /api/shipments/:id", () => {
    it("should delete shipment", async () => {
      (prisma.shipment.delete as jest.Mock).mockResolvedValue({ id: "ship-1" });

      const response = await request(app).delete("/api/shipments/ship-1");

      expect([200, 204]).toContain(response.status);
    });

    it("should return 404 for non-existent shipment", async () => {
      (prisma.shipment.delete as jest.Mock).mockRejectedValue(
        new Error("Not found"),
      );

      const response = await request(app).delete("/api/shipments/nonexistent");

      expect(response.status).toBe(404);
    });
  });
});
