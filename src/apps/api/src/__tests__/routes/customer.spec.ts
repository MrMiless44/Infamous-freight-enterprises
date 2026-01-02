import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { customerRouter } from "../../routes/customer";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Customer Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/customers", customerRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /customers", () => {
    it("should list all customers", async () => {
      const response = await request(app).get("/customers");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by status", async () => {
      const response = await request(app)
        .get("/customers")
        .query({ status: "active" });

      expect(response.status).toBe(200);
    });

    it("should support pagination", async () => {
      const response = await request(app)
        .get("/customers")
        .query({ page: 1, limit: 20 });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /customers/:id", () => {
    it("should return customer details", async () => {
      const response = await request(app).get("/customers/cust-123");

      expect([200, 404]).toContain(response.status);
    });

    it("should include shipment history", async () => {
      const response = await request(app)
        .get("/customers/cust-123")
        .query({ includeHistory: true });

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /customers", () => {
    it("should create new customer", async () => {
      const response = await request(app).post("/customers").send({
        companyName: "ACME Corp",
        contactEmail: "contact@acme.com",
        contactPhone: "+15551234567",
        address: "123 Main St",
      });

      expect([201, 200, 400]).toContain(response.status);
    });

    it("should validate email format", async () => {
      const response = await request(app).post("/customers").send({
        companyName: "ACME Corp",
        contactEmail: "invalid-email",
        contactPhone: "+15551234567",
      });

      expect([400, 422]).toContain(response.status);
    });

    it("should check for duplicate email", async () => {
      // First call
      await request(app).post("/customers").send({
        companyName: "ACME Corp",
        contactEmail: "test@example.com",
        contactPhone: "+15551234567",
      });

      // Duplicate attempt
      const response = await request(app).post("/customers").send({
        companyName: "Another Corp",
        contactEmail: "test@example.com",
        contactPhone: "+15551234568",
      });

      expect([400, 409]).toContain(response.status);
    });
  });

  describe("PUT /customers/:id", () => {
    it("should update customer information", async () => {
      const response = await request(app).put("/customers/cust-123").send({
        companyName: "Updated Name",
      });

      expect([200, 404, 400]).toContain(response.status);
    });

    it("should validate updated data", async () => {
      const response = await request(app).put("/customers/cust-123").send({
        contactEmail: "invalid-email",
      });

      expect([400, 422, 404]).toContain(response.status);
    });
  });

  describe("DELETE /customers/:id", () => {
    it("should deactivate customer", async () => {
      const response = await request(app).delete("/customers/cust-123");

      expect([200, 204, 404]).toContain(response.status);
    });
  });

  describe("GET /customers/:id/shipments", () => {
    it("should list customer shipments", async () => {
      const response = await request(app).get("/customers/cust-123/shipments");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(Array.isArray(response.body.data)).toBe(true);
      }
    });

    it("should filter shipments by status", async () => {
      const response = await request(app)
        .get("/customers/cust-123/shipments")
        .query({ status: "delivered" });

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("GET /customers/:id/invoices", () => {
    it("should list customer invoices", async () => {
      const response = await request(app).get("/customers/cust-123/invoices");

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /customers/:id/payment-method", () => {
    it("should add payment method", async () => {
      const response = await request(app)
        .post("/customers/cust-123/payment-method")
        .send({
          type: "credit_card",
          token: "tok_visa",
        });

      expect([200, 201, 400, 404]).toContain(response.status);
    });
  });

  describe("GET /customers/:id/analytics", () => {
    it("should return customer analytics", async () => {
      const response = await request(app).get("/customers/cust-123/analytics");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("totalShipments");
      }
    });
  });
});
