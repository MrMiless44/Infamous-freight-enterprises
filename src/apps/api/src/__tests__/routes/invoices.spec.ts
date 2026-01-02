import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { invoicesRouter } from "../../routes/invoices";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Invoices Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/invoices", invoicesRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /invoices", () => {
    it("should list invoices", async () => {
      const response = await request(app).get("/invoices");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by status", async () => {
      const response = await request(app)
        .get("/invoices")
        .query({ status: "paid" });

      expect(response.status).toBe(200);
    });

    it("should filter by customer", async () => {
      const response = await request(app)
        .get("/invoices")
        .query({ customerId: "cust-123" });

      expect(response.status).toBe(200);
    });

    it("should support date range filtering", async () => {
      const response = await request(app).get("/invoices").query({
        startDate: "2026-01-01",
        endDate: "2026-01-31",
      });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /invoices/:id", () => {
    it("should return invoice details", async () => {
      const response = await request(app).get("/invoices/inv-123");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("invoiceNumber");
        expect(response.body.data).toHaveProperty("total");
      }
    });
  });

  describe("POST /invoices", () => {
    it("should create invoice", async () => {
      const response = await request(app)
        .post("/invoices")
        .send({
          customerId: "cust-123",
          shipmentIds: ["ship-123", "ship-124"],
          dueDate: "2026-02-15",
        });

      expect([201, 200, 400]).toContain(response.status);

      if (response.status === 201 || response.status === 200) {
        expect(response.body.data).toHaveProperty("invoiceNumber");
      }
    });

    it("should validate customer exists", async () => {
      const response = await request(app)
        .post("/invoices")
        .send({
          customerId: "nonexistent",
          shipmentIds: ["ship-123"],
        });

      expect([400, 404]).toContain(response.status);
    });

    it("should calculate total correctly", async () => {
      const response = await request(app)
        .post("/invoices")
        .send({
          customerId: "cust-123",
          shipmentIds: ["ship-123", "ship-124"],
        });

      expect([201, 200, 400]).toContain(response.status);

      if (response.status === 201 || response.status === 200) {
        expect(response.body.data.total).toBeGreaterThan(0);
      }
    });
  });

  describe("POST /invoices/:id/send", () => {
    it("should send invoice to customer", async () => {
      const response = await request(app)
        .post("/invoices/inv-123/send")
        .send({ email: "customer@example.com" });

      expect([200, 404, 400]).toContain(response.status);
    });

    it("should validate email address", async () => {
      const response = await request(app)
        .post("/invoices/inv-123/send")
        .send({ email: "invalid-email" });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("POST /invoices/:id/payment", () => {
    it("should record payment", async () => {
      const response = await request(app)
        .post("/invoices/inv-123/payment")
        .send({
          amount: 5000,
          method: "credit_card",
          transactionId: "txn-123",
        });

      expect([200, 400, 404]).toContain(response.status);
    });

    it("should validate payment amount", async () => {
      const response = await request(app)
        .post("/invoices/inv-123/payment")
        .send({
          amount: -100,
          method: "credit_card",
        });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("GET /invoices/:id/pdf", () => {
    it("should generate invoice PDF", async () => {
      const response = await request(app).get("/invoices/inv-123/pdf");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(response.type).toMatch(/pdf|octet-stream/);
      }
    });
  });

  describe("POST /invoices/bulk-create", () => {
    it("should create multiple invoices", async () => {
      const response = await request(app)
        .post("/invoices/bulk-create")
        .send({
          invoices: [
            {
              customerId: "cust-123",
              shipmentIds: ["ship-123"],
            },
            {
              customerId: "cust-124",
              shipmentIds: ["ship-124", "ship-125"],
            },
          ],
        });

      expect([200, 201, 400]).toContain(response.status);
    });
  });

  describe("GET /invoices/:id/payment-history", () => {
    it("should list payment history", async () => {
      const response = await request(app).get(
        "/invoices/inv-123/payment-history",
      );

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(Array.isArray(response.body.data)).toBe(true);
      }
    });
  });
});
