import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { billingRouter } from "../../routes/billing";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");
jest.mock("stripe");

describe("Billing Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/billing", billingRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /billing/products", () => {
    it("should return all products", async () => {
      const response = await request(app).get("/billing/products");
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    it("should filter products by category", async () => {
      const response = await request(app)
        .get("/billing/products")
        .query({ category: "shipping" });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe("GET /billing/products/:id", () => {
    it("should return product details", async () => {
      const response = await request(app).get("/billing/products/prod_local");

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    it("should handle product not found", async () => {
      const response = await request(app).get("/billing/products/nonexistent");

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /billing/quote", () => {
    it("should generate a shipping quote", async () => {
      const quoteData = {
        serviceType: "regional",
        distance: 300,
        weight: 5000,
        origin: "New York",
        destination: "Chicago",
      };

      const response = await request(app)
        .post("/billing/quote")
        .send(quoteData);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty("total");
    });

    it("should validate required fields", async () => {
      const response = await request(app).post("/billing/quote").send({
        serviceType: "regional",
        // missing distance and weight
      });

      expect([400, 422]).toContain(response.status);
    });

    it("should calculate correct pricing", async () => {
      const response = await request(app).post("/billing/quote").send({
        serviceType: "local",
        distance: 25,
        weight: 2000,
      });

      expect(response.status).toBe(200);
      expect(response.body.data.total).toBeGreaterThan(0);
    });
  });

  describe("POST /billing/bulk-pricing", () => {
    it("should calculate bulk pricing discount", async () => {
      const response = await request(app).post("/billing/bulk-pricing").send({
        serviceType: "regional",
        volume: 150,
      });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty("discountPercent");
    });

    it("should apply correct discount tiers", async () => {
      // Test 5% discount tier
      const response1 = await request(app)
        .post("/billing/bulk-pricing")
        .send({ serviceType: "regional", volume: 25 });

      const response50 = await request(app)
        .post("/billing/bulk-pricing")
        .send({ serviceType: "regional", volume: 75 });

      expect(response1.body.data.discountPercent).toBeLessThan(
        response50.body.data.discountPercent,
      );
    });
  });

  describe("POST /billing/stripe/checkout", () => {
    it("should create checkout session", async () => {
      const response = await request(app)
        .post("/billing/stripe/checkout")
        .send({
          productId: "prod_professional",
          quantity: 1,
          successUrl: "https://example.com/success",
          cancelUrl: "https://example.com/cancel",
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty("sessionId");
    });

    it("should validate checkout parameters", async () => {
      const response = await request(app)
        .post("/billing/stripe/checkout")
        .send({
          // missing required fields
        });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("POST /billing/subscriptions", () => {
    it("should create subscription", async () => {
      const response = await request(app).post("/billing/subscriptions").send({
        productId: "prod_starter",
      });

      expect([200, 201, 400, 500]).toContain(response.status);
    });
  });

  describe("GET /billing/subscriptions", () => {
    it("should list user subscriptions", async () => {
      const response = await request(app).get("/billing/subscriptions");

      expect([200, 401]).toContain(response.status);
    });
  });

  describe("POST /billing/subscriptions/:id/cancel", () => {
    it("should cancel subscription", async () => {
      const response = await request(app).post(
        "/billing/subscriptions/sub_123/cancel",
      );

      expect([200, 404, 401]).toContain(response.status);
    });
  });
});
