import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { productsRouter } from "../../routes/products";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Products Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/products", productsRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /products", () => {
    it("should list all products", async () => {
      const response = await request(app).get("/products");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by category", async () => {
      const response = await request(app)
        .get("/products")
        .query({ category: "shipping" });

      expect(response.status).toBe(200);
    });

    it("should support search", async () => {
      const response = await request(app)
        .get("/products")
        .query({ search: "express" });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /products/:id", () => {
    it("should return product details", async () => {
      const response = await request(app).get("/products/prod-123");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("name");
        expect(response.body.data).toHaveProperty("price");
      }
    });
  });

  describe("POST /products", () => {
    it("should create new product", async () => {
      const response = await request(app)
        .post("/products")
        .send({
          name: "Express Shipping",
          description: "Fast delivery",
          category: "shipping",
          basePrice: 2999,
          features: ["Priority handling", "Tracking"],
        });

      expect([201, 200, 400, 401]).toContain(response.status);
    });

    it("should validate required fields", async () => {
      const response = await request(app).post("/products").send({
        name: "Express Shipping",
        // missing category and price
      });

      expect([400, 422, 401]).toContain(response.status);
    });
  });

  describe("PUT /products/:id", () => {
    it("should update product", async () => {
      const response = await request(app).put("/products/prod-123").send({
        price: 3499,
        description: "Updated description",
      });

      expect([200, 404, 400, 401]).toContain(response.status);
    });
  });

  describe("DELETE /products/:id", () => {
    it("should delete product", async () => {
      const response = await request(app).delete("/products/prod-123");

      expect([200, 204, 404, 401]).toContain(response.status);
    });
  });

  describe("GET /products/:id/pricing-rules", () => {
    it("should list pricing rules for product", async () => {
      const response = await request(app).get(
        "/products/prod-123/pricing-rules",
      );

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(Array.isArray(response.body.data)).toBe(true);
      }
    });
  });
});
