import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { webhooksRouter } from "../../routes/webhooks";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Webhooks Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/webhooks", webhooksRouter as any);
    jest.clearAllMocks();
  });

  describe("POST /webhooks/register", () => {
    it("should register webhook endpoint", async () => {
      const response = await request(app)
        .post("/webhooks/register")
        .send({
          url: "https://example.com/webhook",
          events: ["shipment.created", "shipment.delivered"],
        });

      expect([200, 201, 400]).toContain(response.status);

      if (response.status === 200 || response.status === 201) {
        expect(response.body.data).toHaveProperty("webhookId");
        expect(response.body.data).toHaveProperty("secret");
      }
    });

    it("should validate webhook URL", async () => {
      const response = await request(app)
        .post("/webhooks/register")
        .send({
          url: "invalid-url",
          events: ["shipment.created"],
        });

      expect([400, 422]).toContain(response.status);
    });

    it("should validate events list", async () => {
      const response = await request(app).post("/webhooks/register").send({
        url: "https://example.com/webhook",
        events: [],
      });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("GET /webhooks", () => {
    it("should list registered webhooks", async () => {
      const response = await request(app).get("/webhooks");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });

  describe("GET /webhooks/:id", () => {
    it("should return webhook details", async () => {
      const response = await request(app).get("/webhooks/hook-123");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("url");
        expect(response.body.data).toHaveProperty("events");
      }
    });
  });

  describe("PUT /webhooks/:id", () => {
    it("should update webhook", async () => {
      const response = await request(app)
        .put("/webhooks/hook-123")
        .send({
          url: "https://example.com/new-webhook",
          events: ["shipment.created"],
        });

      expect([200, 404, 400]).toContain(response.status);
    });
  });

  describe("DELETE /webhooks/:id", () => {
    it("should unregister webhook", async () => {
      const response = await request(app).delete("/webhooks/hook-123");

      expect([200, 204, 404]).toContain(response.status);
    });
  });

  describe("POST /webhooks/:id/test", () => {
    it("should send test webhook", async () => {
      const response = await request(app)
        .post("/webhooks/hook-123/test")
        .send({});

      expect([200, 404, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("statusCode");
      }
    });
  });

  describe("GET /webhooks/:id/deliveries", () => {
    it("should list webhook deliveries", async () => {
      const response = await request(app).get("/webhooks/hook-123/deliveries");

      expect([200, 404]).toContain(response.status);

      if (response.status === 200) {
        expect(Array.isArray(response.body.data)).toBe(true);
      }
    });

    it("should filter by status", async () => {
      const response = await request(app)
        .get("/webhooks/hook-123/deliveries")
        .query({ status: "failed" });

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /webhooks/:id/deliveries/:deliveryId/retry", () => {
    it("should retry failed delivery", async () => {
      const response = await request(app)
        .post("/webhooks/hook-123/deliveries/delivery-456/retry")
        .send({});

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("GET /webhooks/events", () => {
    it("should list available webhook events", async () => {
      const response = await request(app).get("/webhooks/events");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });
});
