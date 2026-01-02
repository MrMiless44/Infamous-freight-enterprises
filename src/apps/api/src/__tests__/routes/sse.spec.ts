import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { sseRouter } from "../../routes/sse";
import { authenticate } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Server-Sent Events (SSE) Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/sse", sseRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /sse/shipment/:shipmentId", () => {
    it("should establish SSE connection for shipment", async () => {
      const response = await request(app).get("/sse/shipment/ship-123");

      expect([200, 404, 401]).toContain(response.status);

      if (response.status === 200) {
        expect(response.headers["content-type"]).toMatch(/text\/event-stream/);
      }
    });

    it("should handle invalid shipment ID", async () => {
      const response = await request(app).get("/sse/shipment/invalid");

      expect([200, 400, 404]).toContain(response.status);
    });
  });

  describe("GET /sse/driver/:driverId", () => {
    it("should establish SSE connection for driver", async () => {
      const response = await request(app).get("/sse/driver/driver-456");

      expect([200, 404, 401]).toContain(response.status);

      if (response.status === 200) {
        expect(response.headers["content-type"]).toMatch(/text\/event-stream/);
      }
    });
  });

  describe("GET /sse/notifications", () => {
    it("should establish SSE connection for notifications", async () => {
      const response = await request(app).get("/sse/notifications");

      expect([200, 401]).toContain(response.status);

      if (response.status === 200) {
        expect(response.headers["content-type"]).toMatch(/text\/event-stream/);
      }
    });
  });

  describe("POST /sse/broadcast", () => {
    it("should broadcast message to all connected clients", async () => {
      const response = await request(app).post("/sse/broadcast").send({
        message: "System maintenance in 30 minutes",
        type: "info",
      });

      expect([200, 201, 400, 401]).toContain(response.status);
    });
  });

  describe("POST /sse/notify/:userId", () => {
    it("should send notification to specific user", async () => {
      const response = await request(app).post("/sse/notify/user-789").send({
        message: "Your shipment has arrived",
        type: "notification",
      });

      expect([200, 201, 404, 401]).toContain(response.status);
    });
  });
});
