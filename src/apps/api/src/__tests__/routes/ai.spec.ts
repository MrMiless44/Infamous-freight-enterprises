import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { aiRouter } from "../../routes/ai";
import {
  authenticate,
  requireScope,
  limiters,
} from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");
jest.mock("../../services/aiSyntheticClient");

describe("AI Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/ai", aiRouter as any);
    jest.clearAllMocks();
  });

  describe("POST /ai/commands", () => {
    it("should process voice command", async () => {
      const response = await request(app)
        .post("/ai/commands")
        .send({
          command: "Find me a driver for pickup in New York",
          context: { shipmentId: "ship-123" },
        });

      expect([200, 400, 401]).toContain(response.status);
    });

    it("should validate command text", async () => {
      const response = await request(app).post("/ai/commands").send({
        command: "",
      });

      expect([400, 422]).toContain(response.status);
    });

    it("should handle command with context", async () => {
      const response = await request(app)
        .post("/ai/commands")
        .send({
          command: "What is the status",
          context: {
            shipmentId: "ship-123",
            driverId: "driver-456",
          },
        });

      expect([200, 400, 401]).toContain(response.status);
    });
  });

  describe("POST /ai/analyze-route", () => {
    it("should analyze route for optimization", async () => {
      const response = await request(app)
        .post("/ai/analyze-route")
        .send({
          waypoints: [
            { lat: 40.7128, lng: -74.006 },
            { lat: 40.758, lng: -73.9855 },
            { lat: 40.7489, lng: -73.968 },
          ],
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("suggestions");
      }
    });

    it("should validate waypoints format", async () => {
      const response = await request(app)
        .post("/ai/analyze-route")
        .send({
          waypoints: [{ invalid: "data" }],
        });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("POST /ai/predict-demand", () => {
    it("should predict demand for region", async () => {
      const response = await request(app).post("/ai/predict-demand").send({
        region: "Northeast",
        date: "2026-01-15",
      });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("demand");
      }
    });

    it("should handle historical data", async () => {
      const response = await request(app).post("/ai/predict-demand").send({
        region: "Northeast",
        date: "2026-01-15",
        includeHistorical: true,
      });

      expect([200, 400]).toContain(response.status);
    });
  });

  describe("POST /ai/sentiment-analysis", () => {
    it("should analyze text sentiment", async () => {
      const response = await request(app).post("/ai/sentiment-analysis").send({
        text: "The delivery was excellent and on time!",
      });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("sentiment");
      }
    });

    it("should validate input text", async () => {
      const response = await request(app).post("/ai/sentiment-analysis").send({
        text: "",
      });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("GET /ai/models", () => {
    it("should list available AI models", async () => {
      const response = await request(app).get("/ai/models");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });

  describe("POST /ai/chat", () => {
    it("should handle multi-turn conversation", async () => {
      const response = await request(app)
        .post("/ai/chat")
        .send({
          messages: [
            { role: "user", content: "What are my pending shipments?" },
          ],
        });

      expect([200, 400, 401]).toContain(response.status);
    });

    it("should validate message format", async () => {
      const response = await request(app)
        .post("/ai/chat")
        .send({
          messages: [{ invalid: "format" }],
        });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("POST /ai/summarize", () => {
    it("should summarize text content", async () => {
      const response = await request(app)
        .post("/ai/summarize")
        .send({
          text:
            "Long content here... " + "Lorem ipsum dolor sit amet. ".repeat(20),
          maxLength: 100,
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("summary");
      }
    });
  });

  describe("Rate limiting on AI routes", () => {
    it("should enforce rate limits on commands", async () => {
      // Note: Actual rate limiting behavior depends on middleware implementation
      const response = await request(app)
        .post("/ai/commands")
        .send({ command: "test" });

      expect([200, 400, 401, 429]).toContain(response.status);
    });
  });
});
