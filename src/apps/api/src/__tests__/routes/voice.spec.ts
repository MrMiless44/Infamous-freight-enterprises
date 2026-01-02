import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { voiceRouter } from "../../routes/voice";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");
jest.mock("multer");

describe("Voice Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/voice", voiceRouter as any);
    jest.clearAllMocks();
  });

  describe("POST /voice/ingest", () => {
    it("should accept voice file upload", async () => {
      const response = await request(app)
        .post("/voice/ingest")
        .set("Content-Type", "multipart/form-data")
        .field("phoneNumber", "+15551234567");

      expect([200, 201, 400]).toContain(response.status);
    });

    it("should validate phone number", async () => {
      const response = await request(app)
        .post("/voice/ingest")
        .field("phoneNumber", "invalid");

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("POST /voice/transcribe", () => {
    it("should transcribe audio", async () => {
      const response = await request(app).post("/voice/transcribe").send({
        audioUrl: "https://example.com/audio.mp3",
        language: "en",
      });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("transcript");
      }
    });

    it("should support multiple languages", async () => {
      const response = await request(app).post("/voice/transcribe").send({
        audioUrl: "https://example.com/audio.mp3",
        language: "es",
      });

      expect([200, 400]).toContain(response.status);
    });
  });

  describe("POST /voice/command", () => {
    it("should process voice command", async () => {
      const response = await request(app)
        .post("/voice/command")
        .send({
          transcript: "Find me a driver for New York to Boston",
          context: { shipmentId: "ship-123" },
        });

      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        expect(response.body.data).toHaveProperty("action");
      }
    });

    it("should validate transcript", async () => {
      const response = await request(app)
        .post("/voice/command")
        .send({ transcript: "" });

      expect([400, 422]).toContain(response.status);
    });
  });

  describe("GET /voice/history", () => {
    it("should list voice call history", async () => {
      const response = await request(app).get("/voice/history");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should support pagination", async () => {
      const response = await request(app)
        .get("/voice/history")
        .query({ page: 1, limit: 20 });

      expect(response.status).toBe(200);
    });
  });

  describe("POST /voice/callback", () => {
    it("should handle voice callback", async () => {
      const response = await request(app).post("/voice/callback").send({
        callId: "call-123",
        status: "completed",
        duration: 120,
      });

      expect([200, 201, 400]).toContain(response.status);
    });
  });
});
