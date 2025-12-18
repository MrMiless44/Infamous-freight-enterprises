const request = require("supertest");
const jwt = require("jsonwebtoken");
const path = require("path");

// Setup test environment
process.env.JWT_SECRET = "test-secret";
process.env.NODE_ENV = "test";
process.env.AI_PROVIDER = "synthetic";
process.env.VOICE_MAX_FILE_SIZE_MB = "10";

// Mock AI service before requiring the app
jest.mock("../src/services/aiSyntheticClient", () => ({
  sendCommand: jest.fn(),
}));

const app = require("../src/server");
const { sendCommand } = require("../src/services/aiSyntheticClient");

// Helper to generate JWT tokens
const makeToken = (scopes) =>
  jwt.sign(
    {
      sub: "test-user-123",
      scopes,
    },
    process.env.JWT_SECRET,
  );

const authHeader = (token) => `Bearer ${token}`;

// Skip tests on Node 22+ due to supertest compatibility issues
const skipOnNode22 = global.skipSupertestOnNode22 ? describe.skip : describe;

skipOnNode22("Voice API Routes", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("POST /api/voice/ingest", () => {
    test("successfully ingests audio file with valid scope", async () => {
      const mockResponse = { action: "route_optimized" };
      sendCommand.mockResolvedValue(mockResponse);

      const token = makeToken(["voice:ingest"]);
      const res = await request(app)
        .post("/api/voice/ingest")
        .set("Authorization", authHeader(token))
        .attach("audio", Buffer.from("fake audio data"), {
          filename: "test.mp3",
          contentType: "audio/mpeg",
        });

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.transcript).toContain("Driver says:");
      expect(res.body.ai).toEqual(mockResponse);
      expect(sendCommand).toHaveBeenCalledWith(
        "voice.input",
        expect.objectContaining({ transcript: expect.any(String) }),
      );
    });

    test("returns 401 when not authenticated", async () => {
      const res = await request(app)
        .post("/api/voice/ingest")
        .attach("audio", Buffer.from("fake audio data"), {
          filename: "test.mp3",
          contentType: "audio/mpeg",
        });

      expect(res.status).toBe(401);
      expect(sendCommand).not.toHaveBeenCalled();
    });

    test("returns 403 when missing required scope", async () => {
      const token = makeToken(["other:scope"]);
      const res = await request(app)
        .post("/api/voice/ingest")
        .set("Authorization", authHeader(token))
        .attach("audio", Buffer.from("fake audio data"), {
          filename: "test.mp3",
          contentType: "audio/mpeg",
        });

      expect(res.status).toBe(403);
      expect(sendCommand).not.toHaveBeenCalled();
    });

    test("returns 400 when audio file is missing", async () => {
      const token = makeToken(["voice:ingest"]);
      const res = await request(app)
        .post("/api/voice/ingest")
        .set("Authorization", authHeader(token))
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("audio required");
    });

    test("accepts wav audio format", async () => {
      sendCommand.mockResolvedValue({ status: "success" });

      const token = makeToken(["voice:ingest"]);
      const res = await request(app)
        .post("/api/voice/ingest")
        .set("Authorization", authHeader(token))
        .attach("audio", Buffer.from("fake wav data"), {
          filename: "test.wav",
          contentType: "audio/wav",
        });

      expect(res.status).toBe(200);
    });

    test("accepts mp4 audio format", async () => {
      sendCommand.mockResolvedValue({ status: "success" });

      const token = makeToken(["voice:ingest"]);
      const res = await request(app)
        .post("/api/voice/ingest")
        .set("Authorization", authHeader(token))
        .attach("audio", Buffer.from("fake mp4 data"), {
          filename: "test.mp4",
          contentType: "audio/mp4",
        });

      expect(res.status).toBe(200);
    });

    test("rejects unsupported audio format", async () => {
      const token = makeToken(["voice:ingest"]);
      const res = await request(app)
        .post("/api/voice/ingest")
        .set("Authorization", authHeader(token))
        .attach("audio", Buffer.from("fake data"), {
          filename: "test.txt",
          contentType: "text/plain",
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Unsupported audio format");
    });

    test("handles AI service errors gracefully", async () => {
      sendCommand.mockRejectedValue(new Error("Voice processing failed"));

      const token = makeToken(["voice:ingest"]);
      const res = await request(app)
        .post("/api/voice/ingest")
        .set("Authorization", authHeader(token))
        .attach("audio", Buffer.from("fake audio data"), {
          filename: "test.mp3",
          contentType: "audio/mpeg",
        });

      expect(res.status).toBe(500);
      expect(res.body.error).toContain("Voice processing failed");
    });
  });

  describe("POST /api/voice/command", () => {
    test("successfully processes voice command with valid scope", async () => {
      const mockResponse = { action: "acknowledged" };
      sendCommand.mockResolvedValue(mockResponse);

      const token = makeToken(["voice:command"]);
      const res = await request(app)
        .post("/api/voice/command")
        .set("Authorization", authHeader(token))
        .send({ text: "Navigate to warehouse" });

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.result).toEqual(mockResponse);
      expect(sendCommand).toHaveBeenCalledWith("voice.command", {
        text: "Navigate to warehouse",
      });
    });

    test("returns 401 when not authenticated", async () => {
      const res = await request(app)
        .post("/api/voice/command")
        .send({ text: "Test command" });

      expect(res.status).toBe(401);
      expect(sendCommand).not.toHaveBeenCalled();
    });

    test("returns 403 when missing required scope", async () => {
      const token = makeToken(["other:scope"]);
      const res = await request(app)
        .post("/api/voice/command")
        .set("Authorization", authHeader(token))
        .send({ text: "Test command" });

      expect(res.status).toBe(403);
      expect(sendCommand).not.toHaveBeenCalled();
    });

    test("validates text field is required", async () => {
      const token = makeToken(["voice:command"]);
      const res = await request(app)
        .post("/api/voice/command")
        .set("Authorization", authHeader(token))
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Validation Error");
    });

    test("validates text minimum length", async () => {
      const token = makeToken(["voice:command"]);
      const res = await request(app)
        .post("/api/voice/command")
        .set("Authorization", authHeader(token))
        .send({ text: "" });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Validation Error");
    });

    test("validates text maximum length", async () => {
      const token = makeToken(["voice:command"]);
      const res = await request(app)
        .post("/api/voice/command")
        .set("Authorization", authHeader(token))
        .send({ text: "A".repeat(1001) });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Validation Error");
    });

    test("accepts text at maximum length boundary", async () => {
      sendCommand.mockResolvedValue({ status: "success" });

      const token = makeToken(["voice:command"]);
      const res = await request(app)
        .post("/api/voice/command")
        .set("Authorization", authHeader(token))
        .send({ text: "A".repeat(1000) });

      expect(res.status).toBe(200);
    });

    test("handles AI service errors gracefully", async () => {
      sendCommand.mockRejectedValue(new Error("Command processing failed"));

      const token = makeToken(["voice:command"]);
      const res = await request(app)
        .post("/api/voice/command")
        .set("Authorization", authHeader(token))
        .send({ text: "Test command" });

      expect(res.status).toBe(500);
      expect(res.body.error).toContain("Command processing failed");
    });
  });
});
