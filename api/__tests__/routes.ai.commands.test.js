const request = require("supertest");
const jwt = require("jsonwebtoken");

// Setup test environment
process.env.JWT_SECRET = "test-secret";
process.env.NODE_ENV = "test";
process.env.AI_PROVIDER = "synthetic";

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

skipOnNode22("AI Commands API Routes", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("POST /api/ai/command", () => {
    const validPayload = {
      command: "optimize_route",
      payload: { destination: "Chicago" },
      meta: { priority: "high" },
    };

    test("successfully processes AI command with valid scope", async () => {
      const mockResponse = { status: "success", data: { route: "optimized" } };
      sendCommand.mockResolvedValue(mockResponse);

      const token = makeToken(["ai:command"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send(validPayload);

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.response).toEqual(mockResponse);
      expect(sendCommand).toHaveBeenCalledWith(
        "optimize_route",
        { destination: "Chicago" },
        expect.objectContaining({
          priority: "high",
          user: "test-user-123",
        }),
      );
    });

    test("returns 401 when not authenticated", async () => {
      const res = await request(app).post("/api/ai/command").send(validPayload);

      expect(res.status).toBe(401);
      expect(sendCommand).not.toHaveBeenCalled();
    });

    test("returns 403 when missing required scope", async () => {
      const token = makeToken(["other:scope"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send(validPayload);

      expect(res.status).toBe(403);
      expect(sendCommand).not.toHaveBeenCalled();
    });

    test("validates command field is required", async () => {
      const token = makeToken(["ai:command"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send({
          payload: { destination: "Chicago" },
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Validation Error");
    });

    test("validates command length minimum", async () => {
      const token = makeToken(["ai:command"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send({
          command: "",
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Validation Error");
    });

    test("validates command length maximum", async () => {
      const token = makeToken(["ai:command"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send({
          command: "A".repeat(201),
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Validation Error");
    });

    test("validates payload must be object if provided", async () => {
      const token = makeToken(["ai:command"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send({
          command: "test_command",
          payload: "invalid",
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Validation Error");
    });

    test("validates meta must be object if provided", async () => {
      const token = makeToken(["ai:command"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send({
          command: "test_command",
          meta: "invalid",
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Validation Error");
    });

    test("accepts command with optional payload and meta", async () => {
      const mockResponse = { status: "success" };
      sendCommand.mockResolvedValue(mockResponse);

      const token = makeToken(["ai:command"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send({ command: "simple_command" });

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(sendCommand).toHaveBeenCalledWith(
        "simple_command",
        {},
        expect.objectContaining({ user: "test-user-123" }),
      );
    });

    test("handles AI service errors gracefully", async () => {
      sendCommand.mockRejectedValue(new Error("AI service unavailable"));

      const token = makeToken(["ai:command"]);
      const res = await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send(validPayload);

      expect(res.status).toBe(500);
      expect(res.body.error).toContain("AI service unavailable");
    });

    test("includes user context in AI command meta", async () => {
      const mockResponse = { status: "success" };
      sendCommand.mockResolvedValue(mockResponse);

      const token = makeToken(["ai:command"]);
      await request(app)
        .post("/api/ai/command")
        .set("Authorization", authHeader(token))
        .send({
          command: "test",
          meta: { existing: "value" },
        });

      expect(sendCommand).toHaveBeenCalledWith(
        "test",
        {},
        expect.objectContaining({
          existing: "value",
          user: "test-user-123",
        }),
      );
    });
  });
});
