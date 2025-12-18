const request = require("supertest");
const jwt = require("jsonwebtoken");

process.env.JWT_SECRET = "test-secret";

jest.mock("../src/services/aiSyntheticClient", () => ({
  sendCommand: jest.fn(),
}));

const { sendCommand } = require("../src/services/aiSyntheticClient");
const app = require("../src/server");

// Skip supertest tests on Node 22+ (target is Node 20.18.1, CI will run these)
const skipOnNode22 = global.skipSupertestOnNode22 ? describe.skip : describe;

const makeToken = (scopes) =>
  jwt.sign(
    {
      sub: "test-user",
      scopes,
    },
    process.env.JWT_SECRET,
  );

const authHeader = (token) => `Bearer ${token}`;

skipOnNode22("Route success flows", () => {
  beforeEach(() => {
    sendCommand.mockReset();
  });

  test("ai command executes when payload is valid", async () => {
    const token = makeToken(["ai:command"]);
    const mockResponse = { provider: "synthetic", text: "done" };
    sendCommand.mockResolvedValueOnce(mockResponse);

    const res = await request(app)
      .post("/api/ai/command")
      .set("Authorization", authHeader(token))
      .send({
        command: "optimize-route",
        payload: { priority: "high" },
        meta: { origin: "dashboard" },
      });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.response).toEqual(mockResponse);
    expect(sendCommand).toHaveBeenCalledWith(
      "optimize-route",
      { priority: "high" },
      expect.objectContaining({ origin: "dashboard", user: "test-user" }),
    );
  });

  test("voice command forwards text to AI service", async () => {
    const token = makeToken(["voice:command"]);
    const mockResult = { message: "ack" };
    sendCommand.mockResolvedValueOnce(mockResult);

    const res = await request(app)
      .post("/api/voice/command")
      .set("Authorization", authHeader(token))
      .send({ text: "Hello dispatcher" });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.result).toEqual(mockResult);
    expect(sendCommand).toHaveBeenCalledWith("voice.command", {
      text: "Hello dispatcher",
    });
  });

  test("voice ingest accepts supported audio uploads", async () => {
    const token = makeToken(["voice:ingest"]);
    const aiResult = { id: "cmd-1", status: "queued" };
    sendCommand.mockResolvedValueOnce(aiResult);

    const res = await request(app)
      .post("/api/voice/ingest")
      .set("Authorization", authHeader(token))
      .attach("audio", Buffer.from("fake-binary"), {
        filename: "sample.mp3",
        contentType: "audio/mpeg",
      });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.ai).toEqual(aiResult);
    expect(res.body.transcript).toMatch(/Driver/i);
    expect(sendCommand).toHaveBeenCalledWith("voice.input", {
      transcript: expect.any(String),
    });
  });
});
