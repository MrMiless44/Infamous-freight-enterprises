const originalEnv = { ...process.env };

beforeEach(() => {
  jest.resetModules();
  jest.clearAllMocks();
  process.env = { ...originalEnv };
});

afterAll(() => {
  process.env = originalEnv;
});

const mockLogger = () => {
  jest.doMock("../../middleware/logger", () => ({
    logger: {
      error: jest.fn(),
      info: jest.fn(),
    },
  }));
};

describe("aiSyntheticClient sendCommand", () => {
  test("uses synthetic provider when configured", async () => {
    process.env.AI_SYNTHETIC_ENGINE_URL = "https://synthetic.test/command";
    process.env.AI_SYNTHETIC_API_KEY = "synthetic-key";
    process.env.AI_SECURITY_MODE = "relaxed";

    const postMock = jest.fn(() => Promise.resolve({ data: { ok: true } }));
    mockLogger();
    jest.doMock("axios", () => ({
      create: jest.fn(() => ({ post: postMock })),
    }));

    const { sendCommand } = require("../aiSyntheticClient");
    const result = await sendCommand(
      "track.shipment",
      { reference: "NF-123" },
      { source: "test" },
    );

    expect(result).toEqual({ ok: true });
    expect(postMock).toHaveBeenCalledWith(
      "https://synthetic.test/command",
      {
        command: "track.shipment",
        payload: { reference: "NF-123" },
        meta: { source: "test" },
      },
      {
        headers: {
          "x-api-key": "synthetic-key",
          "x-security-mode": "relaxed",
        },
      },
    );
  });

  test("throws helpful error when synthetic engine is missing", async () => {
    delete process.env.AI_SYNTHETIC_ENGINE_URL;
    delete process.env.AI_SYNTHETIC_API_KEY;

    mockLogger();
    jest.doMock("axios", () => ({
      create: jest.fn(() => ({ post: jest.fn() })),
    }));

    const { sendCommand } = require("../aiSyntheticClient");

    await expect(sendCommand("anything")).rejects.toMatchObject({
      message: "Synthetic AI engine not configured",
      status: 503,
    });
  });

  test("surfaces upstream errors from synthetic engine", async () => {
    process.env.AI_SYNTHETIC_ENGINE_URL = "https://synthetic.test/command";
    process.env.AI_SYNTHETIC_API_KEY = "synthetic-key";

    const postMock = jest.fn(() =>
      Promise.reject({
        response: {
          status: 429,
          data: { error: "rate limit" },
        },
      }),
    );
    mockLogger();
    jest.doMock("axios", () => ({
      create: jest.fn(() => ({ post: postMock })),
    }));

    const { sendCommand } = require("../aiSyntheticClient");

    await expect(sendCommand("track")).rejects.toMatchObject({
      message: "Synthetic AI engine request failed",
      status: 429,
      details: { error: "rate limit" },
    });
    expect(postMock).toHaveBeenCalledTimes(1);
  });

  test("routes through OpenAI when provider configured", async () => {
    process.env.AI_PROVIDER = "openai";
    process.env.OPENAI_API_KEY = "openai-key";

    const completionMock = jest.fn(() =>
      Promise.resolve({
        choices: [{ message: { content: "Completed request" } }],
      }),
    );
    const OpenAI = jest.fn(() => ({
      chat: {
        completions: {
          create: completionMock,
        },
      },
    }));
    mockLogger();
    jest.doMock("axios", () => ({
      create: jest.fn(() => ({ post: jest.fn() })),
    }));
    jest.doMock("openai", () => OpenAI);

    const { sendCommand } = require("../aiSyntheticClient");
    const result = await sendCommand("summarize", { text: "Details" });

    expect(result).toEqual({
      provider: "openai",
      text: "Completed request",
    });
    expect(OpenAI).toHaveBeenCalledWith({
      apiKey: "openai-key",
      timeout: 8000,
    });
    expect(completionMock).toHaveBeenCalledTimes(1);
  });

  test("throws when OpenAI provider lacks configuration", async () => {
    process.env.AI_PROVIDER = "openai";
    delete process.env.OPENAI_API_KEY;

    mockLogger();
    jest.doMock("axios", () => ({
      create: jest.fn(() => ({ post: jest.fn() })),
    }));

    const { sendCommand } = require("../aiSyntheticClient");

    await expect(sendCommand("anything")).rejects.toMatchObject({
      message: "OpenAI not configured",
      status: 503,
    });
  });
});

describe("Circuit Breaker", () => {
  test("should provide circuit breaker statistics", async () => {
    process.env.AI_SYNTHETIC_ENGINE_URL = "https://synthetic.test/command";
    process.env.AI_SYNTHETIC_API_KEY = "synthetic-key";

    mockLogger();
    jest.doMock("axios", () => ({
      create: jest.fn(() => ({
        post: jest.fn(() => Promise.resolve({ data: { ok: true } })),
      })),
    }));

    const { getCircuitBreakerStats } = require("../aiSyntheticClient");
    const stats = getCircuitBreakerStats();

    expect(stats).toHaveProperty("synthetic");
    expect(stats).toHaveProperty("openai");
    expect(stats).toHaveProperty("anthropic");
    expect(stats.synthetic).toHaveProperty("name");
    expect(stats.synthetic).toHaveProperty("state");
    expect(stats.synthetic).toHaveProperty("stats");
  });

  test("should open circuit after repeated failures", async () => {
    process.env.AI_SYNTHETIC_ENGINE_URL = "https://synthetic.test/command";
    process.env.AI_SYNTHETIC_API_KEY = "synthetic-key";

    const logger = {
      error: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
    };

    jest.doMock("../../middleware/logger", () => ({ logger }));

    const failingPost = jest.fn(() =>
      Promise.reject({ 
        response: { status: 500, data: { error: "Internal Error" } },
        code: "ERR_INTERNAL" 
      })
    );

    jest.doMock("axios", () => ({
      create: jest.fn(() => ({ post: failingPost })),
    }));

    const { sendCommand, getCircuitBreakerStats } = require("../aiSyntheticClient");

    // Send multiple failing requests
    for (let i = 0; i < 10; i++) {
      try {
        await sendCommand("test", {});
      } catch (err) {
        // Expected to fail
      }
    }

    const stats = getCircuitBreakerStats();
    
    // Circuit should be open after repeated failures
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("Circuit breaker opened")
    );
  }, 10000);

  test("should provide direct access without circuit breaker", async () => {
    process.env.AI_SYNTHETIC_ENGINE_URL = "https://synthetic.test/command";
    process.env.AI_SYNTHETIC_API_KEY = "synthetic-key";

    mockLogger();
    const postMock = jest.fn(() => Promise.resolve({ data: { result: "success" } }));

    jest.doMock("axios", () => ({
      create: jest.fn(() => ({ post: postMock })),
    }));

    const { sendCommandDirect } = require("../aiSyntheticClient");
    const result = await sendCommandDirect("test", { data: "test" });

    expect(result).toEqual({ result: "success" });
    expect(postMock).toHaveBeenCalled();
  });
});

