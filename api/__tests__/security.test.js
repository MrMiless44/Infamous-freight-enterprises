const jwt = require("jsonwebtoken");
const express = require("express");

// Mock rate limiter
jest.mock("rate-limiter-flexible", () => ({
  RateLimiterMemory: jest.fn().mockImplementation(() => ({
    consume: jest.fn().mockResolvedValue(true),
  })),
}));

// Mock logger
jest.mock("../src/middleware/logger", () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

const { logger } = require("../src/middleware/logger");

describe("Security Middleware", () => {
  let security;
  let req, res, next;

  const JWT_SECRET = "test-secret-key";

  beforeEach(() => {
    // Set JWT_SECRET
    process.env.JWT_SECRET = JWT_SECRET;
    process.env.AUDIT_LOG = "on";

    // Clear module cache to get fresh instance
    jest.clearAllMocks();
    delete require.cache[require.resolve("../src/middleware/security")];
    security = require("../src/middleware/security");

    // Mock request, response, next
    req = {
      headers: {},
      ip: "127.0.0.1",
      path: "/test",
      method: "GET",
      connection: {},
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    next = jest.fn();
  });

  afterEach(() => {
    delete process.env.JWT_SECRET;
    delete process.env.AUDIT_LOG;
  });

  describe("authenticate", () => {
    test("should authenticate valid JWT token", () => {
      const token = jwt.sign({ sub: "user123", scopes: ["read"] }, JWT_SECRET);
      req.headers.authorization = `Bearer ${token}`;

      security.authenticate(req, res, next);

      expect(req.user).toBeDefined();
      expect(req.user.sub).toBe("user123");
      expect(req.user.scopes).toEqual(["read"]);
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should reject missing authorization header", () => {
      security.authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: "Missing bearer token" });
      expect(next).not.toHaveBeenCalled();
    });

    test("should reject authorization header without Bearer prefix", () => {
      req.headers.authorization = "Basic abc123";

      security.authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: "Missing bearer token" });
      expect(next).not.toHaveBeenCalled();
    });

    test("should reject invalid JWT token", () => {
      req.headers.authorization = "Bearer invalid.token.here";

      security.authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: "Invalid token" });
      expect(next).not.toHaveBeenCalled();
    });

    test("should reject expired JWT token", () => {
      const expiredToken = jwt.sign(
        { sub: "user123", exp: Math.floor(Date.now() / 1000) - 3600 },
        JWT_SECRET
      );
      req.headers.authorization = `Bearer ${expiredToken}`;

      security.authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: "Invalid token" });
      expect(next).not.toHaveBeenCalled();
    });

    test("should reject token with wrong secret", () => {
      const token = jwt.sign({ sub: "user123" }, "wrong-secret");
      req.headers.authorization = `Bearer ${token}`;

      security.authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: "Invalid token" });
      expect(next).not.toHaveBeenCalled();
    });

    test("should handle Bearer token with extra whitespace", () => {
      const token = jwt.sign({ sub: "user123" }, JWT_SECRET);
      req.headers.authorization = `Bearer   ${token}  `;

      security.authenticate(req, res, next);

      expect(req.user).toBeDefined();
      expect(req.user.sub).toBe("user123");
      expect(next).toHaveBeenCalled();
    });

    test("should skip authentication when JWT_SECRET not set", () => {
      delete process.env.JWT_SECRET;
      delete require.cache[require.resolve("../src/middleware/security")];
      security = require("../src/middleware/security");

      security.authenticate(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should handle malformed JWT structure", () => {
      req.headers.authorization = "Bearer not.a.jwt";

      security.authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: "Invalid token" });
    });

    test("should handle empty Bearer token", () => {
      req.headers.authorization = "Bearer ";

      security.authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: "Invalid token" });
    });
  });

  describe("requireScope", () => {
    beforeEach(() => {
      req.user = { sub: "user123", scopes: ["read", "write"] };
    });

    test("should allow access with required scope", () => {
      const middleware = security.requireScope("read");
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should deny access without required scope", () => {
      const middleware = security.requireScope("admin");
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: "Insufficient scope" });
      expect(next).not.toHaveBeenCalled();
    });

    test("should deny access when user has no scopes", () => {
      req.user = { sub: "user123" };
      const middleware = security.requireScope("read");
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: "Insufficient scope" });
    });

    test("should deny access when user is undefined", () => {
      req.user = undefined;
      const middleware = security.requireScope("read");
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: "Insufficient scope" });
    });

    test("should allow access when scope is not specified", () => {
      const middleware = security.requireScope(null);
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should allow access when scope is empty string", () => {
      const middleware = security.requireScope("");
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should check exact scope match", () => {
      req.user = { sub: "user123", scopes: ["read:partial"] };
      const middleware = security.requireScope("read");
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: "Insufficient scope" });
    });
  });

  describe("auditLog", () => {
    beforeEach(() => {
      req.user = { sub: "user123" };
      req.path = "/api/test";
      req.method = "POST";
      req.ip = "192.168.1.1";
    });

    test("should log request details when audit logging enabled", () => {
      process.env.AUDIT_LOG = "on";
      delete require.cache[require.resolve("../src/middleware/security")];
      security = require("../src/middleware/security");

      security.auditLog(req, res, next);

      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          path: "/api/test",
          method: "POST",
          user: "user123",
          ip: "192.168.1.1",
        })
      );
      expect(next).toHaveBeenCalled();
    });

    test("should not log when audit logging disabled", () => {
      process.env.AUDIT_LOG = "off";
      delete require.cache[require.resolve("../src/middleware/security")];
      security = require("../src/middleware/security");

      security.auditLog(req, res, next);

      expect(logger.info).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    test("should log when AUDIT_LOG not set (defaults to on)", () => {
      delete process.env.AUDIT_LOG;
      delete require.cache[require.resolve("../src/middleware/security")];
      security = require("../src/middleware/security");

      security.auditLog(req, res, next);

      expect(logger.info).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    test("should handle missing user in request", () => {
      delete req.user;

      security.auditLog(req, res, next);

      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          user: undefined,
        })
      );
      expect(next).toHaveBeenCalled();
    });

    test("should include timestamp in log", () => {
      security.auditLog(req, res, next);

      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          ts: expect.any(String),
        })
      );
    });
  });

  describe("rateLimit", () => {
    test("should allow request when under rate limit", async () => {
      const { RateLimiterMemory } = require("rate-limiter-flexible");
      const mockConsume = jest.fn().mockResolvedValue(true);
      RateLimiterMemory.mockImplementation(() => ({
        consume: mockConsume,
      }));

      delete require.cache[require.resolve("../src/middleware/security")];
      security = require("../src/middleware/security");

      await security.rateLimit(req, res, next);

      expect(mockConsume).toHaveBeenCalledWith("127.0.0.1");
      expect(next).toHaveBeenCalled();
    });

    test("should reject request when rate limit exceeded", async () => {
      const { RateLimiterMemory } = require("rate-limiter-flexible");
      const mockConsume = jest.fn().mockRejectedValue(new Error("Rate limit exceeded"));
      RateLimiterMemory.mockImplementation(() => ({
        consume: mockConsume,
      }));

      delete require.cache[require.resolve("../src/middleware/security")];
      security = require("../src/middleware/security");

      await security.rateLimit(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: "Too many requests",
          status: 429,
        })
      );
    });

    test("should use connection.remoteAddress when ip not available", async () => {
      const { RateLimiterMemory } = require("rate-limiter-flexible");
      const mockConsume = jest.fn().mockResolvedValue(true);
      RateLimiterMemory.mockImplementation(() => ({
        consume: mockConsume,
      }));

      delete require.cache[require.resolve("../src/middleware/security")];
      security = require("../src/middleware/security");

      delete req.ip;
      req.connection.remoteAddress = "10.0.0.1";

      await security.rateLimit(req, res, next);

      expect(mockConsume).toHaveBeenCalledWith("10.0.0.1");
    });

    test("should use 'global' when neither ip nor remoteAddress available", async () => {
      const { RateLimiterMemory } = require("rate-limiter-flexible");
      const mockConsume = jest.fn().mockResolvedValue(true);
      RateLimiterMemory.mockImplementation(() => ({
        consume: mockConsume,
      }));

      delete require.cache[require.resolve("../src/middleware/security")];
      security = require("../src/middleware/security");

      delete req.ip;
      req.connection = {};

      await security.rateLimit(req, res, next);

      expect(mockConsume).toHaveBeenCalledWith("global");
    });
  });

  describe("createLimiter", () => {
    test("should create limiter with default options", () => {
      const limiter = security.createLimiter();
      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe("function");
    });

    test("should create limiter with custom options", () => {
      const limiter = security.createLimiter({
        windowMs: 60000,
        max: 50,
        message: "Custom message",
      });
      expect(limiter).toBeDefined();
    });
  });

  describe("limiters presets", () => {
    test("should export general limiter", () => {
      expect(security.limiters.general).toBeDefined();
      expect(typeof security.limiters.general).toBe("function");
    });

    test("should export auth limiter", () => {
      expect(security.limiters.auth).toBeDefined();
      expect(typeof security.limiters.auth).toBe("function");
    });

    test("should export billing limiter", () => {
      expect(security.limiters.billing).toBeDefined();
      expect(typeof security.limiters.billing).toBe("function");
    });

    test("should export ai limiter", () => {
      expect(security.limiters.ai).toBeDefined();
      expect(typeof security.limiters.ai).toBe("function");
    });
  });
});
