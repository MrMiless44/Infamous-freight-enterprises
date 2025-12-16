const jwt = require("jsonwebtoken");
const { authHybrid, apiKeyAuth, jwtAuth } = require("../auth.hybrid");

describe("Authentication Middleware", () => {
  let req, res, next;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    req = {
      headers: {},
      ip: "127.0.0.1",
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    next = jest.fn();
    
    // Set test environment variables
    process.env.JWT_SECRET = "test-secret-key";
    process.env.AI_SYNTHETIC_API_KEY = "test-api-key-12345";
  });

  afterEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };
  });

  describe("authHybrid", () => {
    it("should authenticate with valid API key", () => {
      req.headers["x-api-key"] = "test-api-key-12345";

      authHybrid(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.auth).toEqual({
        mode: "api-key",
        scopes: ["ai:query", "data:read", "system:admin", "ai:repair"],
        subject: "ai-synthetic-engine",
      });
    });

    it("should authenticate with valid JWT token", () => {
      const token = jwt.sign(
        { 
          sub: "user123", 
          scopes: ["user:read", "user:write"] 
        },
        "test-secret-key",
        { expiresIn: "1h", issuer: "infamous-freight-api", audience: "infamous-freight-app" }
      );
      req.headers.authorization = `Bearer ${token}`;

      authHybrid(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.auth.mode).toBe("jwt");
      expect(req.auth.subject).toBe("user123");
      expect(req.user).toBeDefined();
    });

    it("should reject expired JWT token", () => {
      const token = jwt.sign(
        { sub: "user123" },
        "test-secret-key",
        { expiresIn: "-1h", issuer: "infamous-freight-api", audience: "infamous-freight-app" }
      );
      req.headers.authorization = `Bearer ${token}`;

      authHybrid(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ 
          error: "Token expired",
          code: "TOKEN_EXPIRED"
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it("should reject invalid JWT token", () => {
      req.headers.authorization = "Bearer invalid-token";

      authHybrid(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ 
          error: "Invalid token",
          code: "INVALID_TOKEN"
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it("should reject token used before valid (nbf)", () => {
      const futureTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour in future
      const token = jwt.sign(
        { sub: "user123", nbf: futureTime },
        "test-secret-key",
        { issuer: "infamous-freight-api", audience: "infamous-freight-app" }
      );
      req.headers.authorization = `Bearer ${token}`;

      authHybrid(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ 
          error: "Token not yet valid",
          code: "TOKEN_NOT_ACTIVE"
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it("should reject when no credentials provided", () => {
      authHybrid(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "Unauthorized" })
      );
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("apiKeyAuth", () => {
    it("should authenticate with valid API key", () => {
      req.headers["x-api-key"] = "test-api-key-12345";

      apiKeyAuth(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.auth.mode).toBe("api-key");
    });

    it("should reject missing API key", () => {
      apiKeyAuth(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "Missing API key" })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it("should reject invalid API key", () => {
      req.headers["x-api-key"] = "wrong-key";

      apiKeyAuth(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "Invalid API key" })
      );
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("jwtAuth", () => {
    it("should authenticate with valid JWT", () => {
      const token = jwt.sign(
        { sub: "user123", scopes: ["user:read"] },
        "test-secret-key",
        { expiresIn: "1h", issuer: "infamous-freight-api", audience: "infamous-freight-app" }
      );
      req.headers.authorization = `Bearer ${token}`;

      jwtAuth(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.auth.mode).toBe("jwt");
      expect(req.auth.subject).toBe("user123");
    });

    it("should reject missing bearer token", () => {
      jwtAuth(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "Missing bearer token" })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it("should reject invalid bearer format", () => {
      req.headers.authorization = "Basic username:password";

      jwtAuth(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "Missing bearer token" })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it("should handle JWT_SECRET not configured", () => {
      delete process.env.JWT_SECRET;
      const token = "some-token";
      req.headers.authorization = `Bearer ${token}`;

      jwtAuth(req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "Authentication not configured" })
      );
      expect(next).not.toHaveBeenCalled();
    });
  });
});
