import { Request, Response, NextFunction } from "express";
import { authenticate, requireScope } from "../../middleware/security";
import jwt from "jsonwebtoken";

jest.mock("jsonwebtoken");

describe("Security Middleware", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  beforeEach(() => {
    req = {
      headers: {},
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    next = jest.fn();
    jest.clearAllMocks();
  });

  describe("authenticate", () => {
    it("should allow requests with valid JWT", async () => {
      const token = "valid-jwt-token";
      req.headers = { authorization: `Bearer ${token}` };

      (jwt.verify as jest.Mock).mockReturnValue({
        sub: "user-123",
        email: "user@example.com",
      });

      await authenticate(req as Request, res as Response, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).user).toBeDefined();
    });

    it("should reject requests without token", async () => {
      req.headers = {};

      await authenticate(req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it("should reject requests with invalid token", async () => {
      req.headers = { authorization: "Bearer invalid-token" };

      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error("Invalid token");
      });

      await authenticate(req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it("should handle expired tokens", async () => {
      req.headers = { authorization: "Bearer expired-token" };

      (jwt.verify as jest.Mock).mockImplementation(() => {
        const err = new Error("Token expired");
        (err as any).name = "TokenExpiredError";
        throw err;
      });

      await authenticate(req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(401);
    });
  });

  describe("requireScope", () => {
    it("should allow requests with required scope", async () => {
      (req as any).user = {
        sub: "user-123",
        scopes: ["shipment:create", "shipment:read"],
      };

      const middleware = requireScope("shipment:create");
      await middleware(req as Request, res as Response, next);

      expect(next).toHaveBeenCalled();
    });

    it("should reject requests without required scope", async () => {
      (req as any).user = {
        sub: "user-123",
        scopes: ["shipment:read"],
      };

      const middleware = requireScope("shipment:create");
      await middleware(req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it("should support multiple scopes", async () => {
      (req as any).user = {
        sub: "user-123",
        scopes: ["shipment:create", "shipment:read"],
      };

      const middleware = requireScope(["shipment:create", "shipment:delete"]);
      await middleware(req as Request, res as Response, next);

      expect(next).toHaveBeenCalled();
    });

    it("should handle missing user", async () => {
      req = { headers: {} };

      const middleware = requireScope("shipment:create");
      await middleware(req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(401);
    });
  });
});
