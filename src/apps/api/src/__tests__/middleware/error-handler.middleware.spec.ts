import { Request, Response, NextFunction } from "express";
import { errorHandler } from "../../middleware/errorHandler";
import logger from "../../middleware/logger";

jest.mock("../../middleware/logger");

describe("Error Handler Middleware", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  beforeEach(() => {
    req = {
      path: "/test",
      method: "GET",
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    next = jest.fn();
    jest.clearAllMocks();
  });

  describe("errorHandler", () => {
    it("should handle validation errors", async () => {
      const error = new Error("Validation failed");
      (error as any).status = 422;

      errorHandler(error, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(422);
      expect(res.json).toHaveBeenCalled();
    });

    it("should handle not found errors", async () => {
      const error = new Error("Resource not found");
      (error as any).status = 404;

      errorHandler(error, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(404);
    });

    it("should handle unauthorized errors", async () => {
      const error = new Error("Unauthorized");
      (error as any).status = 401;

      errorHandler(error, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(401);
    });

    it("should default to 500 for unknown errors", async () => {
      const error = new Error("Unknown error");

      errorHandler(error, req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(500);
    });

    it("should log errors", async () => {
      const error = new Error("Test error");
      (error as any).status = 500;

      errorHandler(error, req as Request, res as Response, next);

      expect(logger.error).toHaveBeenCalled();
    });

    it("should include error message in response", async () => {
      const error = new Error("Test error message");
      (error as any).status = 400;

      errorHandler(error, req as Request, res as Response, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "Test error message",
        }),
      );
    });
  });
});
