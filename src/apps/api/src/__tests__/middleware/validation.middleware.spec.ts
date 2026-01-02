import { Request, Response, NextFunction } from "express";
import {
  validateString,
  handleValidationErrors,
} from "../../middleware/validation";
import { validationResult } from "express-validator";

jest.mock("express-validator");

describe("Validation Middleware", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  beforeEach(() => {
    req = {
      body: {},
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    next = jest.fn();
    jest.clearAllMocks();
  });

  describe("validateString", () => {
    it("should validate string field", async () => {
      const validator = validateString("email");

      expect(validator).toBeDefined();
    });

    it("should accept valid strings", async () => {
      req.body = { email: "test@example.com" };

      const validator = validateString("email");
      await validator.run(req as Request);

      const errors = validationResult(req as Request);
      expect(errors.isEmpty()).toBe(true);
    });

    it("should reject empty strings", async () => {
      req.body = { email: "" };

      const validator = validateString("email");
      await validator.run(req as Request);

      const errors = validationResult(req as Request);
      expect(errors.isEmpty()).toBe(false);
    });
  });

  describe("handleValidationErrors", () => {
    it("should pass on valid data", async () => {
      (validationResult as jest.Mock).mockReturnValue({
        isEmpty: () => true,
      });

      handleValidationErrors(req as Request, res as Response, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it("should return errors on validation failure", async () => {
      (validationResult as jest.Mock).mockReturnValue({
        isEmpty: () => false,
        array: () => [
          {
            msg: "Invalid email",
            param: "email",
          },
        ],
      });

      handleValidationErrors(req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(422);
      expect(res.json).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it("should format error response correctly", async () => {
      (validationResult as jest.Mock).mockReturnValue({
        isEmpty: () => false,
        array: () => [
          {
            msg: "Invalid format",
            param: "phone",
            value: "abc",
          },
        ],
      });

      handleValidationErrors(req as Request, res as Response, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errors: expect.any(Array),
        }),
      );
    });
  });
});
