/**
 * Tests for validation middleware
 */
const { validateEmail, validateString, validatePhone, validateUUID, handleValidationErrors } = require("../src/middleware/validation");
const { validationResult } = require("express-validator");

// Mock express-validator
jest.mock("express-validator", () => ({
  body: jest.fn(() => ({
    isEmail: jest.fn().mockReturnThis(),
    normalizeEmail: jest.fn().mockReturnThis(),
    trim: jest.fn().mockReturnThis(),
    isString: jest.fn().mockReturnThis(),
    notEmpty: jest.fn().mockReturnThis(),
    withMessage: jest.fn().mockReturnThis(),
    isLength: jest.fn().mockReturnThis(),
    optional: jest.fn().mockReturnThis(),
    isMobilePhone: jest.fn().mockReturnThis(),
    isUUID: jest.fn().mockReturnThis(),
  })),
  validationResult: jest.fn(),
}));

describe("Validation Middleware", () => {
  describe("validateEmail", () => {
    test("should create email validator", () => {
      const validator = validateEmail();
      expect(validator).toBeDefined();
    });
  });

  describe("validateString", () => {
    test("should create string validator with default options", () => {
      const validator = validateString("name");
      expect(validator).toBeDefined();
    });

    test("should create string validator with custom options", () => {
      const validator = validateString("description", { min: 10, max: 200 });
      expect(validator).toBeDefined();
    });
  });

  describe("validatePhone", () => {
    test("should create phone validator", () => {
      const validator = validatePhone();
      expect(validator).toBeDefined();
    });
  });

  describe("validateUUID", () => {
    test("should create UUID validator", () => {
      const validator = validateUUID("id");
      expect(validator).toBeDefined();
    });
  });

  describe("handleValidationErrors", () => {
    let req, res, next;

    beforeEach(() => {
      req = {};
      res = {};
      next = jest.fn();
    });

    test("should call next when no validation errors", () => {
      validationResult.mockReturnValue({
        isEmpty: jest.fn(() => true),
      });

      handleValidationErrors(req, res, next);

      expect(next).toHaveBeenCalledWith();
    });

    test("should pass error to next when validation errors exist", () => {
      const errors = [
        { msg: "Email is invalid" },
        { msg: "Name is required" },
      ];

      validationResult.mockReturnValue({
        isEmpty: jest.fn(() => false),
        array: jest.fn(() => errors),
      });

      handleValidationErrors(req, res, next);

      expect(next).toHaveBeenCalled();
      const error = next.mock.calls[0][0];
      expect(error.message).toBe("Validation failed");
      expect(error.status).toBe(400);
      expect(error.array()).toEqual(errors);
    });
  });
});
