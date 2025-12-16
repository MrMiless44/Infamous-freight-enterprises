/**
 * Tests for error handler middleware
 */
const errorHandler = require("../src/middleware/errorHandler");

// Mock logger
jest.mock("../src/middleware/logger", () => ({
  logger: {
    error: jest.fn(),
  },
}));

describe("Error Handler Middleware", () => {
  let req, res, next;
  const { logger } = require("../src/middleware/logger");

  beforeEach(() => {
    req = {
      path: "/test",
      method: "GET",
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    next = jest.fn();
    logger.error.mockClear();
  });

  test("should handle MulterError", () => {
    const err = new Error("File too large");
    err.name = "MulterError";

    errorHandler(err, req, res, next);

    expect(logger.error).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "File Upload Error",
      message: "File too large",
    });
  });

  test("should handle LIMIT_FILE_SIZE error", () => {
    const err = new Error("File size limit exceeded");
    err.code = "LIMIT_FILE_SIZE";

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "File Upload Error",
      message: "File size limit exceeded",
    });
  });

  test("should handle file upload error without message", () => {
    const err = new Error();
    err.name = "MulterError";
    delete err.message;

    errorHandler(err, req, res, next);

    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "File Upload Error",
      message: "Invalid file upload",
    });
  });

  test("should handle validation error with status 400", () => {
    const err = new Error("Validation failed");
    err.status = 400;

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Validation Error",
      details: "Validation failed",
    });
  });

  test("should handle validation error with array method", () => {
    const validationErrors = [{ msg: "Email required" }, { msg: "Name required" }];
    const err = new Error();
    err.array = jest.fn(() => validationErrors);

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Validation Error",
      details: validationErrors,
    });
  });

  test("should handle 401 authentication error", () => {
    const err = new Error("Invalid token");
    err.status = 401;

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Unauthorized",
      message: "Invalid token",
    });
  });

  test("should handle 401 error without message", () => {
    const err = new Error();
    err.status = 401;
    delete err.message;

    errorHandler(err, req, res, next);

    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Unauthorized",
      message: "Authentication required",
    });
  });

  test("should handle 403 forbidden error", () => {
    const err = new Error("Insufficient permissions");
    err.status = 403;

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Forbidden",
      message: "Insufficient permissions",
    });
  });

  test("should handle 403 error without message", () => {
    const err = new Error();
    err.status = 403;
    delete err.message;

    errorHandler(err, req, res, next);

    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Forbidden",
      message: "Access denied",
    });
  });

  test("should handle 404 not found error", () => {
    const err = new Error("User not found");
    err.status = 404;

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Not Found",
      message: "User not found",
    });
  });

  test("should handle 404 error without message", () => {
    const err = new Error();
    err.status = 404;
    delete err.message;

    errorHandler(err, req, res, next);

    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Not Found",
      message: "Resource not found",
    });
  });

  test("should handle 500 server error in production", () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";

    const err = new Error("Database connection failed");
    err.status = 500;

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Server Error",
      message: "Internal server error",
    });

    process.env.NODE_ENV = originalEnv;
  });

  test("should handle 500 server error in development", () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "development";

    const err = new Error("Database connection failed");
    err.status = 500;

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Server Error",
      message: "Database connection failed",
    });

    process.env.NODE_ENV = originalEnv;
  });

  test("should handle error without status (default to 500)", () => {
    const err = new Error("Unexpected error");

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Server Error",
      message: "Unexpected error",
    });
  });

  test("should handle error without message", () => {
    const err = new Error();
    delete err.message;

    errorHandler(err, req, res, next);

    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Server Error",
      message: "Unexpected error",
    });
  });

  test("should handle custom status codes", () => {
    const err = new Error("Payment required");
    err.status = 402;

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(402);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: "Request Error",
      message: "Payment required",
    });
  });

  test("should handle non-integer status codes", () => {
    const err = new Error("Bad status");
    err.status = "invalid";

    errorHandler(err, req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
  });

  test("should log error details", () => {
    const err = new Error("Test error");
    err.stack = "Error: Test error\n    at test.js:10:5";

    errorHandler(err, req, res, next);

    expect(logger.error).toHaveBeenCalledWith({
      msg: "Error occurred",
      error: "Test error",
      stack: err.stack,
      path: "/test",
      method: "GET",
    });
  });
});
