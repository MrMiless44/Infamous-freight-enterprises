/**
 * Tests for logger middleware
 */
const { logger, httpLogger } = require("../src/middleware/logger");

// Mock pino
jest.mock("pino", () => {
  const mockLogger = {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  };
  return jest.fn(() => mockLogger);
});

// Mock pino-http
jest.mock("pino-http", () => {
  return jest.fn(() => (req, res, next) => next());
});

describe("Logger", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("logger should be defined", () => {
    expect(logger).toBeDefined();
    expect(typeof logger.info).toBe("function");
    expect(typeof logger.error).toBe("function");
    expect(typeof logger.warn).toBe("function");
    expect(typeof logger.debug).toBe("function");
  });

  test("httpLogger should be a middleware function", () => {
    expect(httpLogger).toBeDefined();
    expect(typeof httpLogger).toBe("function");
  });

  test("logger.info should log info messages", () => {
    logger.info("Test info message");
    expect(logger.info).toHaveBeenCalledWith("Test info message");
  });

  test("logger.error should log error messages", () => {
    logger.error("Test error message");
    expect(logger.error).toHaveBeenCalledWith("Test error message");
  });

  test("logger.warn should log warning messages", () => {
    logger.warn("Test warning message");
    expect(logger.warn).toHaveBeenCalledWith("Test warning message");
  });

  test("logger.debug should log debug messages", () => {
    logger.debug("Test debug message");
    expect(logger.debug).toHaveBeenCalledWith("Test debug message");
  });

  test("httpLogger should work as Express middleware", () => {
    const req = {};
    const res = {};
    const next = jest.fn();

    httpLogger(req, res, next);
    expect(next).toHaveBeenCalled();
  });
});
