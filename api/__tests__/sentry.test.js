// Mock Sentry before requiring the module
jest.mock("@sentry/node", () => ({
  init: jest.fn(),
  Handlers: {
    requestHandler: jest.fn(() => (req, res, next) => next()),
    tracingHandler: jest.fn(() => (req, res, next) => next()),
    errorHandler: jest.fn(() => (err, req, res, next) => next(err)),
  },
  Integrations: {
    Http: jest.fn(),
    Express: jest.fn(),
  },
  captureException: jest.fn(),
  captureMessage: jest.fn(),
}));

// Mock profiling integration (may not be available)
jest.mock("@sentry/profiling-node", () => ({
  nodeProfilingIntegration: jest.fn(() => ({})),
}), { virtual: true });

const Sentry = require("@sentry/node");
const express = require("express");

describe("Sentry Configuration", () => {
  let originalEnv;
  let consoleLogSpy;
  let consoleWarnSpy;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Clear all mocks
    jest.clearAllMocks();
    
    // Spy on console methods
    consoleLogSpy = jest.spyOn(console, "log").mockImplementation();
    consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation();
    
    // Clear require cache to ensure fresh module load
    delete require.cache[require.resolve("../src/config/sentry")];
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
    
    // Restore console methods
    consoleLogSpy.mockRestore();
    consoleWarnSpy.mockRestore();
  });

  describe("initSentry", () => {
    test("should initialize Sentry in production with DSN", () => {
      process.env.NODE_ENV = "production";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { initSentry } = require("../src/config/sentry");
      const app = express();

      initSentry(app);

      expect(Sentry.init).toHaveBeenCalledWith(
        expect.objectContaining({
          dsn: "https://test@sentry.io/123",
          environment: "production",
          tracesSampleRate: 0.1,
          profilesSampleRate: 0.1,
        })
      );
      expect(Sentry.Handlers.requestHandler).toHaveBeenCalled();
      expect(Sentry.Handlers.tracingHandler).toHaveBeenCalled();
      expect(consoleLogSpy).toHaveBeenCalledWith(
        "✓ Sentry error tracking initialized"
      );
    });

    test("should not initialize Sentry in development", () => {
      process.env.NODE_ENV = "development";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { initSentry } = require("../src/config/sentry");
      const app = express();

      initSentry(app);

      expect(Sentry.init).not.toHaveBeenCalled();
      expect(consoleLogSpy).toHaveBeenCalledWith(
        "ℹ Sentry disabled in development/test environment"
      );
    });

    test("should not initialize Sentry in test environment", () => {
      process.env.NODE_ENV = "test";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { initSentry } = require("../src/config/sentry");
      const app = express();

      initSentry(app);

      expect(Sentry.init).not.toHaveBeenCalled();
      expect(consoleLogSpy).toHaveBeenCalledWith(
        "ℹ Sentry disabled in development/test environment"
      );
    });

    test("should warn when DSN not configured in production", () => {
      process.env.NODE_ENV = "production";
      delete process.env.SENTRY_DSN;

      const { initSentry } = require("../src/config/sentry");
      const app = express();

      initSentry(app);

      expect(Sentry.init).not.toHaveBeenCalled();
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        "⚠ Sentry DSN not configured - error tracking disabled"
      );
    });

    test("should include profiling integration when available", () => {
      process.env.NODE_ENV = "production";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { initSentry } = require("../src/config/sentry");
      const app = express();

      initSentry(app);

      const initCall = Sentry.init.mock.calls[0][0];
      expect(initCall.integrations).toBeDefined();
      expect(Array.isArray(initCall.integrations)).toBe(true);
    });

    test("should include HTTP and Express integrations", () => {
      process.env.NODE_ENV = "production";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { initSentry } = require("../src/config/sentry");
      const app = express();

      initSentry(app);

      expect(Sentry.Integrations.Http).toHaveBeenCalledWith({ tracing: true });
      expect(Sentry.Integrations.Express).toHaveBeenCalledWith(
        expect.objectContaining({
          request: true,
          serverName: false,
          transaction: "name",
          version: false,
          paths: [],
        })
      );
    });

    test("should configure ignored errors", () => {
      process.env.NODE_ENV = "production";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { initSentry } = require("../src/config/sentry");
      const app = express();

      initSentry(app);

      const initCall = Sentry.init.mock.calls[0][0];
      expect(initCall.ignoreErrors).toContain("top.GLOBALS");
      expect(initCall.ignoreErrors).toContain("chrome-extension://");
      expect(initCall.ignoreErrors).toContain("moz-extension://");
      expect(initCall.ignoreErrors).toContain("NetworkError");
      expect(initCall.ignoreErrors).toContain("Network request failed");
    });
  });

  describe("attachErrorHandler", () => {
    test("should attach error handler in production with DSN", () => {
      process.env.NODE_ENV = "production";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { attachErrorHandler } = require("../src/config/sentry");
      const app = express();

      attachErrorHandler(app);

      expect(Sentry.Handlers.errorHandler).toHaveBeenCalled();
    });

    test("should not attach error handler in development", () => {
      process.env.NODE_ENV = "development";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { attachErrorHandler } = require("../src/config/sentry");
      const app = express();

      attachErrorHandler(app);

      expect(Sentry.Handlers.errorHandler).not.toHaveBeenCalled();
    });

    test("should not attach error handler without DSN", () => {
      process.env.NODE_ENV = "production";
      delete process.env.SENTRY_DSN;

      const { attachErrorHandler } = require("../src/config/sentry");
      const app = express();

      attachErrorHandler(app);

      expect(Sentry.Handlers.errorHandler).not.toHaveBeenCalled();
    });
  });

  describe("captureException", () => {
    test("should capture exception when DSN configured", () => {
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { captureException } = require("../src/config/sentry");
      const error = new Error("Test error");
      const context = { userId: "123" };

      captureException(error, context);

      expect(Sentry.captureException).toHaveBeenCalledWith(error, {
        contexts: { custom: context },
      });
    });

    test("should not capture exception without DSN", () => {
      delete process.env.SENTRY_DSN;

      const { captureException } = require("../src/config/sentry");
      const error = new Error("Test error");

      captureException(error);

      expect(Sentry.captureException).not.toHaveBeenCalled();
    });

    test("should handle captureException without context", () => {
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { captureException } = require("../src/config/sentry");
      const error = new Error("Test error");

      captureException(error);

      expect(Sentry.captureException).toHaveBeenCalledWith(error, {
        contexts: { custom: {} },
      });
    });
  });

  describe("captureMessage", () => {
    test("should capture message when DSN configured", () => {
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { captureMessage } = require("../src/config/sentry");
      const message = "Test message";
      const level = "warning";

      captureMessage(message, level);

      expect(Sentry.captureMessage).toHaveBeenCalledWith(message, level);
    });

    test("should not capture message without DSN", () => {
      delete process.env.SENTRY_DSN;

      const { captureMessage } = require("../src/config/sentry");
      const message = "Test message";

      captureMessage(message);

      expect(Sentry.captureMessage).not.toHaveBeenCalled();
    });

    test("should default to info level", () => {
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      const { captureMessage } = require("../src/config/sentry");
      const message = "Test message";

      captureMessage(message);

      expect(Sentry.captureMessage).toHaveBeenCalledWith(message, "info");
    });
  });

  describe("Profiling integration", () => {
    test("should handle missing profiling integration gracefully", () => {
      // Mock profiling integration as unavailable
      jest.resetModules();
      jest.doMock("@sentry/profiling-node", () => {
        throw new Error("Module not found");
      });

      process.env.NODE_ENV = "production";
      process.env.SENTRY_DSN = "https://test@sentry.io/123";

      // This should not throw
      expect(() => {
        delete require.cache[require.resolve("../src/config/sentry")];
        const { initSentry } = require("../src/config/sentry");
        const app = express();
        initSentry(app);
      }).not.toThrow();
    });
  });
});
