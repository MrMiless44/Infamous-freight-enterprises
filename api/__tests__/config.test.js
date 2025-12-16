/**
 * Tests for configuration module
 */

describe("Config", () => {
  let originalEnv;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Clear all environment variables
    Object.keys(process.env).forEach((key) => {
      if (key.startsWith("API_") || 
          key.startsWith("DATABASE_") ||
          key.startsWith("CORS_") ||
          key.startsWith("OPENAI_") ||
          key.startsWith("ANTHROPIC_") ||
          key.startsWith("STRIPE_") ||
          key.startsWith("PAYPAL_") ||
          key.startsWith("AI_") ||
          key.startsWith("JWT_") ||
          key.startsWith("LOG_") ||
          key === "NODE_ENV") {
        delete process.env[key];
      }
    });

    // Delete cached config module
    delete require.cache[require.resolve("../src/config")];
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
    delete require.cache[require.resolve("../src/config")];
  });

  describe("Constructor and environment detection", () => {
    test("should default to development environment", () => {
      delete process.env.NODE_ENV;
      delete require.cache[require.resolve("../src/config")];
      const config = require("../src/config");
      expect(config.nodeEnv).toBe("development");
      expect(config.isDevelopment).toBe(true);
      expect(config.isProduction).toBe(false);
    });

    test("should detect production environment", () => {
      delete process.env.NODE_ENV;
      process.env.NODE_ENV = "production";
      Object.keys(require.cache).forEach(key => {
        if (key.includes("config.js")) {
          delete require.cache[key];
        }
      });
      const config = require("../src/config");
      expect(config.nodeEnv).toBe("production");
      expect(config.isProduction).toBe(true);
      expect(config.isDevelopment).toBe(false);
    });
  });

  describe("getApiConfig", () => {
    test("should return API configuration with defaults", () => {
      process.env.API_PORT = "4000";
      const config = require("../src/config");
      const apiConfig = config.getApiConfig();
      
      expect(apiConfig.port).toBe("4000");
      expect(apiConfig.host).toBe("0.0.0.0");
      expect(apiConfig.basePath).toBe("/api");
    });

    test("should use custom API configuration", () => {
      process.env.API_PORT = "5000";
      process.env.API_HOST = "localhost";
      process.env.API_BASE_PATH = "/v1";
      const config = require("../src/config");
      const apiConfig = config.getApiConfig();
      
      expect(apiConfig.port).toBe("5000");
      expect(apiConfig.host).toBe("localhost");
      expect(apiConfig.basePath).toBe("/v1");
    });
  });

  describe("getDatabaseUrl", () => {
    test("should return database URL", () => {
      process.env.DATABASE_URL = "postgresql://localhost/test";
      const config = require("../src/config");
      expect(config.getDatabaseUrl()).toBe("postgresql://localhost/test");
    });

    test("should throw error when DATABASE_URL is missing", () => {
      const config = require("../src/config");
      expect(() => config.getDatabaseUrl()).toThrow(
        "Missing required environment variable: DATABASE_URL"
      );
    });
  });

  describe("getCorsOrigins", () => {
    test("should return default CORS origins", () => {
      const config = require("../src/config");
      const origins = config.getCorsOrigins();
      expect(origins).toEqual(["http://localhost:3000"]);
    });

    test("should parse multiple CORS origins", () => {
      process.env.CORS_ORIGINS = "http://localhost:3000, http://localhost:4000, https://example.com";
      const config = require("../src/config");
      const origins = config.getCorsOrigins();
      expect(origins).toEqual([
        "http://localhost:3000",
        "http://localhost:4000",
        "https://example.com",
      ]);
    });
  });

  describe("getApiKeys", () => {
    test("should throw errors when required API keys are missing", () => {
      const config = require("../src/config");
      expect(() => config.getApiKeys()).toThrow(/Missing required environment variable/);
    });

    test("should return all API keys when present", () => {
      process.env.OPENAI_API_KEY = "openai-key";
      process.env.ANTHROPIC_API_KEY = "anthropic-key";
      process.env.STRIPE_API_KEY = "stripe-key";
      process.env.STRIPE_WEBHOOK_SECRET = "stripe-webhook";
      process.env.PAYPAL_CLIENT_ID = "paypal-id";
      process.env.PAYPAL_CLIENT_SECRET = "paypal-secret";
      process.env.PAYPAL_SECRET = "paypal-secret-2";
      process.env.AI_SYNTHETIC_ENGINE_URL = "http://localhost:8000";
      process.env.AI_SYNTHETIC_API_KEY = "ai-key";
      
      const config = require("../src/config");
      const keys = config.getApiKeys();
      
      expect(keys.openai).toBe("openai-key");
      expect(keys.anthropic).toBe("anthropic-key");
      expect(keys.stripe).toBe("stripe-key");
      expect(keys.stripeWebhookSecret).toBe("stripe-webhook");
      expect(keys.paypalClientId).toBe("paypal-id");
      expect(keys.paypalClientSecret).toBe("paypal-secret");
      expect(keys.paypalSecret).toBe("paypal-secret-2");
      expect(keys.aiSyntheticUrl).toBe("http://localhost:8000");
      expect(keys.aiSyntheticKey).toBe("ai-key");
    });
  });

  describe("getJwtSecret", () => {
    test("should return JWT secret", () => {
      process.env.JWT_SECRET = "my-secret-key";
      const config = require("../src/config");
      expect(config.getJwtSecret()).toBe("my-secret-key");
    });

    test("should throw error when JWT_SECRET is missing", () => {
      const config = require("../src/config");
      expect(() => config.getJwtSecret()).toThrow(
        "Missing required environment variable: JWT_SECRET"
      );
    });
  });

  describe("getLogLevel", () => {
    test("should return debug log level in development", () => {
      process.env.NODE_ENV = "development";
      delete require.cache[require.resolve("../src/config")];
      const config = require("../src/config");
      expect(config.getLogLevel()).toBe("debug");
    });

    test("should return error log level in production", () => {
      process.env.NODE_ENV = "production";
      delete require.cache[require.resolve("../src/config")];
      const config = require("../src/config");
      expect(config.getLogLevel()).toBe("error");
    });

    test("should use custom log level", () => {
      process.env.LOG_LEVEL = "warn";
      const config = require("../src/config");
      expect(config.getLogLevel()).toBe("warn");
    });
  });

  describe("Helper methods", () => {
    describe("requireEnv", () => {
      test("should return environment variable value", () => {
        process.env.TEST_VAR = "test-value";
        const config = require("../src/config");
        expect(config.requireEnv("TEST_VAR")).toBe("test-value");
      });

      test("should return default value when variable is missing", () => {
        const config = require("../src/config");
        expect(config.requireEnv("MISSING_VAR", "default")).toBe("default");
      });

      test("should throw error when variable is missing and no default", () => {
        const config = require("../src/config");
        expect(() => config.requireEnv("MISSING_VAR")).toThrow(
          "Missing required environment variable: MISSING_VAR"
        );
      });
    });

    describe("getEnv", () => {
      test("should return environment variable value", () => {
        process.env.TEST_VAR = "test-value";
        const config = require("../src/config");
        expect(config.getEnv("TEST_VAR")).toBe("test-value");
      });

      test("should return default value when variable is missing", () => {
        const config = require("../src/config");
        expect(config.getEnv("MISSING_VAR", "default")).toBe("default");
      });

      test("should return empty string when no default provided", () => {
        const config = require("../src/config");
        expect(config.getEnv("MISSING_VAR")).toBe("");
      });
    });

    describe("getBoolean", () => {
      test("should return true for 'true' value", () => {
        process.env.BOOL_VAR = "true";
        const config = require("../src/config");
        expect(config.getBoolean("BOOL_VAR")).toBe(true);
      });

      test("should return true for 'TRUE' value", () => {
        process.env.BOOL_VAR = "TRUE";
        const config = require("../src/config");
        expect(config.getBoolean("BOOL_VAR")).toBe(true);
      });

      test("should return false for 'false' value", () => {
        process.env.BOOL_VAR = "false";
        const config = require("../src/config");
        expect(config.getBoolean("BOOL_VAR")).toBe(false);
      });

      test("should return default value when variable is missing", () => {
        const config = require("../src/config");
        expect(config.getBoolean("MISSING_VAR", true)).toBe(true);
      });

      test("should return false when variable is missing and no default", () => {
        const config = require("../src/config");
        expect(config.getBoolean("MISSING_VAR")).toBe(false);
      });
    });

    describe("getNumber", () => {
      test("should parse number from string", () => {
        process.env.NUM_VAR = "42";
        const config = require("../src/config");
        expect(config.getNumber("NUM_VAR")).toBe(42);
      });

      test("should return default value when variable is missing", () => {
        const config = require("../src/config");
        expect(config.getNumber("MISSING_VAR", 100)).toBe(100);
      });

      test("should return 0 when variable is missing and no default", () => {
        const config = require("../src/config");
        expect(config.getNumber("MISSING_VAR")).toBe(0);
      });

      test("should return default value for invalid number", () => {
        process.env.NUM_VAR = "not-a-number";
        const config = require("../src/config");
        expect(config.getNumber("NUM_VAR", 50)).toBe(50);
      });
    });
  });
});
