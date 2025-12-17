/**
 * Jest setup file
 * Runs before all tests to configure the test environment
 */

// Mock @prisma/client to prevent OpenSSL engine loading errors
jest.mock("@prisma/client", () => {
  const mockPrismaClient = jest.fn();
  mockPrismaClient.prototype.$disconnect = jest.fn();

  return {
    PrismaClient: mockPrismaClient,
    Prisma: {
      PrismaClientValidationError: Error,
      PrismaClientRustPanicError: Error,
      PrismaClientInitializationError: Error,
      PrismaClientKnownRequestError: Error,
      PrismaClientUnknownRequestError: Error,
    },
  };
});

// Mock rate-limiter-flexible before it's loaded by security middleware
jest.mock("rate-limiter-flexible", () => ({
  RateLimiterMemory: jest.fn(() => ({
    consume: jest.fn().mockResolvedValue(true),
  })),
}));

// Set test environment variables
process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "test-secret";
process.env.CORS_ORIGINS = "http://localhost:3000";
process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/test";
process.env.AI_PROVIDER = "synthetic";

// Force listeners to bind to localhost in test runs (0.0.0.0 is blocked)
const net = require("net");
const originalListen = net.Server.prototype.listen;
net.Server.prototype.listen = function patchedListen(...args) {
  if (args[0] && typeof args[0] === "object") {
    const opts = { ...args[0] };
    if (!opts.host || opts.host === "0.0.0.0") {
      opts.host = "127.0.0.1";
    }
    args[0] = opts;
  } else {
    const hostIndex = typeof args[1] === "string" ? 1 : typeof args[2] === "string" ? 2 : -1;
    if (hostIndex === -1) {
      args.splice(1, 0, "127.0.0.1");
    } else if (!args[hostIndex] || args[hostIndex] === "0.0.0.0") {
      args[hostIndex] = "127.0.0.1";
    }
  }

  return originalListen.apply(this, args);
};

// Suppress console output during tests (optional)
global.console = {
  ...console,
  // Uncomment to suppress logs during tests:
  // log: jest.fn(),
  // debug: jest.fn(),
};
