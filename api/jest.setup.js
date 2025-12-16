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

// Suppress console output during tests (optional)
global.console = {
  ...console,
  // Uncomment to suppress logs during tests:
  // log: jest.fn(),
  // debug: jest.fn(),
};
