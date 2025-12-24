/**
 * Jest setup file
 * Runs before all tests to configure the test environment
 */

// Mock @prisma/client to prevent OpenSSL engine loading errors
jest.mock("@prisma/client", () => {
  const mockPrismaClient = jest.fn();
  mockPrismaClient.prototype.$disconnect = jest.fn();

  // Create a mock Prisma instance with user operations
  const mockUserCreate = jest.fn((args) => {
    const { data } = args;
    return Promise.resolve({
      id: "test-user-123",
      email: data.email,
      name: data.name || null,
      role: data.role || "user",
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  });

  const mockUserFindUnique = jest.fn(() =>
    Promise.resolve({
      id: "test-user-123",
      email: "test@example.com",
      name: "Test User",
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
    }),
  );

  const mockUserFindMany = jest.fn(() => Promise.resolve([]));

  const mockInvoiceCreate = jest.fn((args) => {
    const { data } = args;
    return Promise.resolve({
      id: "inv-test-123",
      carrier: data.carrier,
      reference: data.reference,
      totalAmount: data.totalAmount,
      currency: data.currency || "USD",
      auditResult: data.auditResult || null,
      savings: data.savings || 0,
      status: data.status || "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  });

  const mockPrismaInstance = {
    user: {
      create: mockUserCreate,
      findUnique: mockUserFindUnique,
      findMany: mockUserFindMany,
      update: jest.fn(() => Promise.resolve({})),
      delete: jest.fn(() => Promise.resolve({})),
    },
    invoice: {
      create: mockInvoiceCreate,
      findMany: jest.fn(() => Promise.resolve([])),
      findUnique: jest.fn(() => Promise.resolve(null)),
      update: jest.fn(() => Promise.resolve({})),
      deleteMany: jest.fn(() => Promise.resolve({})),
    },
    $disconnect: jest.fn(),
  };

  return {
    PrismaClient: jest.fn(() => mockPrismaInstance),
    Prisma: {
      PrismaClientValidationError: Error,
      PrismaClientRustPanicError: Error,
      PrismaClientInitializationError: Error,
      PrismaClientKnownRequestError: Error,
      PrismaClientUnknownRequestError: Error,
    },
  };
});

// Mock the prisma database module
jest.mock("./src/db/prisma.js", () => {
  const mockUserCreate = jest.fn((args) => {
    const { data } = args;
    return Promise.resolve({
      id: "test-user-123",
      email: data.email,
      name: data.name || null,
      role: data.role || "user",
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  });

  const mockShipmentCreate = jest.fn((args) => {
    const { data } = args;
    return Promise.resolve({
      id: "shipment-" + Date.now(),
      reference: data.reference,
      origin: data.origin,
      destination: data.destination,
      driverId: data.driverId || null,
      status: data.status || 'created',
      trackingNumber: 'TRK-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
      createdAt: new Date(),
      updatedAt: new Date(),
      driver: null,
    });
  });

  const mockShipmentFindMany = jest.fn(() =>
    Promise.resolve([
      {
        id: 'shipment-1',
        reference: 'REF-001',
        origin: 'New York, NY',
        destination: 'Los Angeles, CA',
        status: 'created',
        trackingNumber: 'TRK-ABC123',
        createdAt: new Date(),
        updatedAt: new Date(),
        driver: null,
      },
    ]),
  );

  const mockShipmentFindUnique = jest.fn(() =>
    Promise.resolve({
      id: 'shipment-1',
      reference: 'REF-001',
      origin: 'New York, NY',
      destination: 'Los Angeles, CA',
      status: 'created',
      trackingNumber: 'TRK-ABC123',
      createdAt: new Date(),
      updatedAt: new Date(),
      driver: null,
    }),
  );

  const mockInvoiceCreate = jest.fn((args) => {
    const { data } = args;
    return Promise.resolve({
      id: "inv-" + Math.random().toString(16).slice(2, 8),
      carrier: data.carrier,
      reference: data.reference,
      totalAmount: data.totalAmount,
      currency: data.currency || "USD",
      auditResult: data.auditResult || null,
      savings: data.savings || 0,
      status: data.status || "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  });

  const mockInvoiceFindMany = jest.fn(() =>
    Promise.resolve([
      {
        id: "inv-123",
        carrier: "Blue Steel Logistics",
        reference: "INV-1001",
        totalAmount: 1299.5,
        currency: "USD",
        auditResult: null,
        savings: 0,
        status: "pending",
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]),
  );

  const mockInvoiceFindUnique = jest.fn(() =>
    Promise.resolve({
      id: "inv-123",
      carrier: "Blue Steel Logistics",
      reference: "INV-1001",
      totalAmount: 1299.5,
      currency: "USD",
      auditResult: null,
      savings: 0,
      status: "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    }),
  );

  const mockPrismaInstance = {
    user: {
      create: mockUserCreate,
      findUnique: jest.fn(() => Promise.resolve({})),
      findMany: jest.fn(() => Promise.resolve([])),
      update: jest.fn(() => Promise.resolve({})),
      delete: jest.fn(() => Promise.resolve({})),
    },
    shipment: {
      findMany: mockShipmentFindMany,
      findUnique: mockShipmentFindUnique,
      create: mockShipmentCreate,
      update: jest.fn(() => Promise.resolve({})),
      delete: jest.fn(() => Promise.resolve({})),
    },
    invoice: {
      findMany: mockInvoiceFindMany,
      findUnique: mockInvoiceFindUnique,
      create: mockInvoiceCreate,
      update: jest.fn(() => Promise.resolve({})),
      deleteMany: jest.fn(() => Promise.resolve({})),
    },
    aiEvent: {
      create: jest.fn(() => Promise.resolve({})),
    },
    $transaction: jest.fn((cb) => {
      // Mock $transaction to call the callback with a mock tx object
      const mockTx = {
        shipment: {
          create: mockShipmentCreate,
          findUnique: mockShipmentFindUnique,
          findMany: mockShipmentFindMany,
          update: jest.fn(() => Promise.resolve({})),
          delete: jest.fn(() => Promise.resolve({})),
        },
        aiEvent: {
          create: jest.fn(() => Promise.resolve({})),
        },
      };
      return cb(mockTx);
    }),
    $disconnect: jest.fn(),
  };

  return { prisma: mockPrismaInstance };
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
process.env.HOST = "127.0.0.1";
process.env.PORT = "0";

// Skip supertest-based integration tests on Node 22+
// These pass on Node 20.18.1 which is the target version
const nodeVersion = parseInt(process.version.slice(1).split(".")[0], 10);
if (nodeVersion > 20) {
  // Mark problematic test suites to skip on Node 22+ unless explicitly forced
  global.skipSupertestOnNode22 = process.env.FORCE_SUPERTEST === "true"
    ? false
    : true;
}

// Suppress console output during tests (optional)
global.console = {
  ...console,
  // Uncomment to suppress logs during tests:
  // log: jest.fn(),
  // debug: jest.fn(),
};
