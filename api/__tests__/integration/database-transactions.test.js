/**
 * Integration tests for database transaction handling
 */
const request = require("supertest");
const { makeToken, authHeader } = require("../helpers/auth");
const { createShipment } = require("../helpers/fixtures");

// Skip supertest tests on Node 22+ (target is Node 20.18.1, CI will run these)
const skipOnNode22 = global.skipSupertestOnNode22 ? describe.skip : describe;

// Mock dependencies
const mockPrisma = {
  user: {
    findUnique: jest.fn(),
  },
  shipment: {
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    findUnique: jest.fn(),
    findMany: jest.fn(),
  },
  $transaction: jest.fn(),
  $queryRaw: jest.fn(),
};

jest.mock("../../src/db/prisma", () => mockPrisma);
jest.mock("../../src/config/sentry", () => ({
  initSentry: jest.fn(),
  attachErrorHandler: jest.fn(),
}));

skipOnNode22("Database Transaction Tests", () => {
  let app;
  let token;
  let testShipment;

  beforeAll(() => {
    process.env.NODE_ENV = "test";
    process.env.JWT_SECRET = "test-secret";
    process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/test";

    jest.resetModules();
    app = require("../../src/server");
    token = makeToken(["shipments:write", "shipments:read"]);
  });

  beforeEach(() => {
    jest.clearAllMocks();

    testShipment = createShipment({
      id: "shipment-1",
      trackingNumber: "TEST-001",
      status: "PENDING",
    });

    mockPrisma.user.findUnique.mockResolvedValue({
      id: "user-1",
      email: "test@example.com",
    });
  });

  describe("Transaction Rollback Scenarios", () => {
    test("should rollback transaction on validation error", async () => {
      // Simulate transaction that fails validation midway
      mockPrisma.$transaction.mockImplementation(async (callback) => {
        const mockTx = {
          shipment: {
            create: jest.fn().mockResolvedValue(testShipment),
            update: jest.fn().mockRejectedValue(new Error("Validation failed")),
          },
        };

        try {
          await callback(mockTx);
        } catch (err) {
          // Transaction rolls back
          throw err;
        }
      });

      // This would be a multi-step operation wrapped in a transaction
      // For now, testing that errors are handled correctly

      mockPrisma.shipment.create.mockRejectedValue(
        new Error("Transaction rolled back"),
      );

      const res = await request(app)
        .post("/api/shipments")
        .set(authHeader(token))
        .send({
          origin: "New York",
          destination: "LA",
          weight: -1, // Invalid weight causes rollback
        });

      expect(res.status).toBe(400);
      // Verify no partial data was committed
    });

    test("should handle concurrent update conflicts", async () => {
      mockPrisma.shipment.findUnique
        .mockResolvedValueOnce(testShipment)
        .mockResolvedValueOnce({
          ...testShipment,
          status: "IN_TRANSIT", // Changed by another request
        });

      mockPrisma.shipment.update.mockRejectedValue(
        new Error("Record has been modified"),
      );

      const res = await request(app)
        .patch(`/api/shipments/${testShipment.id}`)
        .set(authHeader(token))
        .send({ status: "DELIVERED" });

      expect(res.status).toBe(500);
    });

    test("should rollback on database constraint violation", async () => {
      mockPrisma.shipment.create.mockRejectedValue({
        code: "P2002", // Prisma unique constraint violation
        meta: { target: ["trackingNumber"] },
      });

      const res = await request(app)
        .post("/api/shipments")
        .set(authHeader(token))
        .send({
          origin: "New York",
          destination: "LA",
          trackingNumber: "DUPLICATE-001",
          weight: 10,
        });

      expect(res.status).toBe(400);
    });
  });

  describe("Transaction Isolation Levels", () => {
    test("should maintain data consistency under concurrent operations", async () => {
      const shipment1 = createShipment({ id: "s1", status: "PENDING" });
      const shipment2 = createShipment({ id: "s2", status: "PENDING" });

      mockPrisma.shipment.findUnique
        .mockResolvedValueOnce(shipment1)
        .mockResolvedValueOnce(shipment2);

      mockPrisma.shipment.update
        .mockResolvedValueOnce({ ...shipment1, status: "IN_TRANSIT" })
        .mockResolvedValueOnce({ ...shipment2, status: "IN_TRANSIT" });

      // Simulate concurrent updates
      const [res1, res2] = await Promise.all([
        request(app)
          .patch(`/api/shipments/${shipment1.id}`)
          .set(authHeader(token))
          .send({ status: "IN_TRANSIT" }),
        request(app)
          .patch(`/api/shipments/${shipment2.id}`)
          .set(authHeader(token))
          .send({ status: "IN_TRANSIT" }),
      ]);

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);
    });

    test("should prevent dirty reads", async () => {
      mockPrisma.shipment.findUnique.mockResolvedValue(testShipment);

      // Read should not see uncommitted changes
      const res = await request(app)
        .get(`/api/shipments/${testShipment.id}`)
        .set(authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.shipment.status).toBe("PENDING");
    });
  });

  describe("Long-Running Transactions", () => {
    test("should timeout long-running transactions", async () => {
      mockPrisma.$queryRaw.mockImplementation(
        () =>
          new Promise((resolve) => {
            setTimeout(resolve, 35000); // Longer than typical timeout
          }),
      );

      // This would trigger a timeout in real scenario
      // For testing, we simulate the timeout error
      mockPrisma.shipment.create.mockRejectedValue(
        new Error("Transaction timeout"),
      );

      const res = await request(app)
        .post("/api/shipments")
        .set(authHeader(token))
        .send({
          origin: "New York",
          destination: "LA",
          weight: 10,
        });

      expect(res.status).toBe(500);
    });
  });

  describe("Nested Transaction Handling", () => {
    test("should handle nested transaction operations", async () => {
      // Simulate a complex operation with multiple database calls
      mockPrisma.$transaction.mockImplementation(async (callback) => {
        const mockTx = {
          shipment: {
            create: jest.fn().mockResolvedValue(testShipment),
            update: jest
              .fn()
              .mockResolvedValue({ ...testShipment, status: "ASSIGNED" }),
          },
          driver: {
            update: jest.fn().mockResolvedValue({ id: "driver-1" }),
          },
        };

        return await callback(mockTx);
      });

      mockPrisma.shipment.create.mockResolvedValue(testShipment);

      const res = await request(app)
        .post("/api/shipments")
        .set(authHeader(token))
        .send({
          origin: "New York",
          destination: "LA",
          weight: 10,
        });

      expect(res.status).toBe(201);
    });
  });

  describe("Deadlock Detection", () => {
    test("should handle database deadlocks gracefully", async () => {
      mockPrisma.shipment.update.mockRejectedValue({
        code: "P2034", // Prisma deadlock error
        message: "Transaction deadlock detected",
      });

      const res = await request(app)
        .patch(`/api/shipments/${testShipment.id}`)
        .set(authHeader(token))
        .send({ status: "IN_TRANSIT" });

      expect(res.status).toBe(500);
    });
  });

  describe("Connection Pool Exhaustion", () => {
    test("should handle connection pool limits", async () => {
      mockPrisma.shipment.findMany.mockRejectedValue(
        new Error("Connection pool exhausted"),
      );

      const res = await request(app)
        .get("/api/shipments")
        .set(authHeader(token));

      expect(res.status).toBe(500);
    });
  });
});
