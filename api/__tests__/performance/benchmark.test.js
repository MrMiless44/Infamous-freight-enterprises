/**
 * Performance benchmark tests
 */
const request = require("supertest");
const { makeToken, authHeader } = require("../helpers/auth");
const { createShipments } = require("../helpers/fixtures");

// Skip supertest tests on Node 22+ (target is Node 20.18.1, CI will run these)
const skipOnNode22 = global.skipSupertestOnNode22 ? describe.skip : describe;

// Mock dependencies
const mockPrisma = {
  user: {
    findUnique: jest.fn(),
  },
  shipment: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    count: jest.fn(),
  },
};

jest.mock("../../src/db/prisma", () => mockPrisma);
jest.mock("../../src/config/sentry", () => ({
  initSentry: jest.fn(),
  attachErrorHandler: jest.fn(),
}));

skipOnNode22("Performance Benchmarks", () => {
  let app;
  let token;

  beforeAll(() => {
    process.env.NODE_ENV = "test";
    process.env.JWT_SECRET = "test-secret";
    process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/test";

    jest.resetModules();
    app = require("../../src/server");
    token = makeToken(["shipments:read", "shipments:write"]);
  });

  beforeEach(() => {
    jest.clearAllMocks();

    mockPrisma.user.findUnique.mockResolvedValue({
      id: "user-1",
      email: "test@example.com",
    });
  });

  describe("Response Time Benchmarks", () => {
    test("GET /api/shipments should respond within 200ms", async () => {
      const shipments = createShipments(10);
      mockPrisma.shipment.findMany.mockResolvedValue(shipments);
      mockPrisma.shipment.count.mockResolvedValue(10);

      const start = Date.now();
      const res = await request(app)
        .get("/api/shipments")
        .set(authHeader(token));
      const duration = Date.now() - start;

      expect(res.status).toBe(200);
      expect(duration).toBeLessThan(200);
    });

    test("GET /api/shipments/:id should respond within 100ms", async () => {
      mockPrisma.shipment.findUnique.mockResolvedValue(createShipments(1)[0]);

      const start = Date.now();
      const res = await request(app)
        .get("/api/shipments/shipment-1")
        .set(authHeader(token));
      const duration = Date.now() - start;

      expect(res.status).toBe(200);
      expect(duration).toBeLessThan(100);
    });

    test("POST /api/shipments should respond within 300ms", async () => {
      mockPrisma.shipment.create.mockResolvedValue(createShipments(1)[0]);

      const start = Date.now();
      const res = await request(app)
        .post("/api/shipments")
        .set(authHeader(token))
        .send({
          origin: "New York, NY",
          destination: "Los Angeles, CA",
          weight: 25.5,
        });
      const duration = Date.now() - start;

      expect(res.status).toBe(201);
      expect(duration).toBeLessThan(300);
    });

    test("PATCH /api/shipments/:id should respond within 150ms", async () => {
      const shipment = createShipments(1)[0];
      mockPrisma.shipment.findUnique.mockResolvedValue(shipment);
      mockPrisma.shipment.update.mockResolvedValue({
        ...shipment,
        status: "IN_TRANSIT",
      });

      const start = Date.now();
      const res = await request(app)
        .patch(`/api/shipments/${shipment.id}`)
        .set(authHeader(token))
        .send({ status: "IN_TRANSIT" });
      const duration = Date.now() - start;

      expect(res.status).toBe(200);
      expect(duration).toBeLessThan(150);
    });
  });

  describe("Pagination Performance", () => {
    test("should handle large result sets efficiently", async () => {
      const largeDataset = createShipments(1000);
      mockPrisma.shipment.findMany.mockResolvedValue(largeDataset.slice(0, 50));
      mockPrisma.shipment.count.mockResolvedValue(1000);

      const start = Date.now();
      const res = await request(app)
        .get("/api/shipments?page=1&limit=50")
        .set(authHeader(token));
      const duration = Date.now() - start;

      expect(res.status).toBe(200);
      expect(duration).toBeLessThan(250);
    });

    test("should maintain performance with deep pagination", async () => {
      const dataset = createShipments(50);
      mockPrisma.shipment.findMany.mockResolvedValue(dataset);
      mockPrisma.shipment.count.mockResolvedValue(10000);

      const start = Date.now();
      const res = await request(app)
        .get("/api/shipments?page=100&limit=50")
        .set(authHeader(token));
      const duration = Date.now() - start;

      expect(res.status).toBe(200);
      expect(duration).toBeLessThan(300);
    });
  });

  describe("Concurrent Request Handling", () => {
    test("should handle 10 concurrent requests", async () => {
      mockPrisma.shipment.findMany.mockResolvedValue(createShipments(10));
      mockPrisma.shipment.count.mockResolvedValue(10);

      const start = Date.now();
      const requests = Array.from({ length: 10 }, () =>
        request(app).get("/api/shipments").set(authHeader(token)),
      );

      const results = await Promise.all(requests);
      const duration = Date.now() - start;

      expect(results.every((r) => r.status === 200)).toBe(true);
      expect(duration).toBeLessThan(1000); // All 10 requests under 1s
    });

    test("should handle 50 concurrent requests", async () => {
      mockPrisma.shipment.findMany.mockResolvedValue(createShipments(10));
      mockPrisma.shipment.count.mockResolvedValue(10);

      const start = Date.now();
      const requests = Array.from({ length: 50 }, () =>
        request(app).get("/api/shipments").set(authHeader(token)),
      );

      const results = await Promise.all(requests);
      const duration = Date.now() - start;

      expect(results.every((r) => r.status === 200)).toBe(true);
      expect(duration).toBeLessThan(2500); // All 50 requests under 2.5s
    });
  });

  describe("Memory Usage Benchmarks", () => {
    test("should not leak memory on repeated requests", async () => {
      mockPrisma.shipment.findMany.mockResolvedValue(createShipments(100));
      mockPrisma.shipment.count.mockResolvedValue(100);

      const initialMemory = process.memoryUsage().heapUsed;

      // Make 100 requests
      for (let i = 0; i < 100; i++) {
        await request(app).get("/api/shipments").set(authHeader(token));
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 50MB for 100 requests)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });
  });

  describe("Database Query Performance", () => {
    test("should optimize queries with filtering", async () => {
      mockPrisma.shipment.findMany.mockResolvedValue(createShipments(5));
      mockPrisma.shipment.count.mockResolvedValue(5);

      const start = Date.now();
      const res = await request(app)
        .get("/api/shipments?status=PENDING")
        .set(authHeader(token));
      const duration = Date.now() - start;

      expect(res.status).toBe(200);
      expect(duration).toBeLessThan(200);

      // Verify filtering was applied
      expect(mockPrisma.shipment.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.any(Object),
        }),
      );
    });

    test("should optimize queries with sorting", async () => {
      mockPrisma.shipment.findMany.mockResolvedValue(createShipments(10));
      mockPrisma.shipment.count.mockResolvedValue(10);

      const start = Date.now();
      const res = await request(app)
        .get("/api/shipments?sortBy=createdAt&order=desc")
        .set(authHeader(token));
      const duration = Date.now() - start;

      expect(res.status).toBe(200);
      expect(duration).toBeLessThan(200);
    });
  });

  describe("Rate Limiting Performance", () => {
    test("should enforce rate limits without degrading performance", async () => {
      mockPrisma.shipment.findMany.mockResolvedValue(createShipments(5));
      mockPrisma.shipment.count.mockResolvedValue(5);

      const start = Date.now();

      // Make requests up to rate limit
      for (let i = 0; i < 10; i++) {
        await request(app).get("/api/shipments").set(authHeader(token));
      }

      const duration = Date.now() - start;

      // Should complete quickly
      expect(duration).toBeLessThan(1000);
    });
  });
});
