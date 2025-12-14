const request = require("supertest");
const jwt = require("jsonwebtoken");

// Setup test environment
process.env.JWT_SECRET = "test-secret";
process.env.NODE_ENV = "test";

// Mock Prisma with transaction support
jest.mock("../src/db/prisma", () => ({
  prisma: {
    shipment: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    },
    aiEvent: {
      create: jest.fn(),
    },
    $transaction: jest.fn((callback) =>
      callback({
        shipment: {
          create: jest.fn(),
          update: jest.fn(),
        },
        aiEvent: {
          create: jest.fn(),
        },
      }),
    ),
  },
}));

const app = require("../src/server");
const { prisma } = require("../src/db/prisma");

// Helper to generate JWT tokens
const makeToken = (scopes) =>
  jwt.sign(
    {
      sub: "test-user-123",
      scopes,
    },
    process.env.JWT_SECRET,
  );

const authHeader = (token) => `Bearer ${token}`;

// Mock shipment data
const mockDriver = {
  id: "driver-123",
  name: "John Driver",
  phone: "+1234567890",
  status: "active",
};

const mockShipment = {
  id: "shipment-123",
  reference: "SHP-001",
  origin: "New York, NY",
  destination: "Los Angeles, CA",
  status: "pending",
  driverId: "driver-123",
  driver: mockDriver,
  createdAt: "2024-01-01T00:00:00.000Z",
  updatedAt: "2024-01-01T00:00:00.000Z",
};

const mockShipments = [
  mockShipment,
  {
    id: "shipment-456",
    reference: "SHP-002",
    origin: "Chicago, IL",
    destination: "Miami, FL",
    status: "in_transit",
    driverId: "driver-123",
    driver: mockDriver,
    createdAt: "2024-01-02T00:00:00.000Z",
    updatedAt: "2024-01-02T00:00:00.000Z",
  },
];

describe("Shipments API Routes", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("GET /api/shipments", () => {
    test("returns all shipments when authenticated", async () => {
      prisma.shipment.findMany.mockResolvedValue(mockShipments);
      const token = makeToken(["shipments:read"]);

      const res = await request(app)
        .get("/api/shipments")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.shipments).toEqual(mockShipments);
      expect(prisma.shipment.findMany).toHaveBeenCalledWith({
        where: {},
        include: {
          driver: {
            select: {
              id: true,
              name: true,
              phone: true,
              status: true,
            },
          },
        },
        orderBy: {
          createdAt: "desc",
        },
      });
    });

    test("filters shipments by status", async () => {
      const filteredShipments = [mockShipments[1]];
      prisma.shipment.findMany.mockResolvedValue(filteredShipments);
      const token = makeToken(["shipments:read"]);

      const res = await request(app)
        .get("/api/shipments?status=in_transit")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.shipments).toEqual(filteredShipments);
      expect(prisma.shipment.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { status: "in_transit" },
        }),
      );
    });

    test("filters shipments by driverId", async () => {
      prisma.shipment.findMany.mockResolvedValue(mockShipments);
      const token = makeToken(["shipments:read"]);

      const res = await request(app)
        .get("/api/shipments?driverId=driver-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(prisma.shipment.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { driverId: "driver-123" },
        }),
      );
    });

    test("returns 401 when not authenticated", async () => {
      const res = await request(app).get("/api/shipments");

      expect(res.status).toBe(401);
      expect(prisma.shipment.findMany).not.toHaveBeenCalled();
    });

    test("returns 403 when missing required scope", async () => {
      const token = makeToken(["other:scope"]);

      const res = await request(app)
        .get("/api/shipments")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(403);
      expect(prisma.shipment.findMany).not.toHaveBeenCalled();
    });
  });

  describe("GET /api/shipments/:id", () => {
    test("returns shipment by ID with driver details", async () => {
      prisma.shipment.findUnique.mockResolvedValue(mockShipment);
      const token = makeToken(["shipments:read"]);

      const res = await request(app)
        .get("/api/shipments/shipment-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.shipment).toEqual(mockShipment);
      expect(res.body.shipment.driver).toEqual(mockDriver);
      expect(prisma.shipment.findUnique).toHaveBeenCalledWith({
        where: { id: "shipment-123" },
        include: {
          driver: {
            select: {
              id: true,
              name: true,
              phone: true,
              status: true,
            },
          },
        },
      });
    });

    test("returns 404 when shipment not found", async () => {
      prisma.shipment.findUnique.mockResolvedValue(null);
      const token = makeToken(["shipments:read"]);

      const res = await request(app)
        .get("/api/shipments/nonexistent")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(404);
      expect(res.body.ok).toBe(false);
      expect(res.body.error).toBe("Shipment not found");
    });
  });

  describe("POST /api/shipments", () => {
    test("creates shipment with transaction and event logging", async () => {
      const newShipmentData = {
        reference: "SHP-003",
        origin: "Seattle, WA",
        destination: "Portland, OR",
        status: "pending",
        driverId: "driver-123",
      };
      const createdShipment = { id: "shipment-789", ...newShipmentData };

      prisma.$transaction.mockImplementation(async (callback) => {
        const mockTx = {
          shipment: {
            create: jest.fn().mockResolvedValue(createdShipment),
          },
          aiEvent: {
            create: jest.fn().mockResolvedValue({ id: "event-123" }),
          },
        };
        return callback(mockTx);
      });

      const token = makeToken(["shipments:write"]);

      const res = await request(app)
        .post("/api/shipments")
        .set("Authorization", authHeader(token))
        .send(newShipmentData);

      expect(res.status).toBe(201);
      expect(res.body.ok).toBe(true);
      expect(res.body.shipment).toEqual(createdShipment);
      expect(prisma.$transaction).toHaveBeenCalled();
    });

    test("returns 400 when required fields missing", async () => {
      const token = makeToken(["shipments:write"]);

      const res = await request(app)
        .post("/api/shipments")
        .set("Authorization", authHeader(token))
        .send({ reference: "SHP-003" });

      expect(res.status).toBe(400);
      expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    test("returns 403 when missing shipments:write scope", async () => {
      const token = makeToken(["shipments:read"]);

      const res = await request(app)
        .post("/api/shipments")
        .set("Authorization", authHeader(token))
        .send({
          reference: "SHP-003",
          origin: "A",
          destination: "B",
        });

      expect(res.status).toBe(403);
      expect(prisma.$transaction).not.toHaveBeenCalled();
    });
  });

  describe("PATCH /api/shipments/:id", () => {
    test("updates shipment with transaction", async () => {
      const updateData = { status: "delivered" };
      const updatedShipment = { ...mockShipment, ...updateData };

      prisma.$transaction.mockImplementation(async (callback) => {
        const mockTx = {
          shipment: {
            update: jest.fn().mockResolvedValue(updatedShipment),
          },
          aiEvent: {
            create: jest.fn().mockResolvedValue({ id: "event-456" }),
          },
        };
        return callback(mockTx);
      });

      const token = makeToken(["shipments:write"]);

      const res = await request(app)
        .patch("/api/shipments/shipment-123")
        .set("Authorization", authHeader(token))
        .send(updateData);

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.shipment.status).toBe("delivered");
      expect(prisma.$transaction).toHaveBeenCalled();
    });

    test("returns 404 when shipment not found during update", async () => {
      prisma.$transaction.mockImplementation(async (callback) => {
        const mockTx = {
          shipment: {
            update: jest.fn().mockRejectedValue({ code: "P2025" }),
          },
          aiEvent: {
            create: jest.fn(),
          },
        };
        return callback(mockTx);
      });

      const token = makeToken(["shipments:write"]);

      const res = await request(app)
        .patch("/api/shipments/nonexistent")
        .set("Authorization", authHeader(token))
        .send({ status: "delivered" });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("Shipment not found");
    });
  });

  describe("DELETE /api/shipments/:id", () => {
    test("deletes shipment successfully", async () => {
      prisma.shipment.delete.mockResolvedValue(mockShipment);
      const token = makeToken(["shipments:write"]);

      const res = await request(app)
        .delete("/api/shipments/shipment-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.message).toBe("Shipment deleted successfully");
      expect(prisma.shipment.delete).toHaveBeenCalledWith({
        where: { id: "shipment-123" },
      });
    });

    test("returns 404 when shipment not found during delete", async () => {
      prisma.shipment.delete.mockRejectedValue({ code: "P2025" });
      const token = makeToken(["shipments:write"]);

      const res = await request(app)
        .delete("/api/shipments/nonexistent")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("Shipment not found");
    });

    test("returns 403 when missing shipments:write scope", async () => {
      const token = makeToken(["shipments:read"]);

      const res = await request(app)
        .delete("/api/shipments/shipment-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(403);
      expect(prisma.shipment.delete).not.toHaveBeenCalled();
    });
  });
});
