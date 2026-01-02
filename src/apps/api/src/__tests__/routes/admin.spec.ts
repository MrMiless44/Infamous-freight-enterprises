import request from "supertest";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { adminRouter } from "../../routes/admin";
import { authenticate, requireScope } from "../../middleware/security";

// Mock Prisma
jest.mock("@prisma/client", () => {
  const mockPrisma = {
    user: {
      findUnique: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
      create: jest.fn(),
      delete: jest.fn(),
    },
    shipment: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      count: jest.fn(),
    },
    driver: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      count: jest.fn(),
    },
    auditLog: {
      create: jest.fn(),
      findMany: jest.fn(),
    },
    $disconnect: jest.fn(),
  };
  return { PrismaClient: jest.fn(() => mockPrisma) };
});

// Mock middleware
jest.mock("../../middleware/security", () => ({
  authenticate: jest.fn((req, res, next) => {
    req.user = { sub: "test-user-123", role: "ADMIN", email: "admin@test.com" };
    next();
  }),
  requireScope: jest.fn(() => (req, res, next) => next()),
}));

describe("Admin Routes", () => {
  let app: express.Application;
  const prisma = new PrismaClient();

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/admin", adminRouter as any);
    jest.clearAllMocks();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  describe("GET /admin/users", () => {
    it("should return all users", async () => {
      const mockUsers = [
        { id: "1", email: "user1@test.com", role: "USER" },
        { id: "2", email: "user2@test.com", role: "ADMIN" },
      ];
      (prisma.user.findMany as jest.Mock).mockResolvedValue(mockUsers);

      const response = await request(app).get("/admin/users");

      expect(response.status).toBe(200);
      expect(response.body.data).toEqual(mockUsers);
    });

    it("should handle errors when fetching users", async () => {
      (prisma.user.findMany as jest.Mock).mockRejectedValue(
        new Error("Database error"),
      );

      const response = await request(app).get("/admin/users");

      expect(response.status).toBe(500);
    });
  });

  describe("POST /admin/users/:id/role", () => {
    it("should update user role", async () => {
      const userId = "test-user-123";
      const updatedUser = { id: userId, role: "ADMIN" };
      (prisma.user.update as jest.Mock).mockResolvedValue(updatedUser);

      const response = await request(app)
        .post(`/admin/users/${userId}/role`)
        .send({ role: "ADMIN" });

      expect(response.status).toBe(200);
      expect(prisma.user.update).toHaveBeenCalled();
    });

    it("should validate role input", async () => {
      const response = await request(app)
        .post("/admin/users/test-id/role")
        .send({ role: "INVALID_ROLE" });

      expect(response.status).toBe(400);
    });
  });

  describe("GET /admin/dashboard", () => {
    it("should return dashboard metrics", async () => {
      (prisma.shipment.count as jest.Mock).mockResolvedValue(150);
      (prisma.driver.count as jest.Mock).mockResolvedValue(50);
      (prisma.user.count as jest.Mock).mockResolvedValue(200);

      const response = await request(app).get("/admin/dashboard");

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveProperty("shipments");
      expect(response.body.data).toHaveProperty("drivers");
      expect(response.body.data).toHaveProperty("users");
    });
  });

  describe("GET /admin/audit-logs", () => {
    it("should return audit logs", async () => {
      const mockLogs = [
        {
          id: "1",
          action: "USER_CREATED",
          userId: "admin-123",
          timestamp: new Date(),
        },
      ];
      (prisma.auditLog.findMany as jest.Mock).mockResolvedValue(mockLogs);

      const response = await request(app).get("/admin/audit-logs");

      expect(response.status).toBe(200);
      expect(response.body.data).toEqual(mockLogs);
    });

    it("should support pagination", async () => {
      (prisma.auditLog.findMany as jest.Mock).mockResolvedValue([]);

      const response = await request(app)
        .get("/admin/audit-logs")
        .query({ skip: 10, take: 20 });

      expect(prisma.auditLog.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 10,
          take: 20,
        }),
      );
    });
  });

  describe("DELETE /admin/users/:id", () => {
    it("should delete a user", async () => {
      const userId = "test-user-123";
      (prisma.user.delete as jest.Mock).mockResolvedValue({ id: userId });

      const response = await request(app).delete(`/admin/users/${userId}`);

      expect(response.status).toBe(200);
      expect(prisma.user.delete).toHaveBeenCalledWith({
        where: { id: userId },
      });
    });

    it("should handle user not found", async () => {
      (prisma.user.delete as jest.Mock).mockRejectedValue(
        new Error("User not found"),
      );

      const response = await request(app).delete("/admin/users/nonexistent");

      expect(response.status).toBe(404);
    });
  });
});
