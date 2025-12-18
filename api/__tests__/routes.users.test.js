const request = require("supertest");
const jwt = require("jsonwebtoken");

// Setup test environment
process.env.JWT_SECRET = "test-secret";
process.env.NODE_ENV = "test";

// Mock Prisma before requiring the app
jest.mock("../src/db/prisma", () => ({
  prisma: {
    user: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    },
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

// Mock user data
const mockUser = {
  id: "user-123",
  email: "test@example.com",
  name: "Test User",
  role: "user",
  createdAt: "2024-01-01T00:00:00.000Z",
  updatedAt: "2024-01-01T00:00:00.000Z",
};

const mockUsers = [
  mockUser,
  {
    id: "user-456",
    email: "admin@example.com",
    name: "Admin User",
    role: "admin",
    createdAt: "2024-01-02T00:00:00.000Z",
    updatedAt: "2024-01-02T00:00:00.000Z",
  },
];

describe("Users API Routes", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("GET /api/users", () => {
    test("returns all users when authenticated with users:read scope", async () => {
      prisma.user.findMany.mockResolvedValue(mockUsers);
      const token = makeToken(["users:read"]);

      const res = await request(app)
        .get("/api/users")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.users).toEqual(mockUsers);
      expect(prisma.user.findMany).toHaveBeenCalledWith({
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: true,
        },
        orderBy: {
          createdAt: "desc",
        },
      });
    });

    test("returns 401 when not authenticated", async () => {
      const res = await request(app).get("/api/users");

      expect(res.status).toBe(401);
      expect(prisma.user.findMany).not.toHaveBeenCalled();
    });

    test("returns 403 when missing required scope", async () => {
      const token = makeToken(["other:scope"]);

      const res = await request(app)
        .get("/api/users")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(403);
      expect(prisma.user.findMany).not.toHaveBeenCalled();
    });

    test("handles database errors gracefully", async () => {
      prisma.user.findMany.mockRejectedValue(new Error("Database error"));
      const token = makeToken(["users:read"]);

      const res = await request(app)
        .get("/api/users")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(500);
    });
  });

  describe("GET /api/users/:id", () => {
    test("returns user by ID when found", async () => {
      prisma.user.findUnique.mockResolvedValue(mockUser);
      const token = makeToken(["users:read"]);

      const res = await request(app)
        .get("/api/users/user-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.user).toEqual(mockUser);
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: "user-123" },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    });

    test("returns 404 when user not found", async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      const token = makeToken(["users:read"]);

      const res = await request(app)
        .get("/api/users/nonexistent")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(404);
      expect(res.body.ok).toBe(false);
      expect(res.body.error).toBe("User not found");
    });

    test("returns 401 when not authenticated", async () => {
      const res = await request(app).get("/api/users/user-123");

      expect(res.status).toBe(401);
      expect(prisma.user.findUnique).not.toHaveBeenCalled();
    });
  });

  describe("POST /api/users", () => {
    test("creates new user with valid data", async () => {
      const newUserData = {
        email: "new@example.com",
        name: "New User",
        role: "user",
      };
      const createdUser = { id: "user-789", ...newUserData };
      prisma.user.create.mockResolvedValue(createdUser);
      const token = makeToken(["users:write"]);

      const res = await request(app)
        .post("/api/users")
        .set("Authorization", authHeader(token))
        .send(newUserData);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual(createdUser);
      expect(prisma.user.create).toHaveBeenCalled();
    });

    test("defaults role to 'user' when not provided", async () => {
      const newUserData = {
        email: "new@example.com",
        name: "New User",
      };
      const createdUser = { id: "user-789", ...newUserData, role: "user" };
      prisma.user.create.mockResolvedValue(createdUser);
      const token = makeToken(["users:write"]);

      const res = await request(app)
        .post("/api/users")
        .set("Authorization", authHeader(token))
        .send(newUserData);

      expect(res.status).toBe(201);
      expect(res.body.data.role).toBe("user");
    });

    test("returns 400 when email is missing", async () => {
      const token = makeToken(["users:write"]);

      const res = await request(app)
        .post("/api/users")
        .set("Authorization", authHeader(token))
        .send({ name: "No Email" });

      expect(res.status).toBe(400);
      expect(prisma.user.create).not.toHaveBeenCalled();
    });

    test("returns 403 when missing users:write scope", async () => {
      const token = makeToken(["users:read"]);

      const res = await request(app)
        .post("/api/users")
        .set("Authorization", authHeader(token))
        .send({ email: "test@example.com", name: "Test" });

      expect(res.status).toBe(403);
      expect(prisma.user.create).not.toHaveBeenCalled();
    });
  });

  describe("PATCH /api/users/:id", () => {
    test("updates user with valid data", async () => {
      const updateData = { name: "Updated Name", role: "admin" };
      const updatedUser = { ...mockUser, ...updateData };
      prisma.user.update.mockResolvedValue(updatedUser);
      const token = makeToken(["users:write"]);

      const res = await request(app)
        .patch("/api/users/user-123")
        .set("Authorization", authHeader(token))
        .send(updateData);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe("Updated Name");
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: "user-123" },
        data: updateData,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    });

    test("returns 404 when user not found during update", async () => {
      prisma.user.update.mockRejectedValue({ code: "P2025" });
      const token = makeToken(["users:write"]);

      const res = await request(app)
        .patch("/api/users/nonexistent")
        .set("Authorization", authHeader(token))
        .send({ name: "New Name" });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("User not found");
    });

    test("returns 403 when missing users:write scope", async () => {
      const token = makeToken(["users:read"]);

      const res = await request(app)
        .patch("/api/users/user-123")
        .set("Authorization", authHeader(token))
        .send({ name: "New Name" });

      expect(res.status).toBe(403);
      expect(prisma.user.update).not.toHaveBeenCalled();
    });
  });

  describe("DELETE /api/users/:id", () => {
    test("deletes user successfully", async () => {
      prisma.user.delete.mockResolvedValue(mockUser);
      const token = makeToken(["users:write"]);

      const res = await request(app)
        .delete("/api/users/user-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe("User deleted successfully");
      expect(prisma.user.delete).toHaveBeenCalledWith({
        where: { id: "user-123" },
      });
    });

    test("returns 404 when user not found during delete", async () => {
      prisma.user.delete.mockRejectedValue({ code: "P2025" });
      const token = makeToken(["users:write"]);

      const res = await request(app)
        .delete("/api/users/nonexistent")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("User not found");
    });

    test("returns 403 when missing users:write scope", async () => {
      const token = makeToken(["users:read"]);

      const res = await request(app)
        .delete("/api/users/user-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(403);
      expect(prisma.user.delete).not.toHaveBeenCalled();
    });
  });
});
