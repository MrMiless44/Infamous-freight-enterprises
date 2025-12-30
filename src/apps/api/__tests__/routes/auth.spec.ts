/**
 * Authentication Routes Tests
 * Tests for auth endpoints
 */

import request from "supertest";
import express from "express";
import { authRouter } from "../../routes/auth";
import { prisma } from "../../lib/prisma";
import bcrypt from "bcrypt";

jest.mock("../../lib/prisma");
jest.mock("bcrypt", () => ({
  hash: jest.fn().mockResolvedValue("hashed-password"),
  compare: jest.fn().mockResolvedValue(true),
}));

describe("Authentication Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use("/api", authRouter);
  });

  describe("POST /api/auth/login", () => {
    it("should login user with valid credentials", async () => {
      const mockUser = {
        id: "user-1",
        email: "test@example.com",
        password: await bcrypt.hash("password123", 10),
        role: "USER",
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

      const response = await request(app).post("/api/auth/login").send({
        email: "test@example.com",
        password: "password123",
      });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("token");
      expect(response.body).toHaveProperty("user");
    });

    it("should reject invalid credentials", async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      const response = await request(app).post("/api/auth/login").send({
        email: "test@example.com",
        password: "wrongpassword",
      });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty("error");
    });

    it("should validate email format", async () => {
      const response = await request(app).post("/api/auth/login").send({
        email: "invalid-email",
        password: "password123",
      });

      expect(response.status).toBe(400);
    });

    it("should require password field", async () => {
      const response = await request(app).post("/api/auth/login").send({
        email: "test@example.com",
      });

      expect(response.status).toBe(400);
    });
  });

  describe("POST /api/auth/register", () => {
    it("should register new user", async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.user.create as jest.Mock).mockResolvedValue({
        id: "user-2",
        email: "newuser@example.com",
        name: "New User",
        role: "USER",
      });

      const response = await request(app).post("/api/auth/register").send({
        email: "newuser@example.com",
        password: "password123",
        name: "New User",
      });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty("user");
      expect(response.body.user.email).toBe("newuser@example.com");
    });

    it("should prevent duplicate email registration", async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({
        id: "user-1",
        email: "existing@example.com",
      });

      const response = await request(app).post("/api/auth/register").send({
        email: "existing@example.com",
        password: "password123",
        name: "Existing User",
      });

      expect(response.status).toBe(409);
    });

    it("should validate password strength", async () => {
      const response = await request(app).post("/api/auth/register").send({
        email: "test@example.com",
        password: "weak",
        name: "Test User",
      });

      expect(response.status).toBe(400);
    });
  });

  describe("POST /api/auth/refresh", () => {
    it("should refresh valid token", async () => {
      const response = await request(app)
        .post("/api/auth/refresh")
        .set("Authorization", `Bearer valid-token`)
        .send();

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("token");
    });

    it("should reject invalid token", async () => {
      const response = await request(app)
        .post("/api/auth/refresh")
        .set("Authorization", `Bearer invalid-token`)
        .send();

      expect(response.status).toBe(401);
    });
  });

  describe("POST /api/auth/logout", () => {
    it("should logout user", async () => {
      const response = await request(app)
        .post("/api/auth/logout")
        .set("Authorization", `Bearer valid-token`)
        .send();

      expect([200, 204]).toContain(response.status);
    });
  });
});
