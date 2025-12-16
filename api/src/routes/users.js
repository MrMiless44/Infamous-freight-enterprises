const express = require("express");
const { prisma } = require("../db/prisma");
const { body, validationResult } = require("express-validator");
const {
  authenticate,
  requireScope,
  auditLog,
} = require("../middleware/security");

const router = express.Router();

// Get all users
router.get(
  "/users",
  authenticate,
  requireScope("users:read"),
  auditLog,
  async (_req, res, next) => {
    try {
      const users = await prisma.user.findMany({
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

      res.json({ ok: true, users });
    } catch (err) {
      next(err);
    }
  },
);

// Search users with filtering and pagination
router.get(
  "/users/search",
  authenticate,
  requireScope("users:read"),
  auditLog,
  async (req, res, next) => {
    try {
      const {
        q = "",
        page = 1,
        limit = 10,
        role,
        sortBy = "createdAt",
        order = "desc",
      } = req.query;

      // Validate and sanitize inputs
      const pageNum = Math.max(1, parseInt(page) || 1);
      const limitNum = Math.min(100, Math.max(1, parseInt(limit) || 10));
      const validSortFields = ["name", "email", "createdAt"];
      const sortField = validSortFields.includes(sortBy) ? sortBy : "createdAt";
      const sortOrder = order === "asc" ? "asc" : "desc";

      // Build filter conditions
      const where = {};

      // Full-text search on email and name
      if (q.trim()) {
        where.OR = [
          { email: { contains: q.trim(), mode: "insensitive" } },
          { name: { contains: q.trim(), mode: "insensitive" } },
        ];
      }

      // Role filter
      if (role && ["user", "admin", "driver"].includes(role)) {
        where.role = role;
      }

      // Get total count for pagination
      const total = await prisma.user.count({ where });
      const totalPages = Math.ceil(total / limitNum);

      // Fetch paginated results
      const users = await prisma.user.findMany({
        where,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: true,
        },
        orderBy: { [sortField]: sortOrder },
        skip: (pageNum - 1) * limitNum,
        take: limitNum,
      });

      res.json({
        success: true,
        data: {
          users,
          pagination: {
            page: pageNum,
            limit: limitNum,
            total,
            totalPages,
          },
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

// Get user by ID
router.get(
  "/users/:id",
  authenticate,
  requireScope("users:read"),
  auditLog,
  async (req, res, next) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.params.id },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      if (!user) {
        return res.status(404).json({ ok: false, error: "User not found" });
      }

      res.json({ ok: true, user });
    } catch (err) {
      next(err);
    }
  },
);

// Create user
router.post(
  "/users",
  authenticate,
  requireScope("users:write"),
  auditLog,
  [
    body("email").isEmail().withMessage("Invalid email format"),
    body("name").optional().isString().trim().isLength({ min: 1, max: 100 }),
    body("role").optional().isIn(["user", "admin", "driver"]).withMessage("Invalid role"),
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          ok: false,
          error: "Validation Error",
          details: errors.array(),
        });
      }

      const { email, name, role = "user" } = req.body;

      if (!email) {
        return res.status(400).json({ ok: false, error: "Email is required" });
      }

      const user = await prisma.user.create({
        data: {
          email,
          name,
          role,
        },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      res.status(201).json({ ok: true, user });
    } catch (err) {
      if (err.code === "P2002") {
        return res
          .status(409)
          .json({ ok: false, error: "Email already exists" });
      }
      next(err);
    }
  },
);

// Update user
router.patch(
  "/users/:id",
  authenticate,
  requireScope("users:write"),
  auditLog,
  async (req, res, next) => {
    try {
      const { name, role } = req.body;
      const updates = {};

      if (name !== undefined) updates.name = name;
      if (role !== undefined) updates.role = role;

      const user = await prisma.user.update({
        where: { id: req.params.id },
        data: updates,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      res.json({ ok: true, user });
    } catch (err) {
      if (err.code === "P2025") {
        return res.status(404).json({ ok: false, error: "User not found" });
      }
      next(err);
    }
  },
);

// Delete user
router.delete(
  "/users/:id",
  authenticate,
  requireScope("users:write"),
  auditLog,
  async (req, res, next) => {
    try {
      await prisma.user.delete({
        where: { id: req.params.id },
      });

      res.json({ ok: true, message: "User deleted successfully" });
    } catch (err) {
      if (err.code === "P2025") {
        return res.status(404).json({ ok: false, error: "User not found" });
      }
      next(err);
    }
  },
);

// Example of a transaction
router.post(
  "/users/transaction",
  authenticate,
  requireScope("users:write"),
  auditLog,
  async (req, res, next) => {
    try {
      const { usersData } = req.body;

      await prisma.$transaction(
        async (tx) => {
          for (const userData of usersData) {
            await tx.user.create({
              data: userData,
            });
          }
        },
        {
          timeout: 30000, // 30s
        },
      );

      res.status(201).json({ ok: true, message: "Users created successfully" });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
