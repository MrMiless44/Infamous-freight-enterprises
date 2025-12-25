import { Router } from "express";
import { FLAGS } from "../config/flags";
import { prisma } from "../db/prisma";
import { auditTrail } from "../middleware/audit";
import { requireAuth } from "../middleware/auth";
import { requireRole } from "../middleware/rbac";

export const admin = Router();

admin.use(requireAuth);
admin.use(requireRole("admin"));
admin.use(auditTrail);

admin.get("/flags", (_req, res) => {
  res.json(FLAGS);
});

admin.get("/organizations", async (_req, res) => {
  const organizations = await prisma.organization.findMany({
    include: { users: true },
  });
  res.json(organizations);
});
