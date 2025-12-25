import { Router } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { prisma } from "../db/prisma";
import config from "../config";
import { AuthUser } from "../middleware/auth";

export const auth = Router();

auth.post("/login", async (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };
  if (!email || !password)
    return res.status(400).json({ error: "email and password required" });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.sendStatus(401);

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.sendStatus(401);

  const payload: AuthUser = {
    id: user.id,
    organizationId: user.organizationId,
    role: user.role,
    email: user.email,
  };
  const token = jwt.sign(payload, config.getJwtSecret());
  res.json({ token });
});
