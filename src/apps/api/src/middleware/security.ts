import jwt from "jsonwebtoken";
import type { NextFunction, Request, Response } from "express";
import config from "../config";
import { auditTrail } from "./audit";
import type { AuthUser } from "./auth";
import { requireAuth, requireScope } from "./auth";

function decodeToken(token: string): AuthUser | null {
  try {
    const payload = jwt.verify(token, config.getJwtSecret()) as jwt.JwtPayload;
    const scopes = Array.isArray(payload.scopes)
      ? (payload.scopes as string[])
      : [];

    return {
      id:
        (payload.sub as string | undefined) ??
        (payload.id as string | undefined) ??
        "user",
      organizationId:
        (payload.organizationId as string | undefined) ??
        (payload.orgId as string | undefined) ??
        (payload.org as string | undefined) ??
        "org_default",
      role: (payload.role as string | undefined) ?? "user",
      email: (payload.email as string | undefined) ?? undefined,
      scopes,
    };
  } catch {
    return null;
  }
}

/**
 * Basic authentication middleware used in tests and legacy routes.
 * Accepts a Bearer token and attaches the decoded user to the request.
 */
export function authenticate(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers?.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authorization header required" });
  }

  const token = authHeader.split(" ")[1];
  const user = decodeToken(token);

  if (!user) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  req.user = user;
  return next();
}

/**
 * Audit logger that mirrors the existing auditTrail middleware.
 */
export function auditLog(req: Request, res: Response, next: NextFunction) {
  return auditTrail(req, res, next);
}

export { requireAuth, requireScope };
